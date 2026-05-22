"""
age-rt: age-based real-time encryption for streaming data

This module implements the age-rt v0.2 protocol, providing authenticated
encryption for streaming data using the age v1 format with passphrase-based
key derivation (scrypt).

age-rt v0.2 features:
- Variable-length chunks with authentication
- ChaCha20-Poly1305 AEAD encryption
- HKDF-based payload key derivation (info="payload")
- age v1 scrypt header format
- Truncation detection via final flag in nonce

Wire format:
    [age header][16-byte nonce][length-prefixed chunks]

Example (encoding):
    # Simple: encode to file
    with open('data.age', 'wb') as f:
        encode_file([b"chunk1", b"chunk2"], f, "secret")

    # Or: iterate over wire chunks
    for wire_chunk in iter_encode_chunks([b"chunk1", b"chunk2"], "secret"):
        output.write(wire_chunk)

Example (decoding):
    # Simple: decode from file
    with open('data.age', 'rb') as f:
        for plaintext in decode_file(f, "secret"):
            process(plaintext)

    # Or: decode from read function
    with open("data.age", "rb") as f:
        for plaintext in iter_decode_callable(f.read, "secret"):
            process(plaintext)

Example (async decoding):
    async for plaintext in aiter_decode_callable(reader.read_fixed_block, "secret"):
        await process(plaintext)

Requires: cryptography>=41.0.0
"""

import base64
import hashlib as _hashlib
import hmac as _hmac
import io
import os
import re
import struct
from dataclasses import dataclass
from enum import Enum, auto
from importlib.metadata import PackageNotFoundError, version
from typing import (
    AsyncIterable,
    AsyncIterator,
    Awaitable,
    BinaryIO,
    Callable,
    Iterable,
    Iterator,
)

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

try:
    __version__ = version("age-rt")
except PackageNotFoundError:
    __version__ = "unknown"


# ============================================================================
# Constants
# ============================================================================

_AGE_IDENTIFIER = "age-encryption.org/v1"
_AGE_RT_IDENTIFIER = "github.com/parsimonit/age-rt-encryption/v0.2"
_AGE_FILE_KEY_SIZE = 16  # age v1 and age-rt: 128-bit file key
CHUNK_SIZE = 65536  # Standard age chunk size (64 KiB)
_MAX_CHUNK_SIZE = 16 * 1024 * 1024  # 16 MiB absolute maximum for DoS protection


# ============================================================================
# Base64 helpers (unpadded, 64-column wrapped per age spec)
# ============================================================================


def _b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=")


def _b64_decode(text: str) -> bytes:
    pad = (-len(text)) % 4
    return base64.b64decode(text + "=" * pad)


def _b64_encode_wrapped(data: bytes) -> str:
    """Encode to unpadded base64, wrapped at 64 columns; final line always < 64 chars."""
    raw = _b64_encode(data) if data else ""
    lines = [raw[i : i + 64] for i in range(0, len(raw), 64)] if raw else [""]
    if raw and len(raw) % 64 == 0:
        lines.append("")  # empty final line ensures last line < 64 chars
    return "\n".join(lines)


# ============================================================================
# Exception Classes
# ============================================================================


class AgeRTError(Exception):
    """Base exception for age-rt errors."""

    pass


class DecodeError(AgeRTError):
    """Base class for decoding errors."""

    pass


class HeaderParseError(DecodeError):
    """Raised when age header parsing fails."""

    pass


class ChunkAuthenticationError(DecodeError):
    """Raised when chunk authentication fails."""

    pass


class InsufficientDataError(DecodeError):
    """Decoder received insufficient data in feed()."""

    pass


class StreamTruncatedError(DecodeError):
    """I/O stream ended before decoding complete (factory-level)."""

    pass


# ============================================================================
# Internal Helper Functions
# ============================================================================


def _derive_file_key_from_passphrase(passphrase: str, salt: bytes, scrypt_context: bytes) -> bytes:
    """Derive 32-byte wrap key via scrypt."""
    if len(salt) != 16:
        raise ValueError("Salt must be 16 bytes")
    kdf = Scrypt(
        salt=scrypt_context + salt,
        length=32,
        n=2**18,
        r=8,
        p=1,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _wrap_file_key(
    file_key: bytes, passphrase: str, scrypt_salt: bytes, scrypt_context: bytes
) -> bytes:
    """Wrap file key with ChaCha20-Poly1305 using a passphrase-derived key."""
    wrap_key = _derive_file_key_from_passphrase(passphrase, scrypt_salt, scrypt_context)
    return ChaCha20Poly1305(wrap_key).encrypt(b"\x00" * 12, file_key, None)


def _unwrap_file_key(
    wrapped: bytes, passphrase: str, scrypt_salt: bytes, scrypt_context: bytes
) -> bytes:
    """Unwrap file key; raises ChunkAuthenticationError on wrong passphrase."""
    wrap_key = _derive_file_key_from_passphrase(passphrase, scrypt_salt, scrypt_context)
    try:
        return ChaCha20Poly1305(wrap_key).decrypt(b"\x00" * 12, wrapped, None)
    except Exception as e:
        raise ChunkAuthenticationError(f"Failed to unwrap file key (wrong passphrase?): {e}")


def _encode_age_scrypt_header(
    passphrase: str, file_key: bytes, scrypt_salt: bytes, identifier: str
) -> bytes:
    """
    Encode age-format scrypt header stanza and HMAC.

    Returns complete header bytes: identifier + stanza + "--- <mac>\n"
    """
    scrypt_context = b"age-encryption.org/v1/scrypt"
    wrapped_key = _wrap_file_key(file_key, passphrase, scrypt_salt, scrypt_context)
    salt_b64 = _b64_encode(scrypt_salt)
    body_b64 = _b64_encode_wrapped(wrapped_key)
    # Build header_no_mac: ends with b"---" (no space or newline)
    header_no_mac = (f"{identifier}\n-> scrypt {salt_b64} 18\n{body_b64}\n---").encode("utf-8")
    # HMAC-SHA256(key=HKDF(file_key, salt=None, info="header"), data=header_no_mac)
    hmac_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"header").derive(
        file_key
    )
    mac = _hmac.new(hmac_key, header_no_mac, _hashlib.sha256).digest()
    return header_no_mac + b" " + _b64_encode(mac).encode("ascii") + b"\n"


def _make_aead_nonce(chunk_index: int, is_final: bool) -> bytes:
    """
    Create 12-byte AEAD nonce: 11-byte counter + 1-byte final flag.

    Args:
        chunk_index: Chunk sequence number
        is_final: Whether this is the final chunk

    Returns:
        12-byte nonce for ChaCha20-Poly1305
    """
    last_chunk_flag = 0x01 if is_final else 0x00
    return chunk_index.to_bytes(11, "big") + bytes([last_chunk_flag])


def _get_header_identifier(header_bytes: bytes) -> str:
    """Extract the format identifier (first line) from parsed header bytes."""
    return header_bytes.split(b"\n", 1)[0].decode("utf-8")


def _derive_payload_key(file_key: bytes, nonce: bytes) -> bytes:
    """Derive 32-byte payload key: HKDF-SHA256(ikm=file_key, salt=nonce, info=b'payload')."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=nonce, info=b"payload").derive(file_key)


def _parse_identifier_params(identifier: str) -> tuple[str, dict[str, int]]:
    """
    Parse identifier into base + integer parameters.

    Examples:
        "age-encryption.org/v1" -> ("age-encryption.org/v1", {})
        "age-encryption.org/v1?chunk=32768" -> ("age-encryption.org/v1", {"chunk": 32768})

    Raises:
        HeaderParseError: If parameter format is invalid
    """
    if "?" not in identifier:
        return identifier, {}

    base, query = identifier.split("?", 1)
    params = {}

    for pair in query.split("&"):
        if "=" not in pair:
            raise HeaderParseError(f"Invalid parameter format: {pair!r}")
        key, value = pair.split("=", 1)

        # Validate parameter name (alphanumeric, starts with letter)
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9]*$", key):
            raise HeaderParseError(f"Invalid parameter name: {key!r}")

        # Parse value as positive integer (no leading zeros unless "0")
        if not value.isdigit() or (value.startswith("0") and len(value) > 1):
            raise HeaderParseError(f"Invalid parameter value for {key}: {value!r}")

        params[key] = int(value)

    return base, params


def _build_identifier(base: str, **params: int) -> str:
    """
    Build identifier with optional integer parameters.

    Parameters are sorted alphabetically for canonical form.
    """
    if not params:
        return base
    query = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
    return f"{base}?{query}"


# ============================================================================
# Header Parsing
# ============================================================================


@dataclass
class _Header:
    """Structural parse of an age header (no crypto)."""

    full_identifier: str
    base_id: str
    params: dict[str, int]
    stanza_args: list[str]  # tokens after "-> " on the stanza line
    stanza_body: bytes  # b64-decoded stanza body
    mac_data: bytes  # bytes that are MACed (up to and including b"---")
    mac: bytes  # b64-decoded MAC value


def _parse_header_bytes(buf: bytes) -> _Header:
    """
    Structural parse of a complete age header buffer.

    Extracts identifier, stanza args, stanza body, and MAC without any crypto.

    Raises:
        HeaderParseError: If the buffer is structurally invalid.
    """
    sep = buf.rfind(b"\n--- ")
    if sep == -1:
        raise HeaderParseError("Invalid header: missing MAC separator")
    mac_data = buf[: sep + 4]  # up to and including b"---"
    mac_b64_bytes = buf[sep + 5 :].rstrip(b"\n")
    try:
        mac = _b64_decode(mac_b64_bytes.decode("ascii"))
    except Exception as e:
        raise HeaderParseError(f"Invalid header MAC encoding: {e}")
    if len(mac) != 32:
        raise HeaderParseError(f"Invalid header MAC length: {len(mac)}")

    lines = mac_data.decode("utf-8").split("\n")
    if lines and lines[-1] == "---":
        lines = lines[:-1]
    if len(lines) < 3:
        raise HeaderParseError("Invalid header: too few lines")

    full_identifier = lines[0]
    base_id, params = _parse_identifier_params(full_identifier)

    if not lines[1].startswith("-> "):
        raise HeaderParseError("Invalid header: expected stanza line")
    stanza_args = lines[1][3:].split()

    body_b64 = "".join(line for line in lines[2:] if line)
    try:
        stanza_body = _b64_decode(body_b64)
    except Exception as e:
        raise HeaderParseError(f"Invalid stanza body: {e}")

    return _Header(
        full_identifier=full_identifier,
        base_id=base_id,
        params=params,
        stanza_args=stanza_args,
        stanza_body=stanza_body,
        mac_data=mac_data,
        mac=mac,
    )


def _scrypt_unwrap(parsed: _Header, passphrase: str) -> bytes:
    """
    Crypto portion of header decoding: unwrap file key and verify header MAC.

    Raises:
        HeaderParseError: If stanza is malformed or MAC verification fails.
        ChunkAuthenticationError: If the passphrase is wrong.
    """
    if not parsed.stanza_args or parsed.stanza_args[0] != "scrypt":
        stanza_type = parsed.stanza_args[0] if parsed.stanza_args else "none"
        raise HeaderParseError(f"Unsupported stanza type: {stanza_type!r}")
    if len(parsed.stanza_args) != 3:
        raise HeaderParseError("Invalid scrypt stanza format")
    salt_b64, log_n_str = parsed.stanza_args[1], parsed.stanza_args[2]
    if not log_n_str.isdigit() or log_n_str.startswith("0"):
        raise HeaderParseError(f"Invalid scrypt work factor encoding: {log_n_str!r}")
    if int(log_n_str) != 18:
        raise HeaderParseError(f"Unsupported scrypt work factor: 2^{log_n_str}")
    try:
        scrypt_salt = _b64_decode(salt_b64)
    except Exception as e:
        raise HeaderParseError(f"Invalid scrypt salt: {e}")
    if len(scrypt_salt) != 16:
        raise HeaderParseError("Scrypt salt must be 16 bytes")
    scrypt_context = b"age-encryption.org/v1/scrypt"
    file_key = _unwrap_file_key(parsed.stanza_body, passphrase, scrypt_salt, scrypt_context)
    hmac_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"header").derive(
        file_key
    )
    expected_mac = _hmac.new(hmac_key, parsed.mac_data, _hashlib.sha256).digest()
    if not _hmac.compare_digest(expected_mac, parsed.mac):
        raise HeaderParseError("Header MAC verification failed")
    return file_key


class _HeaderParser:
    """
    Byte-by-byte age header accumulator.

    feed() always receives exactly 1 byte and returns None until the header
    is complete, then returns the parsed _Header.
    """

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> _Header | None:
        self._buf.extend(data)
        if self._buf[-1:] != b"\n":
            return None
        buf = bytes(self._buf)
        last_nl = buf.rfind(b"\n", 0, len(buf) - 1)
        if not buf[last_nl + 1 : -1].startswith(b"--- "):
            return None
        if len(self._buf) > 4096:
            raise HeaderParseError("Header too large")
        return _parse_header_bytes(buf)


# Encoder
# ============================================================================


class AgeRTEncoder:
    """
    age-rt v0.2 stream encoder.

    Encodes plaintext chunks into age-rt wire format with authentication.
    Supports passphrase-based encryption with age v1 scrypt headers.

    Do not instantiate directly. Use factory methods:
    - AgeRTEncoder.from_passphrase("secret")

    Example:
        encoder = AgeRTEncoder.from_passphrase("secret")
        output.write(encoder.get_header())
        for chunk in chunks:
            output.write(encoder.encode_chunk(chunk))
        output.write(encoder.encode_chunk(b'', is_final=True))
    """

    def __init__(self, _file_key: bytes, _age_header: bytes, _max_chunk_size: int):
        """
        Internal constructor. Use from_passphrase() instead.

        Args:
            _file_key: 16-byte file key (internal)
            _age_header: Pre-encoded age header bytes (internal)
            _max_chunk_size: Maximum chunk size in bytes (internal)

        Raises:
            ValueError: If file_key is not 16 bytes or max_chunk_size is invalid
        """
        if len(_file_key) != _AGE_FILE_KEY_SIZE:
            raise ValueError(f"File key must be {_AGE_FILE_KEY_SIZE} bytes")
        if _max_chunk_size < 1 or _max_chunk_size > _MAX_CHUNK_SIZE:
            raise ValueError(f"max_chunk_size must be 1..{_MAX_CHUNK_SIZE}")

        self._file_key = _file_key
        self._age_header = _age_header
        self._max_chunk_size = _max_chunk_size
        self._nonce = os.urandom(16)
        self._cipher = ChaCha20Poly1305(_derive_payload_key(_file_key, self._nonce))
        self._chunk_index = 0
        self._finalized = False

    @classmethod
    def from_passphrase(cls, passphrase: str, max_chunk_size: int = CHUNK_SIZE) -> "AgeRTEncoder":
        """
        Create encoder from passphrase with age scrypt header.

        Generates random file key and scrypt salt internally.

        Args:
            passphrase: User passphrase
            max_chunk_size: Maximum chunk size (default 65536). Non-standard values produce
                          non-interoperable files with modified identifier.

        Returns:
            New AgeRTEncoder instance

        Raises:
            ValueError: If max_chunk_size is invalid
        """
        if max_chunk_size < 1 or max_chunk_size > _MAX_CHUNK_SIZE:
            raise ValueError(f"max_chunk_size must be 1..{_MAX_CHUNK_SIZE}")

        file_key = os.urandom(_AGE_FILE_KEY_SIZE)
        scrypt_salt = os.urandom(16)

        # Build identifier (omit param if standard)
        if max_chunk_size == CHUNK_SIZE:
            identifier = _AGE_RT_IDENTIFIER
        else:
            identifier = _build_identifier(_AGE_RT_IDENTIFIER, maxchunk=max_chunk_size)

        age_header = _encode_age_scrypt_header(passphrase, file_key, scrypt_salt, identifier)
        return cls(_file_key=file_key, _age_header=age_header, _max_chunk_size=max_chunk_size)

    @property
    def finalized(self) -> bool:
        """Return True if the stream has been finalized."""
        return self._finalized

    def get_header(self) -> bytes:
        """
        Get complete stream header (age header + nonce).

        Returns:
            Stream header bytes
        """
        return self._age_header + self._nonce

    def encode_chunk(self, plaintext: bytes, is_final: bool | None = None) -> bytes:
        """
        Encode a single chunk into wire format.

        Wire format: [4-byte length][ciphertext + tag]

        Args:
            plaintext: Plaintext data to encode
            is_final: Whether this is the final chunk. If None (default), never auto-finalizes.
                     age-rt streams must be explicitly finalized by the caller.

        Returns:
            Encoded chunk in wire format

        Raises:
            RuntimeError: If stream already finalized
            ValueError: If chunk exceeds max_chunk_size
        """
        if self._finalized:
            raise RuntimeError("Stream already finalized")

        # Validate chunk size
        if len(plaintext) > self._max_chunk_size:
            raise ValueError(
                f"Chunk too large: {len(plaintext)} > max_chunk_size={self._max_chunk_size}"
            )

        # age-rt: never auto-finalize (is_final defaults to False if None)
        if is_final is None:
            is_final = False

        aead_nonce = _make_aead_nonce(self._chunk_index, is_final)
        ciphertext = self._cipher.encrypt(aead_nonce, plaintext, None)
        self._chunk_index += 1

        if is_final:
            self._finalized = True

        return struct.pack(">I", len(ciphertext)) + ciphertext


# ============================================================================
# Decoder State Machine
# ============================================================================


class AgeRTDecoder:
    """
    age-rt v0.2 stateful decoder.

    Push-based decoder that announces data needs and processes incrementally.
    Decouples I/O from parsing/crypto logic.

    Usage pattern:
        decoder = AgeRTDecoder(passphrase)
        while needed := decoder.bytes_wanted:
            data = source.read(needed)
            result = decoder.feed(data)
            if result is not None:
                process(result)

    For most use cases, use factory functions instead:
        - iter_decode_callable(): Sync from read function
        - aiter_decode_callable(): Async from read function
        - iter_decode_chunks(): Sync from byte iterable
        - aiter_decode_chunks(): Async from byte iterable
        - decode_file(): From file path
        - decode_bytes(): From bytes object
    """

    class _State(Enum):
        HEADER_SCAN = auto()
        NONCE = auto()
        CHUNK_LENGTH = auto()
        CHUNK_DATA = auto()
        DONE = auto()

    def __init__(self, passphrase: str, max_chunk_size: int = CHUNK_SIZE, **kwargs):
        """
        Initialize decoder with passphrase.

        Args:
            passphrase: Passphrase for decryption
            max_chunk_size: Maximum chunk size to accept (default 65536)
            **kwargs: Reserved for future extensions

        Raises:
            ValueError: If max_chunk_size is invalid
        """
        if max_chunk_size < 1 or max_chunk_size > _MAX_CHUNK_SIZE:
            raise ValueError(f"max_chunk_size must be 1..{_MAX_CHUNK_SIZE}")

        self._passphrase: str | None = passphrase
        self._max_chunk_size = max_chunk_size
        self._header_max_chunk_size: int | None = None
        self._hp: _HeaderParser | None = _HeaderParser()
        self._file_key: bytes | None = None
        self._state = AgeRTDecoder._State.HEADER_SCAN
        self._chunk_index = 0
        self._finalized = False
        self._cipher: ChaCha20Poly1305 | None = None
        self._next_chunk_length: int | None = None
        self._bytes_wanted = 1

    @classmethod
    def _make_from_file_key(
        cls, file_key: bytes, params: dict[str, int], max_chunk_size: int = CHUNK_SIZE
    ) -> "AgeRTDecoder":
        """Create a decoder with the file key already unwrapped (used by AgeAutoDecoder)."""
        header_maxchunk = params.get("maxchunk", CHUNK_SIZE)
        if header_maxchunk > max_chunk_size:
            raise HeaderParseError(
                f"Header max_chunk_size {header_maxchunk} exceeds decoder limit {max_chunk_size}"
            )
        obj = object.__new__(cls)
        obj._passphrase = None
        obj._max_chunk_size = max_chunk_size
        obj._header_max_chunk_size = header_maxchunk
        obj._hp = None
        obj._file_key = file_key
        obj._state = cls._State.NONCE
        obj._chunk_index = 0
        obj._finalized = False
        obj._cipher = None
        obj._next_chunk_length = None
        obj._bytes_wanted = 16
        return obj

    @property
    def bytes_wanted(self) -> int:
        """
        Number of bytes wanted for next operation.

        Returns 0 when decoding is complete.
        """
        return self._bytes_wanted

    def is_done(self) -> bool:
        """Return True when decoding is complete (bytes_wanted == 0)."""
        return self._bytes_wanted == 0

    def feed(self, data: bytes) -> bytes | None:
        """
        Feed exactly bytes_wanted bytes to decoder.

        Returns decrypted plaintext when a chunk is available, else None.

        Args:
            data: Must be exactly bytes_wanted bytes

        Returns:
            Decrypted plaintext chunk, or None if more data is needed.

        Raises:
            InsufficientDataError: If wrong amount of data provided
            HeaderParseError: If header is invalid
            ChunkAuthenticationError: If authentication fails
        """
        if len(data) != self._bytes_wanted:
            raise InsufficientDataError(f"Expected {self._bytes_wanted} bytes, got {len(data)}")

        if self._state == AgeRTDecoder._State.HEADER_SCAN:
            assert self._hp is not None  # Set in __init__
            assert self._passphrase is not None  # Set in __init__
            parsed = self._hp.feed(data)
            if parsed is not None:
                if parsed.base_id != _AGE_RT_IDENTIFIER:
                    raise HeaderParseError(
                        f"Invalid header identifier: expected '{_AGE_RT_IDENTIFIER}', "
                        f"got '{parsed.base_id}'"
                    )
                header_maxchunk = parsed.params.get("maxchunk", CHUNK_SIZE)
                if header_maxchunk > self._max_chunk_size:
                    raise HeaderParseError(
                        f"Header max_chunk_size {header_maxchunk} exceeds "
                        f"decoder limit {self._max_chunk_size}"
                    )
                self._header_max_chunk_size = header_maxchunk
                self._file_key = _scrypt_unwrap(parsed, self._passphrase)
                self._state = AgeRTDecoder._State.NONCE
                self._bytes_wanted = 16
            return None

        elif self._state == AgeRTDecoder._State.NONCE:
            assert self._file_key is not None  # Set in HEADER_SCAN state
            self._cipher = ChaCha20Poly1305(_derive_payload_key(self._file_key, data))
            self._state = AgeRTDecoder._State.CHUNK_LENGTH
            self._bytes_wanted = 4
            return None

        elif self._state == AgeRTDecoder._State.CHUNK_LENGTH:
            length = struct.unpack(">I", data)[0]
            assert self._header_max_chunk_size is not None  # Set in HEADER_SCAN state
            max_allowed = self._header_max_chunk_size + 16
            if length < 16 or length > max_allowed:
                raise ChunkAuthenticationError(
                    f"Chunk length {length} outside valid range [16, {max_allowed}]"
                )
            self._next_chunk_length = length
            self._state = AgeRTDecoder._State.CHUNK_DATA
            self._bytes_wanted = length
            return None

        elif self._state == AgeRTDecoder._State.CHUNK_DATA:
            assert self._cipher is not None  # Set in NONCE state
            try:
                plaintext = self._cipher.decrypt(
                    _make_aead_nonce(self._chunk_index, False), data, None
                )
                self._chunk_index += 1
                self._state = AgeRTDecoder._State.CHUNK_LENGTH
                self._bytes_wanted = 4
                return plaintext
            except Exception:
                pass
            try:
                plaintext = self._cipher.decrypt(
                    _make_aead_nonce(self._chunk_index, True), data, None
                )
                self._chunk_index += 1
                self._state = AgeRTDecoder._State.DONE
                self._bytes_wanted = 0
                return plaintext
            except Exception as e:
                raise ChunkAuthenticationError(f"Auth failed at chunk {self._chunk_index}: {e}")

        elif self._state == AgeRTDecoder._State.DONE:
            raise RuntimeError("Decoder already complete")


# ============================================================================
# Standard age v1 Encoder / Decoder
# ============================================================================


class AgeEncoder:
    """
    Standard age v1 stream encoder.

    Produces raw age v1 ciphertext (no length-prefixed chunks).
    File key is 16 bytes; non-final chunks must be exactly CHUNK_SIZE bytes.

    Do not instantiate directly. Use factory methods:
    - AgeEncoder.from_passphrase("secret")
    """

    def __init__(self, _file_key: bytes, _age_header: bytes, _chunk_size: int):
        """
        Internal constructor. Use from_passphrase() instead.

        Args:
            _file_key: 16-byte file key (internal)
            _age_header: Pre-encoded age header bytes (internal)
            _chunk_size: Fixed chunk size in bytes (internal)

        Raises:
            ValueError: If file_key is not 16 bytes or chunk_size is invalid
        """
        if len(_file_key) != _AGE_FILE_KEY_SIZE:
            raise ValueError(f"File key must be {_AGE_FILE_KEY_SIZE} bytes")
        if _chunk_size < 1 or _chunk_size > _MAX_CHUNK_SIZE:
            raise ValueError(f"chunk_size must be 1..{_MAX_CHUNK_SIZE}")

        self._age_header = _age_header
        self._chunk_size = _chunk_size
        self._nonce = os.urandom(16)
        self._cipher = ChaCha20Poly1305(_derive_payload_key(_file_key, self._nonce))
        self._chunk_index = 0
        self._finalized = False

    @classmethod
    def from_passphrase(cls, passphrase: str, chunk_size: int = CHUNK_SIZE) -> "AgeEncoder":
        """
        Create encoder from passphrase with age scrypt header.

        Args:
            passphrase: User passphrase
            chunk_size: Fixed chunk size (default 65536). Non-standard values produce
                       non-interoperable files with modified identifier.

        Returns:
            New AgeEncoder instance

        Raises:
            ValueError: If chunk_size is invalid
        """
        if chunk_size < 1 or chunk_size > _MAX_CHUNK_SIZE:
            raise ValueError(f"chunk_size must be 1..{_MAX_CHUNK_SIZE}")

        file_key = os.urandom(_AGE_FILE_KEY_SIZE)
        scrypt_salt = os.urandom(16)

        # Build identifier (omit param if standard)
        if chunk_size == CHUNK_SIZE:
            identifier = _AGE_IDENTIFIER
        else:
            identifier = _build_identifier(_AGE_IDENTIFIER, chunk=chunk_size)

        age_header = _encode_age_scrypt_header(passphrase, file_key, scrypt_salt, identifier)
        return cls(_file_key=file_key, _age_header=age_header, _chunk_size=chunk_size)

    @property
    def finalized(self) -> bool:
        """Return True if the stream has been finalized."""
        return self._finalized

    def get_header(self) -> bytes:
        """Return age header + 16-byte payload nonce."""
        return self._age_header + self._nonce

    def encode_chunk(self, plaintext: bytes, is_final: bool | None = None) -> bytes:
        """
        Encrypt one chunk.

        Args:
            plaintext: Plaintext data to encode (0..chunk_size bytes)
            is_final: Whether this is the final chunk. If None (default), auto-detects:
                     chunks < chunk_size are automatically marked as final.
                     If True, chunk must be ≤ chunk_size.
                     If False, chunk must be exactly chunk_size.

        Returns:
            Raw ciphertext (plaintext + 16-byte AEAD tag); no length prefix.

        Raises:
            RuntimeError: If stream already finalized
            ValueError: If chunk size violates constraints
        """
        if self._finalized:
            raise RuntimeError("Stream already finalized")

        # Auto-detect: short chunks are final
        if is_final is None:
            is_final = len(plaintext) < self._chunk_size

        # Validate chunk size
        if not is_final and len(plaintext) != self._chunk_size:
            raise ValueError(f"Non-final chunks must be exactly {self._chunk_size} bytes")
        if is_final and len(plaintext) > self._chunk_size:
            raise ValueError(f"Chunk too large: {len(plaintext)} > {self._chunk_size}")

        ciphertext = self._cipher.encrypt(
            _make_aead_nonce(self._chunk_index, is_final), plaintext, None
        )
        self._chunk_index += 1
        if is_final:
            self._finalized = True
        return ciphertext


class AgeDecoder:
    """
    Standard age v1 stateful decoder.

    bytes_wanted is CHUNK_SIZE + 16 (65552) during the data phase.
    feed() accepts 1..bytes_wanted bytes; a short feed signals the final chunk.

    Usage pattern:
        decoder = AgeDecoder(passphrase)
        while not decoder.is_done():
            wanted = decoder.bytes_wanted
            data = source.read(wanted)   # may return fewer bytes at end of stream
            if not data:
                break
            result = decoder.feed(data)
            if result is not None:
                process(result)
    """

    class _State(Enum):
        HEADER_SCAN = auto()
        NONCE = auto()
        CHUNK_DATA = auto()
        DONE = auto()

    def __init__(self, passphrase: str, chunk_size: int = CHUNK_SIZE, **kwargs):
        """
        Initialize decoder with passphrase.

        Args:
            passphrase: Passphrase for decryption
            chunk_size: Expected chunk size (default 65536)
            **kwargs: Reserved for future extensions

        Raises:
            ValueError: If chunk_size is invalid
        """
        if chunk_size < 1 or chunk_size > _MAX_CHUNK_SIZE:
            raise ValueError(f"chunk_size must be 1..{_MAX_CHUNK_SIZE}")

        self._passphrase: str | None = passphrase
        self._chunk_size = chunk_size
        self._hp: _HeaderParser | None = _HeaderParser()
        self._file_key: bytes | None = None
        self._state = AgeDecoder._State.HEADER_SCAN
        self._chunk_index = 0
        self._cipher: ChaCha20Poly1305 | None = None
        self._bytes_wanted = 1

    @classmethod
    def _make_from_file_key(cls, file_key: bytes, params: dict[str, int]) -> "AgeDecoder":
        """Create a decoder with the file key already unwrapped (used by AgeAutoDecoder)."""
        obj = object.__new__(cls)
        obj._passphrase = None
        obj._chunk_size = params.get("chunk", CHUNK_SIZE)
        obj._hp = None
        obj._file_key = file_key
        obj._state = cls._State.NONCE
        obj._chunk_index = 0
        obj._cipher = None
        obj._bytes_wanted = 16
        return obj

    @property
    def bytes_wanted(self) -> int:
        """
        Maximum bytes to supply to the next feed() call.

        Returns 0 when decoding is complete.
        """
        return self._bytes_wanted

    def is_done(self) -> bool:
        """Return True when decoding is complete (bytes_wanted == 0)."""
        return self._bytes_wanted == 0

    def feed(self, data: bytes) -> bytes | None:
        """
        Feed 1..bytes_wanted bytes to the decoder.

        In HEADER_SCAN state: exactly 1 byte at a time.
        In NONCE state: exactly 16 bytes.
        In CHUNK_DATA state: 1..CHUNK_SIZE+16 bytes; short = final chunk.

        Returns:
            Decrypted plaintext chunk, or None if more data is needed.

        Raises:
            InsufficientDataError: If data is empty or too large
            HeaderParseError: If header is invalid
            ChunkAuthenticationError: If chunk authentication fails
        """
        if not data:
            raise InsufficientDataError("Cannot feed empty bytes")
        if len(data) > self._bytes_wanted:
            raise InsufficientDataError(
                f"Too many bytes: got {len(data)}, max {self._bytes_wanted}"
            )

        if self._state == AgeDecoder._State.HEADER_SCAN:
            assert self._hp is not None  # Set in __init__
            assert self._passphrase is not None  # Set in __init__
            parsed = self._hp.feed(data)
            if parsed is not None:
                if parsed.base_id != _AGE_IDENTIFIER:
                    raise HeaderParseError(
                        f"Invalid header identifier: expected '{_AGE_IDENTIFIER}', "
                        f"got '{parsed.base_id}'"
                    )
                header_chunk = parsed.params.get("chunk", CHUNK_SIZE)
                if header_chunk != self._chunk_size:
                    raise HeaderParseError(
                        f"Chunk size mismatch: header={header_chunk}, decoder={self._chunk_size}"
                    )
                self._file_key = _scrypt_unwrap(parsed, self._passphrase)
                self._state = AgeDecoder._State.NONCE
                self._bytes_wanted = 16
            return None

        elif self._state == AgeDecoder._State.NONCE:
            assert self._file_key is not None  # Set in HEADER_SCAN state
            self._cipher = ChaCha20Poly1305(_derive_payload_key(self._file_key, data))
            self._state = AgeDecoder._State.CHUNK_DATA
            self._bytes_wanted = self._chunk_size + 16
            return None

        elif self._state == AgeDecoder._State.CHUNK_DATA:
            ciphertext = data
            is_short = len(ciphertext) < self._chunk_size + 16

            assert self._cipher is not None  # Set in NONCE state
            if not is_short:
                try:
                    plaintext = self._cipher.decrypt(
                        _make_aead_nonce(self._chunk_index, False), ciphertext, None
                    )
                    self._chunk_index += 1
                    return plaintext
                except Exception:
                    pass

            try:
                plaintext = self._cipher.decrypt(
                    _make_aead_nonce(self._chunk_index, True), ciphertext, None
                )
                self._chunk_index += 1
                self._state = AgeDecoder._State.DONE
                self._bytes_wanted = 0
                return plaintext
            except Exception as e:
                raise ChunkAuthenticationError(f"Auth failed at chunk {self._chunk_index}: {e}")

        elif self._state == AgeDecoder._State.DONE:
            raise RuntimeError("Decoder already complete")


# ============================================================================
# Auto-detecting Decoder
# ============================================================================


class AgeAutoDecoder:
    """
    Auto-detecting decoder for both age v1 and age-rt wire formats.

    Reads the header byte-by-byte, detects the format from the identifier,
    then delegates all payload decoding to an inner AgeDecoder or AgeRTDecoder.

    Usage pattern:
        decoder = AgeAutoDecoder(passphrase)
        while needed := decoder.bytes_wanted:
            data = source.read(needed)
            if not data:
                break
            result = decoder.feed(data)
            if result is not None:
                process(result)
    """

    def __init__(self, passphrase: str, max_chunk_size: int = CHUNK_SIZE):
        """
        Initialize auto-detecting decoder.

        Args:
            passphrase: Passphrase for decryption
            max_chunk_size: Maximum chunk size to accept for age-rt streams (default 65536)

        Raises:
            ValueError: If max_chunk_size is invalid
        """
        if max_chunk_size < 1 or max_chunk_size > _MAX_CHUNK_SIZE:
            raise ValueError(f"max_chunk_size must be 1..{_MAX_CHUNK_SIZE}")
        self._passphrase = passphrase
        self._max_chunk_size = max_chunk_size
        self._hp = _HeaderParser()
        self._inner: AgeDecoder | AgeRTDecoder | None = None

    @property
    def bytes_wanted(self) -> int:
        """Number of bytes wanted for next operation. Returns 0 when done."""
        return self._inner.bytes_wanted if self._inner is not None else 1

    def is_done(self) -> bool:
        """Return True when decoding is complete."""
        return self._inner is not None and self._inner.is_done()

    def feed(self, data: bytes) -> bytes | None:
        """
        Feed bytes to the decoder.

        Returns decrypted plaintext when a chunk is available, else None.

        Raises:
            HeaderParseError: If the header is invalid or the format is unknown
            ChunkAuthenticationError: If authentication fails
        """
        if self._inner is not None:
            return self._inner.feed(data)
        parsed = self._hp.feed(data)
        if parsed is None:
            return None
        file_key = _scrypt_unwrap(parsed, self._passphrase)
        if parsed.base_id == _AGE_IDENTIFIER:
            self._inner = AgeDecoder._make_from_file_key(file_key, parsed.params)
        elif parsed.base_id == _AGE_RT_IDENTIFIER:
            self._inner = AgeRTDecoder._make_from_file_key(
                file_key, parsed.params, self._max_chunk_size
            )
        else:
            raise HeaderParseError(f"Unknown format identifier: {parsed.base_id!r}")
        return None


# ============================================================================
# Factory Functions
# ============================================================================


def iter_encode_chunks(
    chunks: Iterable[bytes],
    encoder: "AgeRTEncoder | AgeEncoder",
) -> Iterator[bytes]:
    """
    Encode chunks as an iterator, delegating all crypto to the provided encoder.

    The caller is responsible for providing correctly-sized chunks:
    - AgeRTEncoder: any chunk size
    - AgeEncoder: non-final chunks must be exactly CHUNK_SIZE bytes (unless using auto-detect)

    Appends an empty final chunk only if the stream has not already been finalized.
    For AgeEncoder with auto-detect, a short chunk will automatically finalize the stream.

    Args:
        chunks: Iterable of plaintext chunks
        encoder: A pre-constructed AgeRTEncoder or AgeEncoder instance

    Yields:
        Wire-format bytes (header first, then encrypted chunks)

    Example:
        >>> encoder = AgeRTEncoder.from_passphrase("secret")
        >>> for wire_chunk in iter_encode_chunks(plaintext_chunks, encoder):
        ...     output.write(wire_chunk)
    """
    yield encoder.get_header()
    for chunk in chunks:
        yield encoder.encode_chunk(chunk)
    if not encoder.finalized:
        yield encoder.encode_chunk(b"", is_final=True)


async def aiter_encode_chunks(
    chunks: AsyncIterable[bytes],
    encoder: "AgeRTEncoder | AgeEncoder",
) -> AsyncIterator[bytes]:
    """
    Encode chunks from an async iterable, delegating all crypto to the provided encoder.

    Args:
        chunks: Async iterable of plaintext chunks
        encoder: A pre-constructed AgeRTEncoder or AgeEncoder instance

    Yields:
        Wire-format bytes (header first, then encrypted chunks)
    """
    yield encoder.get_header()
    async for chunk in chunks:
        yield encoder.encode_chunk(chunk)
    if not encoder.finalized:
        yield encoder.encode_chunk(b"", is_final=True)


def iter_decode_callable(
    read_func: Callable[[int], bytes],
    decoder: "AgeRTDecoder | AgeDecoder",
) -> Iterator[bytes]:
    """
    Decode from a synchronous read function using the provided decoder.

    Calls read_func(decoder.bytes_wanted) in a loop and feeds the result to
    the decoder.  An empty read signals unexpected stream truncation.

    Args:
        read_func: Callable(n: int) -> bytes
        decoder: A pre-constructed AgeRTDecoder or AgeDecoder instance

    Yields:
        Decrypted plaintext chunks

    Raises:
        StreamTruncatedError: If read returns empty bytes before decoding is done
        HeaderParseError: If the age header is invalid
        ChunkAuthenticationError: If a chunk fails authentication

    Example:
        >>> with open('encrypted.age', 'rb') as f:
        ...     for chunk in iter_decode_callable(f.read, AgeRTDecoder("secret")):
        ...         print(chunk)
    """
    while not decoder.is_done():
        data = read_func(decoder.bytes_wanted)
        if not data:
            raise StreamTruncatedError("Stream ended unexpectedly")
        if (result := decoder.feed(data)) is not None:
            yield result


async def aiter_decode_callable(
    read_func: Callable[[int], Awaitable[bytes]],
    decoder: "AgeRTDecoder | AgeDecoder",
) -> AsyncIterator[bytes]:
    """
    Decode from an asynchronous read function using the provided decoder.

    Args:
        read_func: Async callable(n: int) -> bytes
        decoder: A pre-constructed AgeRTDecoder or AgeDecoder instance

    Yields:
        Decrypted plaintext chunks

    Raises:
        StreamTruncatedError: If read returns empty bytes before decoding is done
        HeaderParseError: If the age header is invalid
        ChunkAuthenticationError: If a chunk fails authentication
    """
    while not decoder.is_done():
        data = await read_func(decoder.bytes_wanted)
        if not data:
            raise StreamTruncatedError("Stream ended unexpectedly")
        if (result := decoder.feed(data)) is not None:
            yield result


def iter_decode_chunks(
    data_source: Iterable[bytes],
    decoder: "AgeRTDecoder | AgeDecoder",
) -> Iterator[bytes]:
    """
    Decode from an iterable of byte blobs using the provided decoder.

    Buffers internally to satisfy decoder.bytes_wanted exactly.  Best suited
    for AgeRTDecoder, where chunk boundaries are determined by length prefixes.
    For AgeDecoder, prefer iter_decode_callable with a read function that may
    return short reads at end-of-stream.

    Args:
        data_source: Iterable yielding bytes blobs of arbitrary size
        decoder: A pre-constructed AgeRTDecoder or AgeDecoder instance

    Yields:
        Decrypted plaintext chunks

    Raises:
        StreamTruncatedError: If source is exhausted before decoding is done
    """
    buffer = bytearray()
    source_iter = iter(data_source)

    while not decoder.is_done():
        needed = decoder.bytes_wanted

        while len(buffer) < needed:
            try:
                buffer.extend(next(source_iter))
            except StopIteration:
                raise StreamTruncatedError("Source exhausted before decoding complete")

        data = bytes(buffer[:needed])
        del buffer[:needed]
        if (result := decoder.feed(data)) is not None:
            yield result


async def aiter_decode_chunks(
    data_source: AsyncIterable[bytes],
    decoder: "AgeRTDecoder | AgeDecoder",
) -> AsyncIterator[bytes]:
    """
    Decode from an async iterable of byte blobs using the provided decoder.

    Args:
        data_source: Async iterable yielding bytes blobs of arbitrary size
        decoder: A pre-constructed AgeRTDecoder or AgeDecoder instance

    Yields:
        Decrypted plaintext chunks

    Raises:
        StreamTruncatedError: If source is exhausted before decoding is done
    """
    buffer = bytearray()
    source_iter = aiter(data_source)

    while not decoder.is_done():
        needed = decoder.bytes_wanted

        while len(buffer) < needed:
            try:
                buffer.extend(await anext(source_iter))
            except StopAsyncIteration:
                raise StreamTruncatedError("Source exhausted before decoding complete")

        data = bytes(buffer[:needed])
        del buffer[:needed]
        if (result := decoder.feed(data)) is not None:
            yield result


# ============================================================================
# Convenience Wrappers
# ============================================================================


def encode_file(
    chunks: Iterable[bytes],
    file: BinaryIO,
    encoder: "AgeRTEncoder | AgeEncoder",
) -> None:
    """
    Encode chunks to a file-like object.

    Example:
        >>> with open('data.age', 'wb') as f:
        ...     encode_file([b'chunk1', b'chunk2'], f, AgeRTEncoder.from_passphrase("secret"))
    """
    for wire_chunk in iter_encode_chunks(chunks, encoder):
        file.write(wire_chunk)


def encode_bytes(
    chunks: Iterable[bytes],
    encoder: "AgeRTEncoder | AgeEncoder",
) -> bytes:
    """
    Encode chunks to a bytes object.

    Example:
        >>> encrypted = encode_bytes([b'chunk1', b'chunk2'], AgeRTEncoder.from_passphrase("secret"))
    """
    stream = io.BytesIO()
    for wire_chunk in iter_encode_chunks(chunks, encoder):
        stream.write(wire_chunk)
    return stream.getvalue()


def decode_file(
    file: BinaryIO,
    decoder: "AgeRTDecoder | AgeDecoder",
) -> Iterator[bytes]:
    """
    Decode from a file-like object.

    Example:
        >>> with open('data.age', 'rb') as f:
        ...     for chunk in decode_file(f, AgeRTDecoder("secret")):
        ...         print(chunk)
    """
    yield from iter_decode_callable(file.read, decoder)


def decode_bytes(
    data: bytes,
    decoder: "AgeRTDecoder | AgeDecoder",
) -> Iterator[bytes]:
    """
    Decode from a bytes object.

    Example:
        >>> for chunk in decode_bytes(encrypted, AgeRTDecoder("secret")):
        ...     print(chunk)
    """
    yield from iter_decode_callable(io.BytesIO(data).read, decoder)
