"""Tests for error handling, validation, and edge cases."""

import io
import struct

import pytest
from conftest import age_rt_encode

from age_rt import (
    AgeRTDecoder,
    AgeRTEncoder,
    ChunkAuthenticationError,
    HeaderParseError,
    InsufficientDataError,
    StreamTruncatedError,
    iter_decode_callable,
)


def test_chunk_too_large_encoder(passphrase):
    """Test that encoder rejects chunks exceeding max_chunk_size."""
    max_chunk_size = 8192
    encoder = AgeRTEncoder.from_passphrase(passphrase, max_chunk_size=max_chunk_size)

    # Chunk exceeding limit should fail
    with pytest.raises(ValueError, match="Chunk too large"):
        encoder.encode_chunk(b"x" * (max_chunk_size + 1), is_final=False)

    # Chunk at exact limit should work
    encoder.encode_chunk(b"x" * max_chunk_size, is_final=True)


def test_chunk_length_exceeds_max_decoder(passphrase):
    """AgeRTDecoder validates chunk length against header maxchunk."""
    max_chunk = 1024

    # Create a valid header
    encoder = AgeRTEncoder.from_passphrase(passphrase, max_chunk_size=max_chunk)
    header = encoder.get_header()

    # Manually craft invalid chunk (length exceeds max)
    invalid_length = max_chunk + 100  # Exceeds max_chunk_size
    # Note: we need to create a valid-looking chunk that will fail on length check
    # The length prefix alone should trigger the error before authentication
    invalid_chunk = struct.pack(">I", invalid_length) + b"x" * invalid_length

    wire = header + invalid_chunk

    with pytest.raises(ChunkAuthenticationError, match="outside valid range"):
        decoder = AgeRTDecoder(passphrase, max_chunk_size=max_chunk)
        list(iter_decode_callable(io.BytesIO(wire).read, decoder))


def test_corrupted_header_base64(passphrase):
    """Test that corrupted base64 in header raises error."""
    # Create a header with invalid base64
    # Use correct age-rt identifier
    bad_header = b"""github.com/parsimonit/age-rt-encryption
-> scrypt !!!INVALID_BASE64!!! 18
AAAAAAAAAAAAAAAAAAAAA
---
"""

    # Invalid base64 will cause either HeaderParseError or StreamTruncatedError
    with pytest.raises((HeaderParseError, StreamTruncatedError)):
        decoder = AgeRTDecoder(passphrase)
        list(iter_decode_callable(io.BytesIO(bad_header).read, decoder))


def test_corrupted_scrypt_stanza_wrong_args(passphrase):
    """Test that scrypt stanza with wrong number of args raises error."""
    # Create a header with wrong scrypt args (missing work factor)
    # Use correct age-rt identifier
    bad_header = b"""github.com/parsimonit/age-rt-encryption
-> scrypt AAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAA
---
"""

    # Wrong args will cause either HeaderParseError or StreamTruncatedError
    with pytest.raises((HeaderParseError, StreamTruncatedError)):
        decoder = AgeRTDecoder(passphrase)
        list(iter_decode_callable(io.BytesIO(bad_header).read, decoder))


def test_corrupted_scrypt_work_factor(passphrase):
    """Test that invalid scrypt work factor raises HeaderParseError."""
    import os

    from age_rt import _AGE_RT_IDENTIFIER, _encode_age_psk_header

    # We need to manually create a header with wrong work factor
    # This is tricky because _encode_age_psk_header uses correct work factor
    # Let's modify a valid header - use age-rt identifier
    valid_header = _encode_age_psk_header(
        passphrase, os.urandom(32), os.urandom(16), _AGE_RT_IDENTIFIER
    )

    # Replace work factor 18 with 17
    invalid_header = valid_header.replace(b" 18\n", b" 17\n")

    with pytest.raises(HeaderParseError, match="work factor"):
        decoder = AgeRTDecoder(passphrase)
        list(iter_decode_callable(io.BytesIO(invalid_header).read, decoder))


def test_header_hmac_failure(passphrase, passphrase_wrong):
    """Test that wrong HMAC on file key wrap fails authentication."""
    # Encoding with one passphrase, decoding with another should fail
    # This is already tested elsewhere, but let's be explicit about HMAC
    wire = age_rt_encode([b"test"], passphrase)

    with pytest.raises(ChunkAuthenticationError):
        list(iter_decode_callable(io.BytesIO(wire).read, AgeRTDecoder(passphrase_wrong)))


def test_zero_byte_non_final_chunk(passphrase):
    """Test that zero-byte non-final chunks are valid for age-rt."""
    encoder = AgeRTEncoder.from_passphrase(passphrase)
    output = io.BytesIO()
    output.write(encoder.get_header())

    # Zero-byte non-final chunk should work
    output.write(encoder.encode_chunk(b"", is_final=False))
    output.write(encoder.encode_chunk(b"data", is_final=True))

    wire = output.getvalue()
    decoded = list(iter_decode_callable(io.BytesIO(wire).read, AgeRTDecoder(passphrase)))
    assert decoded == [b"", b"data"]


def test_encoder_after_finalization(passphrase):
    """Test that encoding after finalization raises error."""
    encoder = AgeRTEncoder.from_passphrase(passphrase)
    encoder.encode_chunk(b"test", is_final=True)

    with pytest.raises(RuntimeError, match="already finalized"):
        encoder.encode_chunk(b"more", is_final=False)


def test_decoder_insufficient_data(passphrase):
    """Test InsufficientDataError when feed() receives wrong amount."""
    wire = age_rt_encode([b"test"], passphrase)
    decoder = AgeRTDecoder(passphrase)

    wanted = decoder.bytes_wanted

    # Feed too many bytes
    with pytest.raises(InsufficientDataError):
        decoder.feed(wire[: wanted + 10])


def test_malformed_header_no_footer(passphrase):
    """Test that header without MAC footer raises error."""
    bad_header = b"""github.com/parsimonit/age-rt-encryption
-> scrypt AAAAAAAAAAAAAAAAAAAAAA 18
AAAAAAAAAAAAAAAAAAAAA
"""
    # Missing "---" footer

    # Will raise StreamTruncatedError when trying to read more
    with pytest.raises(StreamTruncatedError):
        decoder = AgeRTDecoder(passphrase)
        list(iter_decode_callable(io.BytesIO(bad_header).read, decoder))


def test_header_too_large():
    """Test that excessively large header is rejected."""
    # Create a header that's too large (> 4096 bytes)
    passphrase = "test"
    huge_header = b"github.com/parsimonit/age-rt-encryption\n"
    huge_header += b"-> scrypt " + b"A" * 5000 + b" 18\n"
    huge_header += b"AAAA\n---\n"

    # Large header may cause various errors
    with pytest.raises((HeaderParseError, StreamTruncatedError)):
        decoder = AgeRTDecoder(passphrase)
        list(iter_decode_callable(io.BytesIO(huge_header).read, decoder))


def test_special_utf8_passphrase():
    """Test that special UTF-8 characters in passphrase work correctly."""
    special_passphrase = "пароль🔐密码"
    chunks = [b"test"]

    # Should encode and decode correctly
    wire = age_rt_encode(chunks, special_passphrase)
    decoded = list(iter_decode_callable(io.BytesIO(wire).read, AgeRTDecoder(special_passphrase)))
    assert decoded == chunks + [b""]

    # Wrong passphrase should still fail
    with pytest.raises(ChunkAuthenticationError):
        list(iter_decode_callable(io.BytesIO(wire).read, AgeRTDecoder("wrong")))


def test_very_long_passphrase():
    """Test that very long passphrases work correctly."""
    long_passphrase = "a" * 10000  # 10 KB passphrase
    chunks = [b"test"]

    wire = age_rt_encode(chunks, long_passphrase)
    decoded = list(iter_decode_callable(io.BytesIO(wire).read, AgeRTDecoder(long_passphrase)))
    assert decoded == chunks + [b""]


def test_chunk_index_many_chunks(passphrase):
    """Test encoding/decoding with many chunks (stress test chunk index)."""
    # Create 1000 small chunks
    chunks = [f"chunk{i}".encode() for i in range(1000)]

    wire = age_rt_encode(chunks, passphrase)
    decoded = list(iter_decode_callable(io.BytesIO(wire).read, AgeRTDecoder(passphrase)))

    # Should get all chunks plus final empty
    assert decoded == chunks + [b""]
    assert len(decoded) == 1001
