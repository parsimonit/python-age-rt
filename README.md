# age-rt Python Module

An implementation of age-rt v0.2 (age-based real-time encryption) for streaming data, with full support for standard age v1 streams. **It currently only supports the passphrase mode**.

## Overview

age-rt provides authenticated encryption for streaming data using the age v1 header format with passphrase-based key derivation. It implements the age-rt v0.2 protocol specification with:

- Variable-length chunks with authentication
- ChaCha20-Poly1305 AEAD encryption (RFC 8439)
- HKDF-based payload key derivation (SHA-256, info="payload")
- Age v1 PSK header format with scrypt
- Truncation detection via final flag in AEAD nonce
- Empty AAD (additional authenticated data)
- Stateful push-based decoder for sync and async contexts
- Auto-detecting decoder for both age v1 and age-rt streams

The package and usage examples focus on age-rt, but the standard age interface the same.

## Wire Format

**age-rt v0.2:**
```
[age header][16-byte nonce][length-prefixed chunks...]
```
Each chunk: `[4-byte big-endian length][ciphertext + 16-byte tag]`

**age v1 (standard):**
```
[age header][16-byte nonce][fixed-size chunks...]
```
Each chunk: `[ciphertext + 16-byte tag]` — no length prefix; short read = final chunk.

## Requirements

Python 3.10 or later.

## Installation

From PyPI:
```bash
pip install age-rt
```

Or install the development version from source:
```bash
git clone https://github.com/parsimonit/python-age-rt.git
cd python-age-rt
pip install -e .
```

Dependency:
```bash
pip install cryptography>=41.0.0
```

## Quick Start

```python
from age_rt import (
    AgeRTEncoder, AgeRTDecoder,
    AgeEncoder, AgeDecoder,
    AgeAutoDecoder,
    encode_bytes, decode_bytes,
)

# age-rt encode
encoder = AgeRTEncoder.from_passphrase("my-secret")
encrypted = encode_bytes([b"Hello", b"World"], encoder)

# age-rt decode
for chunk in decode_bytes(encrypted, AgeRTDecoder("my-secret")):
    print(chunk)  # b"Hello", b"World", b""

# auto-detecting decode (works for both age v1 and age-rt)
for chunk in decode_bytes(encrypted, AgeAutoDecoder("my-secret")):
    print(chunk)
```

## API Design

The module provides:

- **Low-level stateful classes**:
  - `AgeRTEncoder` / `AgeEncoder`: Stateful encoders (created via `from_passphrase()`)
  - `AgeRTDecoder` / `AgeDecoder`: Stateful push-based decoders (feed data, get chunks)
  - `AgeAutoDecoder`: Auto-detecting decoder — handles both age v1 and age-rt streams

- **High-level iterator functions**:
  - `iter_encode_chunks()` / `aiter_encode_chunks()`: Sync/async encoding iterators
  - `iter_decode_callable()` / `aiter_decode_callable()`: Decode from read functions
  - `iter_decode_chunks()` / `aiter_decode_chunks()`: Decode from chunk iterables

- **Convenience wrappers**:
  - `encode_file()` / `decode_file()`: Work with file-like objects
  - `encode_bytes()` / `decode_bytes()`: Work with bytes in memory

All iterator functions and convenience wrappers take a **pre-constructed encoder or decoder instance** rather than a passphrase string. This separates key management from streaming I/O and makes the format explicit at the call site.

## Usage Examples

### Simple File I/O (Recommended)

```python
from age_rt import AgeRTEncoder, AgeRTDecoder, encode_file, decode_file

passphrase = "my-secret-passphrase"
plaintext_chunks = [b"Hello", b"World", b"!"]

# Encode to file
with open("encrypted.age", "wb") as f:
    encode_file(plaintext_chunks, f, AgeRTEncoder.from_passphrase(passphrase))

# Decode from file
with open("encrypted.age", "rb") as f:
    decoded_chunks = list(decode_file(f, AgeRTDecoder(passphrase)))

# Note: decoded_chunks includes the final empty chunk
assert decoded_chunks == plaintext_chunks + [b""]
```

### In-Memory Encoding/Decoding

```python
from age_rt import AgeRTEncoder, AgeRTDecoder, encode_bytes, decode_bytes

passphrase = "secret"
plaintext_chunks = [b"Chunk1", b"Chunk2", b"Chunk3"]

encrypted = encode_bytes(plaintext_chunks, AgeRTEncoder.from_passphrase(passphrase))
decoded_chunks = list(decode_bytes(encrypted, AgeRTDecoder(passphrase)))
assert decoded_chunks == plaintext_chunks + [b""]
```

### Iterator-Based Encoding

```python
from age_rt import AgeRTEncoder, iter_encode_chunks
import io

encoder = AgeRTEncoder.from_passphrase("secret")
plaintext_chunks = [b"Data1", b"Data2", b"Data3"]

output = io.BytesIO()
for wire_chunk in iter_encode_chunks(plaintext_chunks, encoder):
    output.write(wire_chunk)
```

### Auto-Detecting Decoding

`AgeAutoDecoder` reads the header to detect the format (age or age-rt), then delegates to an inner `AgeDecoder` or `AgeRTDecoder`. It accepts the same passphrase and works identically with all factory functions.

```python
from age_rt import AgeAutoDecoder, iter_decode_callable

with open("unknown.age", "rb") as f:
    for chunk in iter_decode_callable(f.read, AgeAutoDecoder("secret")):
        process(chunk)
```

### Async Decoding from Stream

```python
from age_rt import AgeRTDecoder, aiter_decode_callable

async for chunk in aiter_decode_callable(reader.read_fixed_block, AgeRTDecoder("secret")):
    await process(chunk)
```

### Low-Level Stateful Decoder

```python
from age_rt import AgeRTDecoder
import io

decoder = AgeRTDecoder("secret")
stream = io.BytesIO(encrypted_data)

while (wanted := decoder.bytes_wanted) and (data := stream.read(wanted)):
    result = decoder.feed(data)
    if result is not None:
        process(result)
```

### Low-Level Stateful Encoder

```python
from age_rt import AgeRTEncoder

encoder = AgeRTEncoder.from_passphrase("secret")
output.write(encoder.get_header())

for i, chunk in enumerate(plaintext_chunks):
    is_final = (i == len(plaintext_chunks) - 1)
    output.write(encoder.encode_chunk(chunk, is_final=is_final))
```

## Exception Handling

```python
from age_rt import (
    AgeRTError,                    # Base exception
    DecodeError,                   # Base for all decode errors
    HeaderParseError,              # Invalid age header format or unknown identifier
    ChunkAuthenticationError,      # Authentication failed (wrong passphrase/corruption)
    StreamTruncatedError,          # Stream ended without final chunk (factory-level)
    InsufficientDataError,         # Decoder received wrong amount in feed() (low-level)
)

try:
    with open("encrypted.age", "rb") as f:
        for chunk in decode_file(f, AgeRTDecoder(passphrase)):
            process(chunk)
except ChunkAuthenticationError:
    print("Wrong passphrase or corrupted data")
except StreamTruncatedError:
    print("Stream was truncated")
except HeaderParseError:
    print("Invalid or unrecognized age header")
```

## API Reference

### High-Level Iterator Functions (Recommended)

#### Encoding Functions

```python
iter_encode_chunks(chunks: Iterable[bytes], encoder: AgeRTEncoder | AgeEncoder) -> Iterator[bytes]
```

Encode chunks as an iterator, appending an empty final chunk automatically if the stream has not already been finalized.

**Args:**
- `chunks`: Iterable of plaintext chunks
- `encoder`: A pre-constructed `AgeRTEncoder` or `AgeEncoder` instance

**Yields:** Wire-format bytes (header + nonce first, then encrypted chunks)

**Example:**
```python
encoder = AgeRTEncoder.from_passphrase("secret")
for wire_chunk in iter_encode_chunks([b"chunk1", b"chunk2"], encoder):
    output.write(wire_chunk)
```

---

```python
async aiter_encode_chunks(chunks: AsyncIterable[bytes], encoder: AgeRTEncoder | AgeEncoder) -> AsyncIterator[bytes]
```

Async version of `iter_encode_chunks()` for async chunk sources.

---

#### Decoding Functions

```python
iter_decode_callable(read_func: Callable[[int], bytes], decoder: AgeRTDecoder | AgeDecoder | AgeAutoDecoder) -> Iterator[bytes]
```

Decode from a synchronous read function.

**Args:**
- `read_func`: `callable(n: int) -> bytes` — reads exactly `n` bytes
- `decoder`: A pre-constructed decoder instance

**Yields:** Decrypted plaintext chunks

**Raises:** `StreamTruncatedError`, `HeaderParseError`, `ChunkAuthenticationError`

**Example:**
```python
with open('encrypted.age', 'rb') as f:
    for chunk in iter_decode_callable(f.read, AgeRTDecoder("secret")):
        print(chunk)
```

---

```python
async aiter_decode_callable(read_func: Callable[[int], Awaitable[bytes]], decoder: AgeRTDecoder | AgeDecoder | AgeAutoDecoder) -> AsyncIterator[bytes]
```

Async version of `iter_decode_callable()`.

**Example:**
```python
async for chunk in aiter_decode_callable(reader.read_fixed_block, AgeRTDecoder("secret")):
    await process(chunk)
```

---

```python
iter_decode_chunks(data_source: Iterable[bytes], decoder: AgeRTDecoder | AgeDecoder | AgeAutoDecoder) -> Iterator[bytes]
```

Decode from an iterable of byte blobs. Handles internal buffering when blobs don't align with `decoder.bytes_wanted`.

---

```python
async aiter_decode_chunks(data_source: AsyncIterable[bytes], decoder: AgeRTDecoder | AgeDecoder | AgeAutoDecoder) -> AsyncIterator[bytes]
```

Async version of `iter_decode_chunks()`.

---

### Convenience Wrappers

```python
encode_file(chunks: Iterable[bytes], file: BinaryIO, encoder: AgeRTEncoder | AgeEncoder) -> None
```

Encode chunks to a file-like object.

**Example:**
```python
with open('data.age', 'wb') as f:
    encode_file([b'chunk1', b'chunk2'], f, AgeRTEncoder.from_passphrase("secret"))
```

---

```python
encode_bytes(chunks: Iterable[bytes], encoder: AgeRTEncoder | AgeEncoder) -> bytes
```

Encode chunks to a `bytes` object. Returns the complete encrypted stream.

---

```python
decode_file(file: BinaryIO, decoder: AgeRTDecoder | AgeDecoder | AgeAutoDecoder) -> Iterator[bytes]
```

Decode from a file-like object.

---

```python
decode_bytes(data: bytes, decoder: AgeRTDecoder | AgeDecoder | AgeAutoDecoder) -> Iterator[bytes]
```

Decode from a `bytes` object.

---

### Low-Level Stateful Classes

For advanced use cases requiring fine-grained control.

#### AgeRTEncoder

```python
AgeRTEncoder.from_passphrase(passphrase: str, max_chunk_size: int = 65536) -> AgeRTEncoder
```

Create an age-rt encoder. Generates a random 32-byte file key and scrypt salt internally.

⚠️ **Non-standard `max_chunk_size` values (other than 65536) are for internal/testing use only.** They create non-interoperable streams with a modified identifier.

**Instance methods:**

```python
get_header() -> bytes        # age header + 16-byte payload nonce
encode_chunk(plaintext: bytes, is_final: bool = False) -> bytes
finalized: bool              # True once the final chunk has been emitted
```

`encode_chunk` includes a 4-byte big-endian length prefix. Raises `RuntimeError` if called after finalization.

---

#### AgeEncoder

```python
AgeEncoder.from_passphrase(passphrase: str, chunk_size: int = 65536) -> AgeEncoder
```

Create a standard age v1 encoder. Uses a fixed 16-byte file key and fixed chunk size.

⚠️ **Non-standard `chunk_size` values (other than 65536) are for internal/testing use only.** They create non-interoperable streams that will fail to decode with other age implementations.

⚠️ **`AgeEncoder` requires non-final chunks to be exactly `chunk_size` bytes.** When using `iter_encode_chunks()`, ensure your chunks match the encoder's `chunk_size`, or the final chunk is automatically detected via short read. Mismatched chunk sizes will raise `ValueError`.

**Instance methods:** same as `AgeRTEncoder` — `get_header()`, `encode_chunk()`, `finalized`.

`encode_chunk` with `is_final=None` (default) auto-detects: a short chunk is automatically the final chunk.

---

#### AgeRTDecoder

```python
AgeRTDecoder(passphrase: str, max_chunk_size: int = 65536)
```

Stateful push-based decoder for age-rt v0.2 streams.

⚠️ **The `max_chunk_size` parameter is for internal/testing use only.** Use the default (65536) for standard age-rt streams.

**Properties / methods:**

```python
bytes_wanted: int      # bytes to supply to the next feed() call; 0 when done
is_done() -> bool
feed(data: bytes) -> bytes | None
```

`feed()` returns a decrypted plaintext chunk when one is ready, otherwise `None`. Call with exactly `bytes_wanted` bytes (1 byte during header scan, 16 during nonce, variable during data).

**Raises:** `HeaderParseError`, `ChunkAuthenticationError`, `InsufficientDataError`

**Usage pattern:**
```python
decoder = AgeRTDecoder(passphrase)
while (wanted := decoder.bytes_wanted) and (data := source.read(wanted)):
    result = decoder.feed(data)
    if result is not None:
        process(result)
```

---

#### AgeDecoder

```python
AgeDecoder(passphrase: str, chunk_size: int = 65536)
```

Stateful push-based decoder for standard age v1 streams. Identical interface to `AgeRTDecoder`. During the data phase `bytes_wanted` is `chunk_size + 16`; a short read signals the final chunk.

⚠️ **The `chunk_size` parameter is for internal/testing use only.** Use the default (65536) for standard age v1 streams.

---

#### AgeAutoDecoder

```python
AgeAutoDecoder(passphrase: str, max_chunk_size: int = 65536)
```

Auto-detecting decoder. Reads the header byte-by-byte, detects the format identifier, then delegates all payload decoding to an inner `AgeDecoder` (age v1) or `AgeRTDecoder` (age-rt). Raises `HeaderParseError` if the identifier is unknown.

Identical `bytes_wanted` / `is_done()` / `feed()` interface — drop-in replacement for either decoder in any iterator function.

⚠️ **The `max_chunk_size` parameter is for internal/testing use only.** Use the default (65536) for standard streams.

---

## Design Rationale

### Push-Based Stateful Decoder

The decoder uses a **push-based architecture** where it announces data needs via `bytes_wanted`:

- **Decouples I/O from crypto**: Core decoder logic is independent of I/O mechanisms
- **Supports sync and async**: Same decoder works with blocking I/O, async I/O, or manual feeding
- **Exact reads**: Always requests exactly the bytes it needs (efficient with `read_fixed_block()`)
- **No buffering in core**: The decoder itself never buffers. Only `iter_decode_chunks()` / `aiter_decode_chunks()` buffer internally (to handle arbitrarily-sized input blobs); `iter_decode_callable()` / `aiter_decode_callable()` expect the read function to return exactly the requested bytes

This architecture enables the decoder to work seamlessly with:
- File I/O: `f.read(decoder.bytes_wanted)`
- Async streams: `await reader.read_fixed_block(decoder.bytes_wanted)`
- Network streams: `socket.recv(decoder.bytes_wanted)`

### Iterator Functions Use Decoder Instances as First-Class Arguments

- Iterator functions accept a **decoder instance**
- **Format is explicit**: `AgeRTDecoder(passphrase="pw")` vs `AgeDecoder(passphrase="pw")` vs `AgeAutoDecoder(passphrase="pw")` — no hidden dispatch
- **Parameters travel with the decoder**: `max_chunk_size`, `chunk_size` etc. are set at construction
- **Composable**: Decoders can be created, configured, and passed around independently of I/O

### Factory Method Pattern for Encoders

Encoders use `from_passphrase()` rather than direct instantiation:

- **Matches age ecosystem**: Standard age libraries use builder/factory patterns
- **Internal key management**: File keys and salts generated internally
- **Extensible**: Easy to add `from_recipients()`, `from_ssh_keys()`, etc.

### Sync-First with Async Support

The core decoder is synchronous; `feed()` returns `bytes | None`, not a coroutine. Async support is provided by thin async generator wrappers (`aiter_decode_callable`, `aiter_decode_chunks`, `aiter_encode_chunks`).

### Empty Chunks Are Preserved

The decoder yields the final empty chunk emitted e.g. by `iter_encode_chunks()`:

- **Transparent**: Decoder preserves all chunks the encoder sent
- **Application choice**: Filter if needed: `(c for c in decode_bytes(...) if c)`

## Testing

Run the test suite:
```bash
uv run pytest
```

## Security Considerations

Note that, in contrast to standard age, variable size **messages in age-rt expose interpretable length patterns (but not content)**. For real-time streaming, this is often an acceptable compromise between delay, bandwidth efficiency on the one hand, and security on the other hand, in particular if secured with an additional layer of transport encryption.

The security of this implementation derives from the following facts:

- Using cryptographic primitives from the well known `cryptography` package
- Compatibility with the official Go age implementation (for the age part)
- Being a minor protocol variation (the variable chunk part)
- Being small and open source

**THIS PACKAGE IMPLEMENTATION IS NOT INDEPENDENTLY REVIEWED!**

These are the basic cryptographic properties:

- **Scrypt parameters**: N=2^18, r=8, p=1 (age v1 standard)
- **AEAD**: ChaCha20-Poly1305 with unique nonces per chunk
- **Truncation detection**: Final flag in nonce prevents truncation attacks
- **Authentication**: Each chunk is authenticated with a 16-byte Poly1305 tag
- **Max chunk size**: Capped at 16 MB (`_MAX_CHUNK_SIZE`) to prevent DoS via oversized length fields

## Protocol Specification

The age-rt protocol variant is inherently linked to age. age-rt v0.2 implements:

- Variable-length chunks (max 64 KiB by default)
- 12-byte AEAD nonce: 11-byte big-endian counter + 1-byte final flag
- Empty AAD (additional authenticated data)
- HKDF(file_key, salt=nonce, info="payload") for payload key derivation
- Age v1 header format for passphrase mode (scrypt stanza)

The primary protocol spec can be found at the [age-rt-encryption repository](https://github.com/parsimonit/age-rt-encryption).

## Package Structure

Currently a single-file module (`age_rt.py`) for easy integration. Future versions may deliver a richer internal structure.

## Release Notes

### v0.1.0 (Initial Release)

**First public release** of age-rt Python implementation.

**Features:**
- age-rt v0.2 streaming encryption with variable-length chunks
- Full age v1 standard format support
- Passphrase-based encryption (scrypt key derivation)
- Auto-detecting decoder for both formats
- Sync and async iterator APIs
- Fully type-hinted (PEP 561 compatible with py.typed marker)
- Comprehensive test suite (65 tests, 90%+ coverage)

**Limitations:**
- Passphrase mode only (no public key support yet)
- Single-file module (no internal package structure)

**Security Note:** This implementation has not been independently audited. Use at your own risk.

See the [GitHub releases page](https://github.com/parsimonit/python-age-rt/releases) for future updates.

## Contributing

Contributions are welcome! Please see the [GitHub repository](https://github.com/parsimonit/python-age-rt) for issue tracking and pull requests.

## License

MIT License. See [LICENSE](LICENSE) file for details.

## References

- [age encryption format](https://age-encryption.org/)
- [RFC 8439: ChaCha20-Poly1305](https://www.rfc-editor.org/rfc/rfc8439)
- [RFC 5869: HMAC-based Key Derivation Function (HKDF)](https://www.rfc-editor.org/rfc/rfc5869)
