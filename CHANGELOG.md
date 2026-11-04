# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Releases before 1.0 may contain breaking
changes in minor and patch versions.

## [Unreleased]

### Changed

- **Breaking:** the decode iterators and helpers (`decode_file`, `decode_bytes`,
  `iter_decode_callable`, `aiter_decode_callable`, `iter_decode_chunks`, `aiter_decode_chunks`) no
  longer yield the final empty chunk. It is the end-of-stream marker, not a message, so
  `iter_decode(iter_encode(chunks)) == chunks` for age-rt and an empty payload decodes to no
  chunks. Empty non-final chunks (age-rt heartbeats) are still yielded. The low-level
  `decoder.feed()` is unchanged: it still returns the empty final chunk, and `decoder.is_done()` is
  the signal.
- `AgeEncoder.encode_chunk` now defers its output by one chunk: the first call returns `b""` and
  finalizing may return two chunks joined. It holds back one full chunk so that it can mark it as
  final. The concatenated ciphertext is standard age. The encode iterators handle this for you.
- `AgeEncoder` copies buffer-like input (`bytearray`, `memoryview`), so reusing a read buffer
  cannot alter the held-back chunk.

### Fixed

- `AgeEncoder` no longer emits an empty final chunk after a non-empty payload. Since age v1.1.0 an
  empty final chunk is only valid as the sole chunk of an empty payload.
- The age decoder now rejects an empty final chunk after a non-empty payload with `DecodeError`,
  as current age and rage do. Streams written by age-rt 0.2.2 or earlier whose payload is a
  multiple of the chunk size contain such a chunk and no longer decode.

### Documentation

- The module docstring and README examples now show the instance-based API.

## [0.2.2] - 2026-05-28

### Fixed

- The chunk iterator decoder did not work in standard age mode.

## [0.2.1] - 2026-05-22

### Changed

- **Breaking:** renamed the async convenience wrapper `aiter_encode` to `aiter_encode_chunks` to
  match the sync version.

## [0.2.0] - 2026-05-21

### Fixed

- Aligned scrypt key derivation, header format, and key size with age-rt v2.

## [0.1.0] - 2026-05-20

Initial release.

- age-rt v0.2 streaming encryption with variable-length chunks.
- Standard age v1 format support.
- Passphrase-based encryption (scrypt key derivation); no public key support.
- Auto-detecting decoder for both formats.
- Sync and async iterator APIs.
- Fully type-hinted (PEP 561, `py.typed`).

[Unreleased]: https://github.com/parsimonit/python-age-rt/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/parsimonit/python-age-rt/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/parsimonit/python-age-rt/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/parsimonit/python-age-rt/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/parsimonit/python-age-rt/releases/tag/v0.1.0
