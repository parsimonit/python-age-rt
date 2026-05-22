# age-rt Test Suite

This directory contains the test suite for the age-rt Python package, organized into focused test modules for better maintainability.

## Test Structure

The test suite is split into the following modules:

### Core Functionality Tests
- **`test_encoders.py`** - Tests for `AgeRTEncoder` and `AgeEncoder` classes
  - Custom chunk size validation
  - Encoder finalization
  - Large payload handling
  - Boundary conditions

- **`test_decoders.py`** - Tests for `AgeRTDecoder`, `AgeDecoder`, and `AgeAutoDecoder` classes
  - Basic roundtrip encryption/decryption
  - Wrong passphrase detection
  - Stream truncation detection
  - Stateful decoder API
  - Auto-format detection

- **`test_iterators.py`** - Tests for iterator functions
  - `iter_encode_chunks()` - Encode from chunk iterator
  - `iter_decode_callable()` - Decode from read function
  - `iter_decode_chunks()` - Decode from chunk iterator
  - Partial feed handling

- **`test_convenience.py`** - Tests for convenience wrapper functions
  - `encode_file()` / `decode_file()` - File I/O wrappers
  - `encode_bytes()` / `decode_bytes()` - Bytes wrappers
  - Integration with real file operations

- **`test_async.py`** - Minimal smoke tests for async functions
  - `aiter_encode_chunks()` - Async chunk encoding
  - `aiter_decode_callable()` - Async callable decoding
  - `aiter_decode_chunks()` - Async chunk decoding

### Format and Error Tests
- **`test_formats.py`** - Format interoperability and identifier handling
  - age-rt vs age v1 format distinction
  - Identifier parameter parsing and building
  - Custom chunk size identifiers
  - Format mismatch rejection

- **`test_errors.py`** - Error handling, validation, and edge cases
  - Chunk size validation
  - Encoder/decoder state machine edge cases
  - Header corruption scenarios
  - HMAC validation
  - UTF-8 passphrase handling
  - Large header rejection

### Test Infrastructure
- **`conftest.py`** - Shared fixtures and helper functions
  - Pytest fixtures for common test data (passphrases, chunks, payloads)
  - Helper functions: `age_encode()`, `age_rt_encode()`

## Running Tests

### Run all tests
```bash
uv run pytest tests/
```

### Run with coverage
```bash
uv run pytest tests/ --cov=age_rt --cov-report=term-missing --cov-report=html
```

### Run specific test file
```bash
uv run pytest tests/test_encoders.py -v
```

### Run specific test
```bash
uv run pytest tests/test_encoders.py::test_encoder_finalization -v
```

### Run async tests only
```bash
uv run pytest tests/test_async.py -v
```

## Test Coverage

Current test coverage includes:

### ✅ Well-Covered Areas
- Encoder and decoder classes (both age-rt and age v1)
- Iterator functions (sync only, minimal async)
- Convenience wrappers (file and bytes operations)
- Format interoperability (age-rt vs age v1)
- Error handling (authentication, truncation, validation)
- Custom chunk sizes and parameter handling
- Stateful decoder API

### ⚠️ Partially Covered
- Async functions (minimal smoke tests only)
- Very large payloads (tested up to 5 MB)
- Edge cases in header parsing

### ❌ Not Covered
- Property-based testing / fuzzing
- Performance benchmarks
- Network stream scenarios
- Concurrent access patterns

## Coverage Goal

- **Current:** ~85-90% line coverage
- **Target for v0.1:** 85%+ (achieved)
- **Target for stable release:** 90%+

## Dependencies

The test suite requires:
- `pytest>=8` - Test framework
- `pytest-asyncio>=0.21` - Async test support

Install with:
```bash
uv sync
```

## Contributing

When adding new tests:
1. Place tests in the appropriate module based on functionality
2. Use fixtures from `conftest.py` for common test data
3. Follow existing naming conventions (`test_<functionality>`)
4. Add docstrings to describe what each test validates
5. Run the full test suite before committing

## CI/CD

Tests are designed to be run in CI/CD pipelines. Example GitHub Actions workflow:

```yaml
- name: Run tests
  run: |
    uv sync
    uv run pytest tests/ --cov=age_rt --cov-report=xml
```
