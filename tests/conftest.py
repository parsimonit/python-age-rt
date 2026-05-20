"""Shared fixtures and test utilities for age-rt test suite."""

import pytest

from age_rt import (
    CHUNK_SIZE,
    AgeEncoder,
    AgeRTEncoder,
)

# ============================================================================
# Shared Test Data
# ============================================================================


@pytest.fixture
def passphrase():
    """Standard test passphrase."""
    return "correct-horse-battery-staple"


@pytest.fixture
def passphrase_wrong():
    """Wrong passphrase for authentication tests."""
    return "wrong-passphrase"


@pytest.fixture
def sample_chunks():
    """Standard set of test chunks."""
    return [b"Hello", b"World", b"!"]


@pytest.fixture
def large_chunk():
    """A large chunk at standard CHUNK_SIZE."""
    return bytes(range(256)) * (CHUNK_SIZE // 256)


@pytest.fixture
def multi_chunk_payload(large_chunk):
    """Payload spanning multiple chunks."""
    return large_chunk * 2 + b"tail"


# ============================================================================
# Helper Functions
# ============================================================================


def age_encode(plaintext: bytes, passphrase: str) -> bytes:
    """Helper: encode arbitrary-length plaintext with AgeEncoder."""
    encoder = AgeEncoder.from_passphrase(passphrase)
    out = [encoder.get_header()]
    offset = 0
    while offset + CHUNK_SIZE <= len(plaintext):
        out.append(encoder.encode_chunk(plaintext[offset : offset + CHUNK_SIZE]))
        offset += CHUNK_SIZE
    # Final chunk (auto-detects is_final=True since len < CHUNK_SIZE)
    out.append(encoder.encode_chunk(plaintext[offset:]))
    return b"".join(out)


def age_rt_encode(chunks: list[bytes], passphrase: str) -> bytes:
    """Helper: encode chunks with AgeRTEncoder."""
    from age_rt import iter_encode_chunks

    encoder = AgeRTEncoder.from_passphrase(passphrase)
    return b"".join(iter_encode_chunks(chunks, encoder))
