"""Minimal smoke tests for async iterator functions."""

import pytest

from age_rt import (
    AgeDecoder,
    AgeEncoder,
    AgeRTDecoder,
    AgeRTEncoder,
    aiter_decode_callable,
    aiter_decode_chunks,
    aiter_encode,
)


async def async_chunk_source(chunks):
    """Helper: async generator for chunks."""
    for chunk in chunks:
        yield chunk


@pytest.mark.asyncio
async def test_aiter_encode_age_rt(passphrase, sample_chunks):
    """Test aiter_encode with age-rt format."""
    encoder = AgeRTEncoder.from_passphrase(passphrase)

    wire_chunks = []
    async for wire_chunk in aiter_encode(async_chunk_source(sample_chunks), encoder):
        wire_chunks.append(wire_chunk)

    # Should produce header + encoded chunks
    assert len(wire_chunks) > 0
    wire = b"".join(wire_chunks)

    # Verify we can decode
    from age_rt import decode_bytes

    decoded = list(decode_bytes(wire, AgeRTDecoder(passphrase)))
    assert decoded == sample_chunks + [b""]


@pytest.mark.asyncio
async def test_aiter_encode_age_v1(passphrase, large_chunk):
    """Test aiter_encode with age v1 format."""
    encoder = AgeEncoder.from_passphrase(passphrase)
    chunks = [large_chunk, b"tail"]

    wire_chunks = []
    async for wire_chunk in aiter_encode(async_chunk_source(chunks), encoder):
        wire_chunks.append(wire_chunk)

    wire = b"".join(wire_chunks)

    # Verify we can decode
    from age_rt import decode_bytes

    decoded = list(decode_bytes(wire, AgeDecoder(passphrase)))
    assert b"".join(decoded) == large_chunk + b"tail"


@pytest.mark.asyncio
async def test_aiter_decode_callable(passphrase, sample_chunks):
    """Test aiter_decode_callable with age-rt format."""
    from conftest import age_rt_encode

    wire = age_rt_encode(sample_chunks, passphrase)

    # Create async read function
    offset = [0]  # Use list to allow mutation in nested function

    async def async_read(n: int) -> bytes:
        result = wire[offset[0] : offset[0] + n]
        offset[0] += len(result)
        return result

    # Decode
    decoded = []
    async for chunk in aiter_decode_callable(async_read, AgeRTDecoder(passphrase)):
        decoded.append(chunk)

    assert decoded == sample_chunks + [b""]


@pytest.mark.asyncio
async def test_aiter_decode_chunks(passphrase, sample_chunks):
    """Test aiter_decode_chunks with age-rt format."""
    from conftest import age_rt_encode

    wire = age_rt_encode(sample_chunks, passphrase)

    # Split into small wire chunks
    chunk_size = 50
    wire_chunks = [wire[i : i + chunk_size] for i in range(0, len(wire), chunk_size)]

    # Decode
    decoded = []
    async for chunk in aiter_decode_chunks(
        async_chunk_source(wire_chunks), AgeRTDecoder(passphrase)
    ):
        decoded.append(chunk)

    assert decoded == sample_chunks + [b""]


@pytest.mark.asyncio
async def test_aiter_decode_callable_age_v1(passphrase):
    """Test aiter_decode_callable with age v1 format."""
    from conftest import age_encode

    plaintext = b"Hello async age v1"
    wire = age_encode(plaintext, passphrase)

    offset = [0]

    async def async_read(n: int) -> bytes:
        result = wire[offset[0] : offset[0] + n]
        offset[0] += len(result)
        return result

    decoded = []
    async for chunk in aiter_decode_callable(async_read, AgeDecoder(passphrase)):
        decoded.append(chunk)

    assert b"".join(decoded) == plaintext


@pytest.mark.asyncio
async def test_aiter_decode_chunks_empty_source(passphrase):
    """Test aiter_decode_chunks with empty async source."""
    from age_rt import StreamTruncatedError

    async def empty_source():
        return
        yield  # Make it a generator

    with pytest.raises(StreamTruncatedError):
        async for _ in aiter_decode_chunks(empty_source(), AgeRTDecoder(passphrase)):
            pass
