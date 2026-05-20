"""Tests for AgeRTEncoder and AgeEncoder classes."""

import io

import pytest

from age_rt import (
    CHUNK_SIZE,
    AgeEncoder,
    AgeRTEncoder,
)


def test_age_rt_encoder_custom_max_chunk_size(passphrase):
    """AgeRTEncoder with custom max_chunk_size validates and encodes correctly."""
    max_chunk_size = 8192  # 8 KiB

    encoder = AgeRTEncoder.from_passphrase(passphrase, max_chunk_size=max_chunk_size)

    # Chunk within limit should work
    small_chunk = b"a" * 4096
    encoder.encode_chunk(small_chunk, is_final=False)

    # Chunk at limit should work
    max_chunk = b"b" * max_chunk_size
    encoder_2 = AgeRTEncoder.from_passphrase(passphrase, max_chunk_size=max_chunk_size)
    encoder_2.encode_chunk(max_chunk, is_final=False)

    # Chunk exceeding limit should fail
    encoder_3 = AgeRTEncoder.from_passphrase(passphrase, max_chunk_size=max_chunk_size)
    with pytest.raises(ValueError, match="Chunk too large"):
        encoder_3.encode_chunk(b"c" * (max_chunk_size + 1), is_final=False)


def test_age_encoder_custom_chunk_size(passphrase):
    """AgeEncoder with custom chunk_size produces non-standard format."""
    chunk_size = 32768  # 32 KiB
    plaintext = b"x" * (chunk_size * 2 + 100)

    # Encode with custom chunk size
    from age_rt import AgeDecoder, HeaderParseError, iter_decode_callable, iter_encode_chunks

    encoder = AgeEncoder.from_passphrase(passphrase, chunk_size=chunk_size)
    chunks = [plaintext[i : i + chunk_size] for i in range(0, len(plaintext), chunk_size)]
    wire = b"".join(iter_encode_chunks(chunks, encoder))

    # Decode with matching chunk size
    decoder = AgeDecoder(passphrase, chunk_size=chunk_size)
    recovered = b"".join(iter_decode_callable(io.BytesIO(wire).read, decoder))
    assert recovered == plaintext

    # Decode with wrong chunk size should fail
    with pytest.raises(HeaderParseError, match="Chunk size mismatch"):
        decoder_wrong = AgeDecoder(passphrase, chunk_size=CHUNK_SIZE)
        list(iter_decode_callable(io.BytesIO(wire).read, decoder_wrong))


def test_chunk_size_validation():
    """Test chunk_size and max_chunk_size validation."""
    passphrase = "pw"

    # Invalid chunk sizes
    for invalid_size in [0, -1, 16 * 1024 * 1024 + 1]:
        with pytest.raises(ValueError):
            AgeEncoder.from_passphrase(passphrase, chunk_size=invalid_size)

        with pytest.raises(ValueError):
            from age_rt import AgeDecoder

            AgeDecoder(passphrase, chunk_size=invalid_size)

        with pytest.raises(ValueError):
            AgeRTEncoder.from_passphrase(passphrase, max_chunk_size=invalid_size)

        with pytest.raises(ValueError):
            from age_rt import AgeRTDecoder

            AgeRTDecoder(passphrase, max_chunk_size=invalid_size)

    # Valid boundary cases
    for valid_size in [1, 65536, 16 * 1024 * 1024]:
        AgeEncoder.from_passphrase(passphrase, chunk_size=valid_size)
        from age_rt import AgeDecoder

        AgeDecoder(passphrase, chunk_size=valid_size)
        AgeRTEncoder.from_passphrase(passphrase, max_chunk_size=valid_size)
        from age_rt import AgeRTDecoder

        AgeRTDecoder(passphrase, max_chunk_size=valid_size)


def test_encoder_finalization(passphrase):
    """Test that encoding after finalization raises an error."""
    # Test AgeRTEncoder
    encoder_rt = AgeRTEncoder.from_passphrase(passphrase)
    encoder_rt.encode_chunk(b"test", is_final=True)
    assert encoder_rt.finalized

    with pytest.raises(RuntimeError, match="already finalized"):
        encoder_rt.encode_chunk(b"more data", is_final=False)

    # Test AgeEncoder
    encoder_age = AgeEncoder.from_passphrase(passphrase)
    encoder_age.encode_chunk(b"test", is_final=True)
    assert encoder_age.finalized

    with pytest.raises(RuntimeError, match="already finalized"):
        encoder_age.encode_chunk(b"more data", is_final=False)


def test_encoder_large_payload(passphrase):
    """Test encoding large payloads (multi-megabyte)."""
    # Create a 2 MB payload
    large_payload = b"x" * (2 * 1024 * 1024)

    # Test AgeEncoder
    encoder = AgeEncoder.from_passphrase(passphrase)
    from age_rt import AgeDecoder, iter_decode_callable, iter_encode_chunks

    chunks = [large_payload[i : i + CHUNK_SIZE] for i in range(0, len(large_payload), CHUNK_SIZE)]
    wire = b"".join(iter_encode_chunks(chunks, encoder))

    # Decode and verify
    decoder = AgeDecoder(passphrase)
    recovered = b"".join(iter_decode_callable(io.BytesIO(wire).read, decoder))
    assert recovered == large_payload

    # Test AgeRTEncoder with variable chunks
    encoder_rt = AgeRTEncoder.from_passphrase(passphrase)
    # Use varied chunk sizes
    rt_chunks = [large_payload[i : i + 50000] for i in range(0, len(large_payload), 50000)]
    wire_rt = b"".join(iter_encode_chunks(rt_chunks, encoder_rt))

    from age_rt import AgeRTDecoder

    decoder_rt = AgeRTDecoder(passphrase)
    recovered_rt = b"".join(iter_decode_callable(io.BytesIO(wire_rt).read, decoder_rt))
    assert recovered_rt == large_payload


def test_encoder_chunk_at_exact_boundary(passphrase):
    """Test encoding chunk at exact max_chunk_size boundary."""
    max_size = 8192

    encoder = AgeRTEncoder.from_passphrase(passphrase, max_chunk_size=max_size)
    # Chunk exactly at boundary should work
    exact_chunk = b"z" * max_size
    wire = encoder.encode_chunk(exact_chunk, is_final=True)

    # Verify it encodes correctly
    assert len(wire) > len(exact_chunk)  # Should include length prefix + tag

    # Decode to verify
    from age_rt import AgeRTDecoder, iter_decode_callable

    full_wire = encoder.get_header() + wire
    decoder = AgeRTDecoder(passphrase, max_chunk_size=max_size)
    recovered = list(iter_decode_callable(io.BytesIO(full_wire).read, decoder))
    assert recovered == [exact_chunk]
