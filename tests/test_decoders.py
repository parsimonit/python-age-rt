"""Tests for AgeRTDecoder, AgeDecoder, and AgeAutoDecoder classes."""

import io

import pytest
from conftest import age_encode, age_rt_encode

from age_rt import (
    AgeAutoDecoder,
    AgeDecoder,
    AgeEncoder,
    AgeRTDecoder,
    AgeRTEncoder,
    ChunkAuthenticationError,
    HeaderParseError,
    InsufficientDataError,
    StreamTruncatedError,
    iter_decode_callable,
    iter_encode_chunks,
)


def test_basic_encryption_decryption(passphrase, sample_chunks):
    """Test basic encryption and decryption."""
    # Encode
    encoder = AgeRTEncoder.from_passphrase(passphrase)
    output = io.BytesIO()
    output.write(encoder.get_header())
    for i, chunk in enumerate(sample_chunks):
        is_final = i == len(sample_chunks) - 1
        output.write(encoder.encode_chunk(chunk, is_final=is_final))

    # Decode using factory function
    output.seek(0)
    decoded = list(iter_decode_callable(output.read, AgeRTDecoder(passphrase)))

    assert decoded == sample_chunks


def test_wrong_passphrase(passphrase, passphrase_wrong):
    """Test wrong passphrase detection."""
    # Encode
    encoder = AgeRTEncoder.from_passphrase(passphrase)
    output = io.BytesIO()
    output.write(encoder.get_header())
    output.write(encoder.encode_chunk(b"Secret", is_final=True))

    # Try to decode with wrong passphrase
    output.seek(0)
    with pytest.raises(ChunkAuthenticationError):
        list(iter_decode_callable(output.read, AgeRTDecoder(passphrase_wrong)))


def test_truncation_detection(passphrase):
    """Test truncation detection."""
    chunks = [b"Data1", b"Data2", b"Data3"]

    # Encode
    encoder = AgeRTEncoder.from_passphrase(passphrase)
    output = io.BytesIO()
    output.write(encoder.get_header())
    for chunk in chunks:
        output.write(encoder.encode_chunk(chunk, is_final=False))  # Missing final chunk!

    # Try to decode (should fail due to truncation)
    output.seek(0)
    with pytest.raises(StreamTruncatedError):
        list(iter_decode_callable(output.read, AgeRTDecoder(passphrase)))


def test_empty_chunk(passphrase):
    """Test empty chunk handling."""
    # Encode with empty final chunk
    encoder = AgeRTEncoder.from_passphrase(passphrase)
    output = io.BytesIO()
    output.write(encoder.get_header())
    output.write(encoder.encode_chunk(b"Data", is_final=False))
    output.write(encoder.encode_chunk(b"", is_final=True))  # Empty final chunk

    # Decode using factory function
    output.seek(0)
    decoded = list(iter_decode_callable(output.read, AgeRTDecoder(passphrase)))

    assert decoded == [b"Data", b""]


def test_stateful_decoder(passphrase, sample_chunks):
    """Test stateful decoder with explicit feed/decode."""
    # Encode
    output = io.BytesIO()
    for wire_chunk in iter_encode_chunks(sample_chunks, AgeRTEncoder.from_passphrase(passphrase)):
        output.write(wire_chunk)

    # Decode using stateful decoder
    output.seek(0)
    decoder = AgeRTDecoder(passphrase)

    decoded = []
    while needed := decoder.bytes_wanted:
        data = output.read(needed)
        if not data:
            raise StreamTruncatedError("Stream ended unexpectedly")
        result = decoder.feed(data)
        if result is not None:
            decoded.append(result)

    # iter_encode_chunks adds a final empty chunk, so decoded should be chunks + [b'']
    assert decoded == sample_chunks + [b""]


def test_age_roundtrip_small(passphrase):
    """AgeEncoder/AgeDecoder: small payload (single final chunk)."""
    plaintext = b"Hello, standard age!"

    wire = age_encode(plaintext, passphrase)
    recovered = list(iter_decode_callable(io.BytesIO(wire).read, AgeDecoder(passphrase)))

    assert b"".join(recovered) == plaintext


def test_age_roundtrip_multi_chunk(passphrase, multi_chunk_payload, large_chunk):
    """AgeEncoder/AgeDecoder: two full CHUNK_SIZE chunks + short final."""
    # iter_encode_chunks with auto-detect: full chunks are non-final, short tail is final
    encoder = AgeEncoder.from_passphrase(passphrase)
    wire = b"".join(iter_encode_chunks([large_chunk, large_chunk, b"tail"], encoder))
    recovered_chunks = list(iter_decode_callable(io.BytesIO(wire).read, AgeDecoder(passphrase)))
    # Auto-detect: two full (non-final) + one short (final), no extra empty chunk
    assert b"".join(recovered_chunks) == multi_chunk_payload

    # Also test via helper which manually drives the encoder
    wire2 = age_encode(multi_chunk_payload, passphrase)
    recovered2 = b"".join(iter_decode_callable(io.BytesIO(wire2).read, AgeDecoder(passphrase)))
    assert recovered2 == multi_chunk_payload


def test_age_wrong_passphrase(passphrase, passphrase_wrong):
    """AgeDecoder must reject a wrong passphrase."""
    wire = age_encode(b"secret", passphrase)

    with pytest.raises(ChunkAuthenticationError):
        list(iter_decode_callable(io.BytesIO(wire).read, AgeDecoder(passphrase_wrong)))


def test_age_rt_decoder_validates_header_maxchunk(passphrase):
    """AgeRTDecoder validates header maxchunk against decoder limit."""
    # Encoder with 8 KiB max
    encoder = AgeRTEncoder.from_passphrase(passphrase, max_chunk_size=8192)
    wire = b"".join(iter_encode_chunks([b"test"], encoder))

    # Decoder with higher limit should accept
    decoder_ok = AgeRTDecoder(passphrase, max_chunk_size=16384)
    recovered = b"".join(iter_decode_callable(io.BytesIO(wire).read, decoder_ok))
    assert recovered == b"test"

    # Decoder with lower limit should reject
    with pytest.raises(HeaderParseError, match="exceeds decoder limit"):
        decoder_bad = AgeRTDecoder(passphrase, max_chunk_size=4096)
        list(iter_decode_callable(io.BytesIO(wire).read, decoder_bad))


def test_age_auto_decoder_age_v1(passphrase):
    """AgeAutoDecoder: auto-detects and decodes age v1 wire format."""
    plaintext = b"Hello from age v1"

    wire = age_encode(plaintext, passphrase)
    recovered = list(iter_decode_callable(io.BytesIO(wire).read, AgeAutoDecoder(passphrase)))
    assert b"".join(recovered) == plaintext


def test_age_auto_decoder_age_rt(passphrase, sample_chunks):
    """AgeAutoDecoder: auto-detects and decodes age-rt wire format."""
    encoder = AgeRTEncoder.from_passphrase(passphrase)
    wire = b"".join(iter_encode_chunks(sample_chunks, encoder))
    recovered = list(iter_decode_callable(io.BytesIO(wire).read, AgeAutoDecoder(passphrase)))
    assert recovered == sample_chunks + [b""]


def test_age_auto_decoder_unknown_identifier(passphrase):
    """AgeAutoDecoder: raises HeaderParseError for unknown format identifier."""
    import os

    from age_rt import _encode_age_psk_header

    wire = _encode_age_psk_header(passphrase, os.urandom(32), os.urandom(16), "unknown.example/v1")

    with pytest.raises(HeaderParseError, match="Unknown format identifier"):
        list(iter_decode_callable(io.BytesIO(wire).read, AgeAutoDecoder(passphrase)))


def test_decoder_feed_zero_bytes(passphrase):
    """Test that feed() with 0 bytes raises InsufficientDataError."""
    decoder = AgeRTDecoder(passphrase)

    # Feed 0 bytes should raise InsufficientDataError
    with pytest.raises(InsufficientDataError):
        decoder.feed(b"")


def test_decoder_feed_too_many_bytes(passphrase):
    """Test that feed() with more bytes than bytes_wanted raises error."""
    age_rt_encode([b"test"], passphrase)

    decoder = AgeRTDecoder(passphrase)
    wanted = decoder.bytes_wanted

    # Feed more than wanted should raise
    with pytest.raises(InsufficientDataError):
        decoder.feed(b"x" * (wanted + 1))


def test_decoder_feed_after_done(passphrase):
    """Test that feed() called after is_done() raises error."""
    wire = age_rt_encode([b"test"], passphrase)

    decoder = AgeRTDecoder(passphrase)

    # Consume all data
    while decoder.bytes_wanted:
        data = wire[: decoder.bytes_wanted]
        wire = wire[decoder.bytes_wanted :]
        decoder.feed(data)

    assert decoder.is_done()
    assert decoder.bytes_wanted == 0

    # Feeding more data after done should raise InsufficientDataError (expected 0 bytes)
    with pytest.raises(InsufficientDataError):
        decoder.feed(b"x")
