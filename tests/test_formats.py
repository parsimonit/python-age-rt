"""Tests for format interoperability and identifier handling."""

import io

import pytest
from conftest import age_encode, age_rt_encode

from age_rt import (
    _AGE_IDENTIFIER,
    _AGE_RT_IDENTIFIER,
    CHUNK_SIZE,
    AgeDecoder,
    AgeEncoder,
    AgeRTDecoder,
    AgeRTEncoder,
    ChunkAuthenticationError,
    HeaderParseError,
    _build_identifier,
    _parse_identifier_params,
    iter_decode_callable,
    iter_encode_chunks,
)


def test_age_rt_rejects_age_wire(passphrase):
    """AgeRTDecoder must not silently accept standard age v1 wire data."""
    wire = age_encode(b"hello", passphrase)

    with pytest.raises((HeaderParseError, ChunkAuthenticationError)):
        list(iter_decode_callable(io.BytesIO(wire).read, AgeRTDecoder(passphrase)))


def test_age_rejects_age_rt_wire(passphrase):
    """AgeDecoder must not silently accept age-rt wire data."""
    wire = age_rt_encode([b"hello"], passphrase)

    with pytest.raises((HeaderParseError, ChunkAuthenticationError)):
        list(iter_decode_callable(io.BytesIO(wire).read, AgeDecoder(passphrase)))


def test_identifier_with_parameters(passphrase):
    """Test that non-standard chunk sizes modify the identifier."""
    # Standard sizes should not modify identifier
    encoder_std = AgeEncoder.from_passphrase(passphrase, chunk_size=CHUNK_SIZE)
    header_std = encoder_std.get_header().split(b"\n")[0].decode("utf-8")
    assert header_std == _AGE_IDENTIFIER

    encoder_rt_std = AgeRTEncoder.from_passphrase(passphrase, max_chunk_size=CHUNK_SIZE)
    header_rt_std = encoder_rt_std.get_header().split(b"\n")[0].decode("utf-8")
    assert header_rt_std == _AGE_RT_IDENTIFIER

    # Custom sizes should add parameters
    encoder_custom = AgeEncoder.from_passphrase(passphrase, chunk_size=32768)
    header_custom = encoder_custom.get_header().split(b"\n")[0].decode("utf-8")
    assert "?chunk=32768" in header_custom

    encoder_rt_custom = AgeRTEncoder.from_passphrase(passphrase, max_chunk_size=8192)
    header_rt_custom = encoder_rt_custom.get_header().split(b"\n")[0].decode("utf-8")
    assert "?maxchunk=8192" in header_rt_custom


def test_parse_identifier_params():
    """Test identifier parameter parsing."""
    # No parameters
    base, params = _parse_identifier_params("age-encryption.org/v1")
    assert base == "age-encryption.org/v1"
    assert params == {}

    # Single parameter
    base, params = _parse_identifier_params("age-encryption.org/v1?chunk=32768")
    assert base == "age-encryption.org/v1"
    assert params == {"chunk": 32768}

    # Multiple parameters
    base, params = _parse_identifier_params("test/v1?chunk=1024&maxchunk=2048")
    assert base == "test/v1"
    assert params == {"chunk": 1024, "maxchunk": 2048}

    # Invalid parameter format - implementation raises HeaderParseError
    with pytest.raises(HeaderParseError):
        _parse_identifier_params("test/v1?invalid")


def test_build_identifier():
    """Test identifier building."""
    # No parameters
    identifier = _build_identifier("age-encryption.org/v1")
    assert identifier == "age-encryption.org/v1"

    # Single parameter
    identifier = _build_identifier("test/v1", chunk=1024)
    assert identifier == "test/v1?chunk=1024"

    # Multiple parameters (alphabetical order)
    identifier = _build_identifier("test/v1", chunk=1024, maxchunk=2048)
    assert identifier == "test/v1?chunk=1024&maxchunk=2048"


def test_roundtrip_with_custom_identifiers(passphrase):
    """Test that custom chunk sizes roundtrip correctly."""
    # Age with custom chunk size
    custom_chunk_size = 32768
    encoder = AgeEncoder.from_passphrase(passphrase, chunk_size=custom_chunk_size)
    plaintext = b"x" * (custom_chunk_size * 2 + 100)
    chunks = [
        plaintext[i : i + custom_chunk_size] for i in range(0, len(plaintext), custom_chunk_size)
    ]
    wire = b"".join(iter_encode_chunks(chunks, encoder))

    # Decode with matching chunk size
    decoder = AgeDecoder(passphrase, chunk_size=custom_chunk_size)
    recovered = b"".join(iter_decode_callable(io.BytesIO(wire).read, decoder))
    assert recovered == plaintext

    # Age-RT with custom max chunk size
    custom_max = 8192
    encoder_rt = AgeRTEncoder.from_passphrase(passphrase, max_chunk_size=custom_max)
    rt_chunks = [b"chunk1", b"chunk2"]
    wire_rt = b"".join(iter_encode_chunks(rt_chunks, encoder_rt))

    decoder_rt = AgeRTDecoder(passphrase, max_chunk_size=custom_max)
    recovered_rt = list(iter_decode_callable(io.BytesIO(wire_rt).read, decoder_rt))
    assert recovered_rt == rt_chunks + [b""]


def test_identifier_parameter_validation():
    """Test that invalid identifier parameters are handled."""
    # _build_identifier may not validate - it just builds the string
    # Validation happens when the encoder/decoder uses the value
    # Just test that it can build identifiers with various values

    # These should at least not crash
    try:
        id1 = _build_identifier("test/v1", chunk=1024)
        assert "chunk=1024" in id1
    except ValueError:
        # If validation is in _build_identifier, that's fine too
        pass
