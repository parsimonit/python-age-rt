"""Tests for convenience wrapper functions: encode_file, decode_file, encode_bytes, decode_bytes."""

import io

import pytest

from age_rt import (
    AgeAutoDecoder,
    AgeDecoder,
    AgeEncoder,
    AgeRTDecoder,
    AgeRTEncoder,
    decode_bytes,
    decode_file,
    encode_bytes,
    encode_file,
)


def test_encode_file_decode_file_age_rt(passphrase, sample_chunks):
    """Test encode_file and decode_file with age-rt format."""
    # Encode to file
    output = io.BytesIO()
    encode_file(sample_chunks, output, AgeRTEncoder.from_passphrase(passphrase))

    # Decode from file
    output.seek(0)
    decoded = list(decode_file(output, AgeRTDecoder(passphrase)))

    # encode_file uses iter_encode_chunks which adds empty final chunk
    assert decoded == sample_chunks + [b""]


def test_encode_file_decode_file_age_v1(passphrase, large_chunk):
    """Test encode_file and decode_file with age v1 format."""
    chunks = [large_chunk, b"tail"]

    # Encode to file
    output = io.BytesIO()
    encode_file(chunks, output, AgeEncoder.from_passphrase(passphrase))

    # Decode from file
    output.seek(0)
    decoded = list(decode_file(output, AgeDecoder(passphrase)))

    expected = large_chunk + b"tail"
    assert b"".join(decoded) == expected


def test_encode_bytes_decode_bytes_age_rt(passphrase, sample_chunks):
    """Test encode_bytes and decode_bytes with age-rt format."""
    # Encode to bytes
    encrypted = encode_bytes(sample_chunks, AgeRTEncoder.from_passphrase(passphrase))
    assert isinstance(encrypted, bytes)

    # Decode from bytes
    decoded = list(decode_bytes(encrypted, AgeRTDecoder(passphrase)))
    assert decoded == sample_chunks + [b""]


def test_encode_bytes_decode_bytes_age_v1(passphrase):
    """Test encode_bytes and decode_bytes with age v1 format."""
    plaintext = b"Hello, world!"
    chunks = [plaintext]

    # Encode to bytes
    encrypted = encode_bytes(chunks, AgeEncoder.from_passphrase(passphrase))
    assert isinstance(encrypted, bytes)

    # Decode from bytes
    decoded = list(decode_bytes(encrypted, AgeDecoder(passphrase)))
    assert b"".join(decoded) == plaintext


def test_encode_bytes_decode_bytes_auto_decoder(passphrase, sample_chunks):
    """Test that encode_bytes output can be decoded with AgeAutoDecoder."""
    # Encode with age-rt
    encrypted_rt = encode_bytes(sample_chunks, AgeRTEncoder.from_passphrase(passphrase))
    decoded_rt = list(decode_bytes(encrypted_rt, AgeAutoDecoder(passphrase)))
    assert decoded_rt == sample_chunks + [b""]

    # Encode with age v1
    plaintext = b"test data"
    encrypted_age = encode_bytes([plaintext], AgeEncoder.from_passphrase(passphrase))
    decoded_age = list(decode_bytes(encrypted_age, AgeAutoDecoder(passphrase)))
    assert b"".join(decoded_age) == plaintext


def test_decode_file_with_real_file_operations(passphrase, sample_chunks, tmp_path):
    """Test encode_file and decode_file with actual file I/O."""
    file_path = tmp_path / "test.age"

    # Encode to real file
    with open(file_path, "wb") as f:
        encode_file(sample_chunks, f, AgeRTEncoder.from_passphrase(passphrase))

    # Decode from real file
    with open(file_path, "rb") as f:
        decoded = list(decode_file(f, AgeRTDecoder(passphrase)))

    assert decoded == sample_chunks + [b""]


def test_encode_bytes_empty_chunks(passphrase):
    """Test encode_bytes with empty chunk list."""
    # Empty input should produce header + final empty chunk
    encrypted = encode_bytes([], AgeRTEncoder.from_passphrase(passphrase))

    decoded = list(decode_bytes(encrypted, AgeRTDecoder(passphrase)))
    # Should get just the final empty chunk
    assert decoded == [b""]


def test_decode_bytes_wrong_passphrase(passphrase, passphrase_wrong, sample_chunks):
    """Test decode_bytes with wrong passphrase."""
    from age_rt import ChunkAuthenticationError

    encrypted = encode_bytes(sample_chunks, AgeRTEncoder.from_passphrase(passphrase))

    with pytest.raises(ChunkAuthenticationError):
        list(decode_bytes(encrypted, AgeRTDecoder(passphrase_wrong)))


def test_encode_file_large_chunks(passphrase, tmp_path):
    """Test encode_file with large chunks."""
    # Create 5 MB of data
    large_data = b"x" * (1024 * 1024)  # 1 MB chunks
    chunks = [large_data] * 5

    file_path = tmp_path / "large.age"

    # Encode with increased max_chunk_size
    max_chunk_size = 2 * 1024 * 1024  # 2 MB
    with open(file_path, "wb") as f:
        encode_file(
            chunks, f, AgeRTEncoder.from_passphrase(passphrase, max_chunk_size=max_chunk_size)
        )

    # Decode and verify
    with open(file_path, "rb") as f:
        decoded = list(decode_file(f, AgeRTDecoder(passphrase, max_chunk_size=max_chunk_size)))

    # Remove final empty chunk for comparison
    assert b"".join(decoded[:-1]) == b"".join(chunks)
