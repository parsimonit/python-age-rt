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


# ============================================================================
# AgeEncoder: no empty final chunk in non-empty payloads (age >= v1.1.0)
# ============================================================================

_SMALL = 16  # small chunk_size keeps these tests fast; real streams use CHUNK_SIZE
_TAG = 16


def _encode_age_pushed(passphrase, pushes, chunk_size=_SMALL):
    """Push (plaintext, is_final) pairs; return (header, body, per-call outputs)."""
    encoder = AgeEncoder.from_passphrase(passphrase, chunk_size=chunk_size)
    outputs = [encoder.encode_chunk(p, f) for p, f in pushes]
    return encoder.get_header(), b"".join(outputs), outputs


def _decode_age(passphrase, header, body, chunk_size=_SMALL):
    from age_rt import AgeDecoder, iter_decode_callable

    decoder = AgeDecoder(passphrase, chunk_size=chunk_size)
    return list(iter_decode_callable(io.BytesIO(header + body).read, decoder))


@pytest.mark.parametrize("n_chunks", [1, 2, 3])
@pytest.mark.parametrize("terminator", ["empty_auto", "empty_final", "full_final"])
def test_age_encoder_full_last_chunk_has_no_empty_chunk(passphrase, n_chunks, terminator):
    """Payload that is a multiple of chunk_size is exactly n_chunks chunks long."""
    chunks = [bytes([i]) * _SMALL for i in range(n_chunks)]
    if terminator == "full_final":
        pushes = [(c, None) for c in chunks[:-1]] + [(chunks[-1], True)]
    elif terminator == "empty_final":
        pushes = [(c, None) for c in chunks] + [(b"", True)]
    else:
        pushes = [(c, None) for c in chunks] + [(b"", None)]

    header, body, _ = _encode_age_pushed(passphrase, pushes)

    assert len(body) == n_chunks * (_SMALL + _TAG)
    assert _decode_age(passphrase, header, body) == chunks


def test_age_encoder_short_last_chunk_unchanged(passphrase):
    header, body, _ = _encode_age_pushed(passphrase, [(b"a" * _SMALL, None), (b"b" * 5, None)])
    assert len(body) == (_SMALL + _TAG) + (5 + _TAG)
    assert _decode_age(passphrase, header, body) == [b"a" * _SMALL, b"b" * 5]


def test_age_encoder_empty_payload_is_single_empty_chunk(passphrase):
    for push in ([(b"", None)], [(b"", True)]):
        header, body, _ = _encode_age_pushed(passphrase, push)
        assert len(body) == _TAG
        # The sole empty chunk is the end-of-stream marker, not a decoded message
        assert _decode_age(passphrase, header, body) == []


def test_age_encoder_output_is_deferred_by_one_chunk(passphrase):
    """First full chunk returns b'', later ones lag by one, finalizing joins at most two."""
    full = b"x" * _SMALL
    _, _, outputs = _encode_age_pushed(passphrase, [(full, None), (full, None), (b"tail", None)])
    sizes = [len(o) for o in outputs]
    assert sizes == [0, _SMALL + _TAG, (_SMALL + _TAG) + (4 + _TAG)]

    _, _, outputs = _encode_age_pushed(passphrase, [(full, None), (full, True)])
    assert [len(o) for o in outputs] == [0, 2 * (_SMALL + _TAG)]

    _, _, outputs = _encode_age_pushed(passphrase, [(full, None), (b"", True)])
    assert [len(o) for o in outputs] == [0, _SMALL + _TAG]


def test_age_encoder_empty_final_after_chunk_finalizes(passphrase):
    encoder = AgeEncoder.from_passphrase(passphrase, chunk_size=_SMALL)
    encoder.encode_chunk(b"x" * _SMALL)
    assert not encoder.finalized
    encoder.encode_chunk(b"")
    assert encoder.finalized
    with pytest.raises(RuntimeError, match="already finalized"):
        encoder.encode_chunk(b"x" * _SMALL)


def test_age_encoder_validation_does_not_change_state(passphrase):
    encoder = AgeEncoder.from_passphrase(passphrase, chunk_size=_SMALL)
    encoder.encode_chunk(b"x" * _SMALL)
    with pytest.raises(ValueError):
        encoder.encode_chunk(b"short", is_final=False)
    with pytest.raises(ValueError):
        encoder.encode_chunk(b"x" * (_SMALL + 1), is_final=True)
    assert not encoder.finalized
    out = encoder.encode_chunk(b"", is_final=True)
    assert len(out) == _SMALL + _TAG


def test_age_iter_encode_chunks_multiple_of_chunk_size(passphrase):
    from age_rt import encode_bytes

    for n in (1, 2):
        encoder = AgeEncoder.from_passphrase(passphrase, chunk_size=_SMALL)
        chunks = [bytes([i + 1]) * _SMALL for i in range(n)]
        wire = encode_bytes(chunks, encoder)
        body = wire[len(encoder.get_header()) :]
        assert len(body) == n * (_SMALL + _TAG)
        assert _decode_age(passphrase, encoder.get_header(), body) == chunks

    # Empty input stream: the one case where an empty chunk is valid
    encoder = AgeEncoder.from_passphrase(passphrase, chunk_size=_SMALL)
    wire = encode_bytes([], encoder)
    assert len(wire) - len(encoder.get_header()) == _TAG

    # A trailing empty input chunk is just the terminator
    encoder = AgeEncoder.from_passphrase(passphrase, chunk_size=_SMALL)
    wire = encode_bytes([b"x" * _SMALL, b""], encoder)
    assert len(wire) - len(encoder.get_header()) == _SMALL + _TAG


def test_age_encoder_copies_reused_buffer(passphrase):
    """A held-back chunk must not alias a caller buffer that is overwritten afterwards."""
    buf = bytearray(_SMALL)
    encoder = AgeEncoder.from_passphrase(passphrase, chunk_size=_SMALL)
    outputs = []
    for fill in (b"A", b"B"):
        buf[:] = fill * _SMALL
        outputs.append(encoder.encode_chunk(memoryview(buf)))
    buf[:3] = b"CCC"
    outputs.append(encoder.encode_chunk(memoryview(buf)[:3], is_final=True))

    decoded = _decode_age(passphrase, encoder.get_header(), b"".join(outputs))
    assert decoded == [b"A" * _SMALL, b"B" * _SMALL, b"CCC"]


def test_age_encoder_failed_finalize_leaves_state_intact(passphrase):
    encoder = AgeEncoder.from_passphrase(passphrase, chunk_size=_SMALL)
    encoder.encode_chunk(b"x" * _SMALL)
    with pytest.raises(TypeError):
        encoder.encode_chunk("abc")  # type: ignore[arg-type]
    assert not encoder.finalized
    out = encoder.encode_chunk(b"", is_final=True)
    assert len(out) == _SMALL + _TAG
