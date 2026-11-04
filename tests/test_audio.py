"""WAV tests: the low bits of the samples, and the honest limits of a WAV.

The fixture is a one-second 440 Hz sine whose samples carry the flag in their
low bit - which is what an audio stego challenge is. The rest of the file is
about not over-claiming: silence must produce nothing, a compressed WAV must be
refused with the conversion command, and the spectrogram must be named as not
looked at.
"""

from __future__ import annotations

import io
import math
import struct
import wave
from pathlib import Path

import pytest

from ctfc.core import audio, readers
from ctfc.core.budget import Budget
from ctfc.core.solve import solve

FIXTURE = Path(__file__).parent / "fixtures" / "audio_lsb.wav"
FLAG = "CYBN{lsb_in_the_wav}"


def make_wav(samples: list[int], channels: int = 1, width: int = 2, rate: int = 8000) -> bytes:
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as handle:
        handle.setnchannels(channels)
        handle.setsampwidth(width)
        handle.setframerate(rate)
        if width == 2:
            handle.writeframes(b"".join(struct.pack("<H", value & 0xFFFF) for value in samples))
        else:
            handle.writeframes(bytes(value & 0xFF for value in samples))
    return buffer.getvalue()


def hide(message: bytes, frames: int = 9000, channels: int = 1, channel: int = 0) -> bytes:
    """A sine wave carrying `message` in the low bit of one channel's samples."""
    bits = [(byte >> (7 - index)) & 1 for byte in message for index in range(8)]
    samples: list[int] = []
    for position in range(frames):
        value = int(8000 * math.sin(2 * math.pi * 440 * position / 8000)) & ~1
        for current in range(channels):
            carried = value
            if current == channel and position < len(bits):
                carried |= bits[position]
            samples.append(carried)
    return make_wav(samples, channels=channels)


# ---------------------------------------------------------------------------
# What it is for
# ---------------------------------------------------------------------------


def test_the_flag_in_the_low_bits_of_the_fixture():
    report = audio.analyse(FIXTURE.read_bytes())
    assert report.channels == 1
    assert report.width == 2
    assert report.rate == 8000
    assert report.candidates
    best = report.candidates[0]
    assert FLAG.encode() in best.data
    assert "low bit 0" in best.label
    assert "wave" in best.python  # the snippet uses the standard library


def test_a_message_in_one_channel_of_a_stereo_file():
    data = hide(b"CYBN{right_channel_only}\x00", channels=2, channel=1)
    report = audio.analyse(data, budget=Budget(max_attempts=400, max_seconds=20))
    labels = [candidate.label for candidate in report.candidates]
    assert any(b"CYBN{right_channel_only}" in candidate.data for candidate in report.candidates)
    assert any("channel 1" in label for label in labels)


def test_the_whole_low_byte_layout_is_tried():
    """The simplest hiding scripts write a byte per sample, not a bit."""
    message = b"CYBN{whole_low_byte}" + b"\x00" * 8
    samples = []
    for index in range(2000):
        high = int(4000 * math.sin(2 * math.pi * 440 * index / 8000)) & 0xFF00
        low = message[index] if index < len(message) else 0
        samples.append(high | low)
    report = audio.analyse(make_wav(samples), budget=Budget(max_attempts=400, max_seconds=20))
    assert any("low byte" in candidate.label for candidate in report.candidates)
    assert any(b"CYBN{whole_low_byte}" in candidate.data for candidate in report.candidates)


def test_the_metadata_chunks_are_read():
    data = bytearray(FIXTURE.read_bytes())
    info = b"INFO" + b"ICMT" + struct.pack("<I", 24) + b"CYBN{in_a_list_chunk}\x00\x00\x00"
    chunk = b"LIST" + struct.pack("<I", len(info)) + info
    data += chunk
    data[4:8] = (len(data) - 8).to_bytes(4, "little")
    report = audio.analyse(bytes(data))
    assert ("ICMT", "CYBN{in_a_list_chunk}") in report.texts


def test_data_appended_after_the_riff_container_is_reported():
    data = FIXTURE.read_bytes() + b"PK\x03\x04" + bytes(400)
    report = audio.analyse(data)
    assert any("after the end of the RIFF container" in note for note in report.notes)


# ---------------------------------------------------------------------------
# What it refuses to claim
# ---------------------------------------------------------------------------


def test_silence_produces_nothing():
    report = audio.analyse(make_wav([0] * 4000))
    assert report.candidates == []
    assert any("nothing readable in the low bits" in note for note in report.notes)


def test_the_spectrogram_is_named_as_not_looked_at():
    report = audio.analyse(FIXTURE.read_bytes())
    note = " ".join(report.notes)
    assert "spectrogram" in note
    assert "Audacity" in note or "Sonic Visualiser" in note
    assert "numpy" in note  # and why it is not done here


def test_a_compressed_wav_is_refused_with_the_conversion_command():
    # A WAV header claiming format 2 (ADPCM): `wave` refuses it, and so do we.
    data = bytearray(make_wav([100] * 100))
    data[20] = 2
    with pytest.raises(audio.AudioError, match="ffmpeg"):
        audio.analyse(bytes(data))


def test_something_that_is_not_a_wav():
    with pytest.raises(audio.AudioError, match="RIFF/WAVE"):
        audio.load(b"ID3\x04ancient mp3 bytes")


def test_a_truncated_data_chunk_is_reported_and_still_read():
    data = bytearray(hide(b"CYBN{cut_short}\x00"))
    cut = bytes(data[: len(data) - 4000])
    report = audio.analyse(cut)
    assert report.candidates or report.notes


# ---------------------------------------------------------------------------
# Where a user meets it
# ---------------------------------------------------------------------------


def test_the_registry_claims_a_wav_and_hands_the_bits_over():
    data = FIXTURE.read_bytes()
    assert readers.sniff(data) == "wav"
    opened = readers.open_with("wav", data, None, "track.wav")
    assert "8000 Hz" in opened.detail
    assert any(FLAG.encode() in child.data for child in opened.children)


def test_solve_finds_a_flag_hidden_in_audio():
    assert FLAG in [flag.text for flag in solve(FIXTURE.read_bytes(), "track.wav").flags]


def test_the_web_tab_renders_it():
    from ctfc.web import formats

    answer = formats.analyse(FIXTURE.read_bytes())
    assert answer["reader"] == "wav"
    assert FLAG in answer["flags"]
