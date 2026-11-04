"""WAV: a message in the low bits of the samples, and what a WAV cannot tell you.

The audio version of the image stego challenge. A WAV holds raw PCM samples -
no compression, nothing lossy - so the low bit of each sample can be rewritten
without a listener noticing, exactly as in a PNG's pixels. The standard
library's `wave` module reads the container, which leaves only the bit
arithmetic.

What is tried, in order of how often it appears:

- the **low bit of every sample**, bytes rebuilt MSB-first and LSB-first;
- the same **per channel** (a stereo file often carries the message in one
  channel only), and both channels interleaved;
- **bit planes 1 and 2** as well as 0, for a tool that was sloppy about it;
- for 16-bit audio, the **low byte in full** rather than one bit of it, which
  is what the simplest "hide bytes in audio" scripts actually do.

Each result is scored by `scoring.py` like any other candidate, so a run of
silence (whose low bits are a constant) scores as nothing and is dropped.

**What this module refuses to pretend.** A large family of audio challenges is
a *spectrogram* puzzle: the flag is drawn in the frequency domain and only a
viewer shows it. That needs an FFT, which needs numpy, which is not an allowed
dependency here - and a hand-rolled DFT over a minute of audio in pure Python
is not a tool, it is a wait. So the report says plainly that a spectrogram was
not looked at and names Audacity and Sonic Visualiser, and the same goes for
DTMF tones and Morse whistled in a sine wave. Pointing at the right tool beats
a half-measure that would be trusted.
"""

from __future__ import annotations

import wave
from dataclasses import dataclass, field

from ctfc.core.budget import Budget
from ctfc.core.errors import FormatError
from ctfc.core.flags import FlagSet
from ctfc.core.scoring import score
from ctfc.core.types import Candidate

# How many bytes one combination produces before it is scored. A WAV is big and
# there are a dozen combinations, so the probe is short on purpose.
PROBE_BYTES = 4096
# Below this a result is noise, not a message.
KEEP_SCORE = 0.45
BIT_PLANES = (0, 1, 2)


class AudioError(FormatError):
    """The data is not a WAV this module can read."""


@dataclass
class Audio:
    """One decoded WAV: the samples, as integers per channel."""

    channels: int
    width: int  # bytes per sample: 1 (unsigned), 2 or 3
    rate: int
    frames: int
    raw: bytes = field(repr=False, default=b"")
    notes: list[str] = field(default_factory=list)

    @property
    def seconds(self) -> float:
        return self.frames / self.rate if self.rate else 0.0

    def sample(self, frame: int, channel: int) -> int:
        """The sample's integer value - only its low bits are ever used here."""
        at = (frame * self.channels + channel) * self.width
        return int.from_bytes(self.raw[at : at + self.width], "little", signed=False)


@dataclass
class AudioReport:
    """What the file is, what its low bits spell, and what was not looked at."""

    channels: int = 0
    width: int = 0
    rate: int = 0
    frames: int = 0
    seconds: float = 0.0
    texts: list[tuple[str, str]] = field(default_factory=list)  # LIST/INFO chunks
    candidates: list[Candidate] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "channels": self.channels,
            "width": self.width,
            "rate": self.rate,
            "frames": self.frames,
            "seconds": round(self.seconds, 3),
            "texts": [{"keyword": key, "text": value} for key, value in self.texts],
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "notes": list(self.notes),
        }


def looks_like_wav(data: bytes) -> bool:
    return data[:4] == b"RIFF" and data[8:12] == b"WAVE"


def load(data: bytes) -> Audio:
    """Read the PCM samples with the standard library."""
    import io

    if not looks_like_wav(data):
        raise AudioError("not a WAV: the RIFF/WAVE header is missing")
    try:
        with wave.open(io.BytesIO(data), "rb") as handle:
            channels = handle.getnchannels()
            width = handle.getsampwidth()
            rate = handle.getframerate()
            frames = handle.getnframes()
            raw = handle.readframes(frames)
    except (wave.Error, EOFError, ValueError) as exc:
        raise AudioError(
            f"this WAV cannot be read ({exc}). Compressed WAVs (ADPCM, mu-law) and "
            "other formats (MP3, FLAC, OGG) hold no raw samples to hide bits in: "
            "convert it first with `ffmpeg -i in.ext out.wav`"
        ) from exc
    audio = Audio(channels=channels, width=width, rate=rate, frames=frames, raw=raw)
    if len(raw) < frames * channels * width:
        audio.notes.append(
            f"the data chunk is short: {len(raw)} bytes for {frames} declared frames "
            "(truncated file - what is there is still read)"
        )
    return audio


# ---------------------------------------------------------------------------
# The chunks around the samples
# ---------------------------------------------------------------------------


def riff_chunks(data: bytes):
    """Yield (id, payload) for each RIFF chunk, which is where metadata hides."""
    offset = 12
    while offset + 8 <= len(data):
        name = data[offset : offset + 4]
        size = int.from_bytes(data[offset + 4 : offset + 8], "little")
        payload = data[offset + 8 : offset + 8 + size]
        yield name.decode("latin-1"), payload
        offset += 8 + size + (size & 1)  # chunks are word-aligned


def metadata(data: bytes) -> list[tuple[str, str]]:
    """The LIST/INFO strings, and any other chunk that is readable text."""
    found: list[tuple[str, str]] = []
    for name, payload in riff_chunks(data):
        if name == "LIST" and payload[:4] == b"INFO":
            position = 4
            while position + 8 <= len(payload):
                tag = payload[position : position + 4].decode("latin-1")
                size = int.from_bytes(payload[position + 4 : position + 8], "little")
                value = payload[position + 8 : position + 8 + size]
                found.append((tag, value.decode("utf-8", "replace").strip("\x00")))
                position += 8 + size + (size & 1)
        elif name not in ("fmt ", "data", "fact"):
            text = payload[:400]
            printable = sum(1 for byte in text if 32 <= byte < 127 or byte in (9, 10, 13))
            if text and printable / len(text) > 0.8:
                found.append((name, text.decode("utf-8", "replace").strip("\x00")))
    return found


# ---------------------------------------------------------------------------
# The low bits
# ---------------------------------------------------------------------------


def extract_bits(
    audio: Audio,
    channels: tuple[int, ...],
    plane: int,
    msb_first: bool,
    limit: int = PROBE_BYTES,
) -> bytes:
    """One bit per sample, rebuilt into bytes, for one combination."""
    out = bytearray()
    accumulator = 0
    count = 0
    for frame in range(audio.frames):
        for channel in channels:
            bit = (audio.sample(frame, channel) >> plane) & 1
            if msb_first:
                accumulator = (accumulator << 1) | bit
            else:
                accumulator |= bit << count
            count += 1
            if count == 8:
                out.append(accumulator)
                accumulator = 0
                count = 0
                if len(out) >= limit:
                    return bytes(out)
    return bytes(out)


def extract_low_bytes(audio: Audio, channels: tuple[int, ...], limit: int = PROBE_BYTES) -> bytes:
    """The whole low byte of each sample - what the simplest scripts write."""
    out = bytearray()
    for frame in range(audio.frames):
        for channel in channels:
            at = (frame * audio.channels + channel) * audio.width
            out.append(audio.raw[at])
            if len(out) >= limit:
                return bytes(out)
    return bytes(out)


def _snippet(channels: tuple[int, ...], plane: int, msb_first: bool, low_byte: bool) -> str:
    """A standalone script that redoes this extraction."""
    picked = ", ".join(str(index) for index in channels)
    if low_byte:
        return (
            "import wave\n"
            "with wave.open('audio.wav', 'rb') as f:\n"
            "    channels, width = f.getnchannels(), f.getsampwidth()\n"
            "    raw = f.readframes(f.getnframes())\n"
            f"picked = [{picked}]\n"
            "out = bytearray()\n"
            "for frame in range(len(raw) // (channels * width)):\n"
            "    for channel in picked:\n"
            "        out.append(raw[(frame * channels + channel) * width])\n"
            "print(bytes(out)[:200])\n"
        )
    order = "(acc << 1) | bit" if msb_first else "acc | (bit << n)"
    return (
        "import wave\n"
        "with wave.open('audio.wav', 'rb') as f:\n"
        "    channels, width = f.getnchannels(), f.getsampwidth()\n"
        "    raw = f.readframes(f.getnframes())\n"
        f"picked = [{picked}]\n"
        "out, acc, n = bytearray(), 0, 0\n"
        "for frame in range(len(raw) // (channels * width)):\n"
        "    for channel in picked:\n"
        "        at = (frame * channels + channel) * width\n"
        "        sample = int.from_bytes(raw[at:at + width], 'little')\n"
        f"        bit = (sample >> {plane}) & 1\n"
        f"        acc = {order}\n"
        "        n += 1\n"
        "        if n == 8:\n"
        "            out.append(acc); acc, n = 0, 0\n"
        "print(bytes(out)[:200])\n"
    )


def lsb_candidates(
    audio: Audio, flagset: FlagSet | None = None, budget: Budget | None = None, top_n: int = 5
) -> list[Candidate]:
    """Try the plausible low-bit layouts and keep what reads as something."""
    budget = budget or Budget(max_attempts=200, max_seconds=15)
    orders: list[tuple[int, ...]] = [tuple(range(audio.channels))]
    if audio.channels > 1:
        orders += [(index,) for index in range(audio.channels)]

    results: list[Candidate] = []
    for channels in orders:
        name = "all channels" if len(channels) == audio.channels else f"channel {channels[0]}"
        for plane in BIT_PLANES:
            for msb_first in (True, False):
                if not budget.spend():
                    break
                probe = extract_bits(audio, channels, plane, msb_first)
                results += _keep(
                    probe,
                    f"low bit {plane} of each sample, {name}, "
                    + ("MSB first" if msb_first else "LSB first"),
                    {"plane": plane, "channels": name, "bit_order": "msb" if msb_first else "lsb"},
                    _snippet(channels, plane, msb_first, low_byte=False),
                    flagset,
                )
        if audio.width > 1 and budget.spend():
            probe = extract_low_bytes(audio, channels)
            results += _keep(
                probe,
                f"the whole low byte of each sample, {name}",
                {"channels": name, "layout": "low byte"},
                _snippet(channels, 0, True, low_byte=True),
                flagset,
            )

    results.sort(key=lambda candidate: -candidate.score)
    unique: list[Candidate] = []
    seen: set[bytes] = set()
    for candidate in results:
        if candidate.data[:64] in seen:
            continue
        seen.add(candidate.data[:64])
        unique.append(candidate)
    return unique[:top_n]


def _keep(
    probe: bytes, label: str, params: dict, snippet: str, flagset: FlagSet | None
) -> list[Candidate]:
    """Score one probe and turn it into a candidate, or into nothing."""
    if len(probe) < 8 or len(set(probe[:64])) < 4:
        # Silence, or a constant low bit: printable-looking without being a
        # message. The same guard the image side needed.
        return []
    value, reasons = score(probe, flagset)
    if value < KEEP_SCORE:
        return []
    return [
        Candidate(
            label=label,
            data=probe,
            score=value,
            reasons=reasons,
            params=params,
            python=snippet,
        )
    ]


def analyse(
    data: bytes, flagset: FlagSet | None = None, budget: Budget | None = None, top_n: int = 5
) -> AudioReport:
    """Read the WAV, its metadata chunks, and try the low-bit layouts."""
    audio = load(data)
    report = AudioReport(
        channels=audio.channels,
        width=audio.width,
        rate=audio.rate,
        frames=audio.frames,
        seconds=audio.seconds,
        texts=metadata(data),
        notes=list(audio.notes),
    )
    for keyword, text in report.texts:
        if text.strip():
            report.notes.append(f"{keyword} chunk: {text[:200]}")

    declared = int.from_bytes(data[4:8], "little") + 8
    if len(data) > declared + 8:
        report.notes.append(
            f"{len(data) - declared} byte(s) sit after the end of the RIFF container "
            f"(offset {declared}): run `ctfc repair` on the file, that is a whole file "
            "hidden behind the audio often enough"
        )

    report.candidates = lsb_candidates(audio, flagset, budget, top_n)
    if not report.candidates:
        report.notes.append(
            "nothing readable in the low bits (bits 0-2, each channel, both bit orders, "
            "and the whole low byte were tried)"
        )
    report.notes.append(
        "not looked at here: the spectrogram, DTMF tones, and a Morse whistle - all three "
        "live in the frequency domain, which needs an FFT (numpy is not a dependency of "
        "ctfc). Open the file in Audacity (Spectrogram view) or Sonic Visualiser: if the "
        "flag is drawn in the spectrum, it is visible in seconds there"
    )
    return report
