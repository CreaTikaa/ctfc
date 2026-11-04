"""EXIF: what a photograph says about itself.

The flag is in the comment field, the answer is the GPS point, or the question
is "which camera took both of these?" - and the usual advice is "install
exiftool". It is about a hundred and fifty lines of TIFF parsing, with no
dependency, so here it is.

The structure, once: EXIF is a **TIFF file embedded in a JPEG**. A JPEG is a
chain of markers; the one called APP1 (`FF E1`) holds `Exif\\0\\0` followed by a
complete little- or big-endian TIFF header. That header points at the first
**IFD** (image file directory), which is a count followed by 12-byte entries:

    tag (2) | type (2) | count (4) | value or offset (4)

A value longer than four bytes does not fit in the entry, so the last field is
then an offset from the start of the TIFF header. Two of the tags are pointers
to further IFDs - the EXIF sub-IFD (0x8769) and the GPS IFD (0x8825) - which is
where everything interesting actually lives: the date the shutter fired, the
lens, the serial number, the user comment, the coordinates.

GPS is stored as three rationals (degrees, minutes, seconds) plus a reference
letter, and is converted here to the decimal pair every map wants.

Three formats reach this module: a JPEG (through its APP1 marker), a raw TIFF
(the same bytes without the JPEG around them) and a PNG (whose `eXIf` chunk is,
again, the same TIFF). Nothing is executed and no image is decoded - this reads
a table of numbers and strings.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ctfc.core.errors import FormatError

JPEG_MAGIC = b"\xff\xd8\xff"
TIFF_LITTLE = b"II\x2a\x00"
TIFF_BIG = b"MM\x00\x2a"
EXIF_HEADER = b"Exif\x00\x00"

# How many bytes one TIFF value takes, per type code.
TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}
# A damaged or hostile file must not make this walk forever.
MAX_ENTRIES = 512
MAX_IFDS = 16
MAX_VALUE = 64 * 1024

# The tags worth naming. Everything else is reported by number, because a
# challenge sometimes hides its answer in an obscure one.
TAGS = {
    0x010E: "ImageDescription",
    0x010F: "Make",
    0x0110: "Model",
    0x0112: "Orientation",
    0x0131: "Software",
    0x0132: "DateTime",
    0x013B: "Artist",
    0x8298: "Copyright",
    0x8769: "ExifIFD",
    0x8825: "GPSIFD",
    0x829A: "ExposureTime",
    0x829D: "FNumber",
    0x8827: "ISO",
    0x9003: "DateTimeOriginal",
    0x9004: "DateTimeDigitized",
    0x9286: "UserComment",
    0xA002: "PixelXDimension",
    0xA003: "PixelYDimension",
    0xA420: "ImageUniqueID",
    0xA430: "CameraOwnerName",
    0xA431: "BodySerialNumber",
    0xA432: "LensSpecification",
    0xA433: "LensMake",
    0xA434: "LensModel",
    0xA435: "LensSerialNumber",
    0x927C: "MakerNote",
}
GPS_TAGS = {
    0x0000: "GPSVersionID",
    0x0001: "GPSLatitudeRef",
    0x0002: "GPSLatitude",
    0x0003: "GPSLongitudeRef",
    0x0004: "GPSLongitude",
    0x0005: "GPSAltitudeRef",
    0x0006: "GPSAltitude",
    0x0007: "GPSTimeStamp",
    0x0012: "GPSMapDatum",
    0x001D: "GPSDateStamp",
}
# The tags whose value is free text, and so the ones a flag hides in.
TEXT_TAGS = {
    "ImageDescription",
    "UserComment",
    "Artist",
    "Copyright",
    "Software",
    "Make",
    "Model",
    "CameraOwnerName",
    "BodySerialNumber",
    "LensModel",
    "ImageUniqueID",
    "GPSMapDatum",
}


class ExifError(FormatError):
    """There is no EXIF block in this data."""


@dataclass
class Tag:
    """One EXIF entry, already turned into something printable."""

    ifd: str  # "IFD0", "EXIF", "GPS", "IFD1" (the thumbnail)
    tag: int
    name: str  # the name, or "tag 0x9999" when unknown
    value: str

    @property
    def is_text(self) -> bool:
        return self.name in TEXT_TAGS


@dataclass
class ExifReport:
    """Everything the metadata says."""

    container: str = ""  # "jpeg" | "tiff" | "png"
    byte_order: str = ""  # "little" | "big"
    tags: list[Tag] = field(default_factory=list)
    latitude: float | None = None
    longitude: float | None = None
    altitude: str = ""
    thumbnail: bytes = field(repr=False, default=b"")
    notes: list[str] = field(default_factory=list)

    def get(self, name: str) -> str:
        for tag in self.tags:
            if tag.name == name:
                return tag.value
        return ""

    @property
    def coordinates(self) -> str:
        if self.latitude is None or self.longitude is None:
            return ""
        return f"{self.latitude:.6f}, {self.longitude:.6f}"

    @property
    def map_url(self) -> str:
        """A link the user can paste. Opening it is their choice, not ours."""
        if not self.coordinates:
            return ""
        return f"https://www.openstreetmap.org/?mlat={self.latitude:.6f}&mlon={self.longitude:.6f}"

    def to_dict(self) -> dict:
        return {
            "container": self.container,
            "byte_order": self.byte_order,
            "tags": [
                {"ifd": tag.ifd, "tag": f"0x{tag.tag:04x}", "name": tag.name, "value": tag.value}
                for tag in self.tags
            ],
            "coordinates": self.coordinates,
            "altitude": self.altitude,
            "map_url": self.map_url,
            "thumbnail": len(self.thumbnail),
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Finding the TIFF block
# ---------------------------------------------------------------------------


def jpeg_segments(data: bytes):
    """Yield (marker, payload) for each JPEG segment, in order.

    A JPEG is `FF D8` then segments: `FF <marker> <length:2> <payload>`. The
    markers without a length (`D0`-`D9`, `01`) are skipped, and the walk stops
    at the start of the compressed scan, where there is nothing left to read.
    """
    offset = 2
    while offset + 4 <= len(data):
        if data[offset] != 0xFF:
            offset += 1
            continue
        marker = data[offset + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            offset += 2
            continue
        if marker == 0xDA:  # start of scan: the rest is entropy-coded data
            return
        length = int.from_bytes(data[offset + 2 : offset + 4], "big")
        if length < 2 or offset + 2 + length > len(data):
            return
        yield marker, data[offset + 4 : offset + 2 + length]
        offset += 2 + length


def find_tiff(data: bytes) -> tuple[bytes, str]:
    """The embedded TIFF block and the container it came from."""
    if data[:4] in (TIFF_LITTLE, TIFF_BIG):
        return data, "tiff"
    if data[:3] == JPEG_MAGIC:
        for marker, payload in jpeg_segments(data):
            if marker == 0xE1 and payload[: len(EXIF_HEADER)] == EXIF_HEADER:
                return payload[len(EXIF_HEADER) :], "jpeg"
        raise ExifError(
            "this JPEG has no APP1/Exif segment: it carries no EXIF "
            "(a comment may still be in a COM segment - `ctfc detect` shows the strings)"
        )
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        from ctfc.core.pngfix import read_chunks

        for chunk in read_chunks(data):
            if chunk.kind == "eXIf":
                return chunk.payload, "png"
        raise ExifError("this PNG has no eXIf chunk")
    raise ExifError("no EXIF here: the data is not a JPEG, a TIFF or a PNG")


# ---------------------------------------------------------------------------
# Reading the IFDs
# ---------------------------------------------------------------------------


def _rational(data: bytes, order: str) -> float | None:
    numerator = int.from_bytes(data[0:4], order)
    denominator = int.from_bytes(data[4:8], order)
    return numerator / denominator if denominator else None


def _value_of(tiff: bytes, order: str, kind: int, count: int, raw: bytes) -> str:
    """One entry's value, as text. `raw` is the 4-byte value-or-offset field."""
    size = TYPE_SIZE.get(kind, 1) * count
    if size > 4:
        offset = int.from_bytes(raw, order)
        if offset + size > len(tiff) or size > MAX_VALUE:
            return "<points outside the file>"
        payload = tiff[offset : offset + size]
    else:
        payload = raw[:size]

    if kind == 2:  # ASCII, NUL-terminated
        return payload.split(b"\x00")[0].decode("utf-8", "replace")
    if kind == 7:  # undefined bytes: UserComment hides its charset in the first 8
        text = payload[8:] if payload[:5] in (b"ASCII", b"UNICO") else payload
        printable = sum(1 for byte in text if 32 <= byte < 127 or byte in (9, 10, 13))
        if text and printable / len(text) > 0.7:
            return text.decode("utf-8", "replace").strip("\x00 ")
        return payload[:32].hex()
    if kind in (5, 10):  # rationals
        parts = []
        for index in range(count):
            chunk = payload[index * 8 : index * 8 + 8]
            value = _rational(chunk, order)
            parts.append("?" if value is None else f"{value:g}")
        return " ".join(parts)
    if kind in (1, 3, 4, 6, 8, 9):
        width = TYPE_SIZE[kind]
        numbers = [
            int.from_bytes(payload[index * width : (index + 1) * width], order)
            for index in range(min(count, 16))
        ]
        return " ".join(str(number) for number in numbers)
    return payload[:32].hex()


def _read_ifd(tiff: bytes, order: str, offset: int, name: str) -> tuple[list[Tag], int, dict]:
    """One IFD: its tags, the offset of the next IFD, and the pointers it holds."""
    tags: list[Tag] = []
    pointers: dict[str, int] = {}
    if offset + 2 > len(tiff):
        return tags, 0, pointers
    count = int.from_bytes(tiff[offset : offset + 2], order)
    count = min(count, MAX_ENTRIES)
    names = GPS_TAGS if name == "GPS" else TAGS
    for index in range(count):
        at = offset + 2 + index * 12
        if at + 12 > len(tiff):
            break
        tag = int.from_bytes(tiff[at : at + 2], order)
        kind = int.from_bytes(tiff[at + 2 : at + 4], order)
        length = int.from_bytes(tiff[at + 4 : at + 8], order)
        raw = tiff[at + 8 : at + 12]
        label = names.get(tag) or TAGS.get(tag) or f"tag 0x{tag:04x}"
        if label in ("ExifIFD", "GPSIFD"):
            pointers[label] = int.from_bytes(raw, order)
            continue
        tags.append(Tag(name, tag, label, _value_of(tiff, order, kind, length, raw)))
    next_at = offset + 2 + count * 12
    following = (
        int.from_bytes(tiff[next_at : next_at + 4], order) if next_at + 4 <= len(tiff) else 0
    )
    return tags, following, pointers


def _gps_decimal(values: str, reference: str) -> float | None:
    """Three rationals plus N/S/E/W, as one signed decimal degree."""
    parts = values.split()
    if len(parts) < 3:
        return None
    try:
        degrees, minutes, seconds = (float(part) for part in parts[:3])
    except ValueError:
        return None
    decimal = degrees + minutes / 60 + seconds / 3600
    return -decimal if reference.upper() in ("S", "W") else decimal


def read(data: bytes) -> ExifReport:
    """Read every IFD of the embedded TIFF and report what it says."""
    tiff, container = find_tiff(data)
    if tiff[:2] == b"II":
        order = "little"
    elif tiff[:2] == b"MM":
        order = "big"
    else:
        raise ExifError("the EXIF block does not start with a TIFF byte-order mark")
    report = ExifReport(container=container, byte_order=order)

    first = int.from_bytes(tiff[4:8], order)
    offset, name, seen = first, "IFD0", 0
    pending: list[tuple[int, str]] = []
    while offset and seen < MAX_IFDS:
        seen += 1
        tags, following, pointers = _read_ifd(tiff, order, offset, name)
        report.tags += tags
        for label, target in pointers.items():
            pending.append((target, "EXIF" if label == "ExifIFD" else "GPS"))
        if name == "IFD0" and following:
            pending.append((following, "IFD1"))  # the thumbnail's directory
        if pending:
            offset, name = pending.pop(0)
        else:
            break

    latitude_ref = report.get("GPSLatitudeRef")
    longitude_ref = report.get("GPSLongitudeRef")
    report.latitude = _gps_decimal(report.get("GPSLatitude"), latitude_ref)
    report.longitude = _gps_decimal(report.get("GPSLongitude"), longitude_ref)
    altitude = report.get("GPSAltitude")
    if altitude:
        above = report.get("GPSAltitudeRef") != "1"
        report.altitude = f"{altitude} m {'above' if above else 'below'} sea level"

    if report.coordinates:
        report.notes.append(
            f"GPS: {report.coordinates} - the photograph says where it was taken. "
            f"Map: {report.map_url} (opening it is a request to a third party)"
        )
    for tag in report.tags:
        if tag.is_text and tag.value.strip():
            report.notes.append(f"{tag.name}: {tag.value[:200]}")
    if not report.tags:
        report.notes.append("the EXIF block holds no readable entry")
    return report


def text_values(report: ExifReport) -> bytes:
    """Every string in the metadata, joined - for the flag search to run over."""
    return "\n".join(f"{tag.name}: {tag.value}" for tag in report.tags).encode()
