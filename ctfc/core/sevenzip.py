"""Read a .7z archive: its file list, its codecs, and how it is encrypted.

7z is the most interesting of the common archives, because its header is not a
plain list of entries - it is a little description of a *dataflow*:

- the archive's bytes are grouped into **pack streams** (the physical blobs);
- a **folder** (7z's unfortunate word for "compression unit") is a chain of
  **coders** - LZMA, BCJ, AES - wired together by bind pairs, with one output
  at the end;
- a folder's output is then cut into **substreams**, one per file. That is why
  7z compresses better and why extracting one file out of a solid archive has
  to decompress everything before it.

Two consequences matter in a CTF:

1. **the header itself is usually compressed** (`kEncodedHeader`). The file list
   is LZMA inside the file, so `strings` shows nothing. It is decoded here.
2. **the header can be *encrypted***. `7z a -p` encrypts the files and leaves the
   names readable; `7z a -mhe=on -p` encrypts the header too, and then even the
   listing needs the password - that is the difference between "I know what I am
   missing" and "I know nothing", and it is worth saying out loud.

Where the codecs are ones Python already has (stored, LZMA, LZMA2, deflate,
bzip2), the files are extracted here too, offline and with no 7z installed.
AES-encrypted entries are reported with the exact iteration count, which is what
`7z2john` puts in its hash.
"""

from __future__ import annotations

import bz2
import lzma
import zlib
from dataclasses import dataclass, field

from ctfc.core.errors import FormatError

SIGNATURE = b"7z\xbc\xaf\x27\x1c"

# Property ids of the header (7zFormat.txt).
kEnd = 0x00
kHeader = 0x01
kArchiveProperties = 0x02
kAdditionalStreamsInfo = 0x03
kMainStreamsInfo = 0x04
kFilesInfo = 0x05
kPackInfo = 0x06
kUnPackInfo = 0x07
kSubStreamsInfo = 0x08
kSize = 0x09
kCRC = 0x0A
kFolder = 0x0B
kCodersUnPackSize = 0x0C
kNumUnPackStream = 0x0D
kEmptyStream = 0x0E
kEmptyFile = 0x0F
kAnti = 0x10
kName = 0x11
kCTime = 0x12
kATime = 0x13
kMTime = 0x14
kWinAttributes = 0x15
kEncodedHeader = 0x17
kDummy = 0x19

# Codec ids, as big-endian numbers. 7z stores them as 1 to 4 bytes.
CODECS = {
    0x00: "stored",
    0x21: "LZMA2",
    0x030101: "LZMA",
    0x03030103: "BCJ (x86 filter)",
    0x0303011B: "BCJ2 (x86 filter)",
    0x03030205: "PPC filter",
    0x03030301: "IA64 filter",
    0x03030501: "ARM filter",
    0x03030701: "SPARC filter",
    0x030401: "PPMd",
    0x040108: "deflate",
    0x040109: "deflate64",
    0x040202: "bzip2",
    0x06F10701: "AES-256 + SHA-256",
}
AES_CODEC = 0x06F10701
MAX_FILES = 200_000
MAX_FOLDERS = 100_000
DECODE_LIMIT = 256 << 20


class SevenZipError(FormatError):
    """The data is not a .7z we can read."""


# ---------------------------------------------------------------------------
# The byte-level reader: 7z numbers and bit vectors
# ---------------------------------------------------------------------------


class Reader:
    """A cursor over the header bytes, with 7z's own number encoding."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    def byte(self) -> int:
        if self.position >= len(self.data):
            raise SevenZipError("the header ends in the middle of a field")
        value = self.data[self.position]
        self.position += 1
        return value

    def take(self, count: int) -> bytes:
        if count < 0 or self.position + count > len(self.data):
            raise SevenZipError(f"the header is {len(self.data)} bytes: {count} more do not fit")
        chunk = self.data[self.position : self.position + count]
        self.position += count
        return chunk

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "little")

    def u64(self) -> int:
        return int.from_bytes(self.take(8), "little")

    def number(self) -> int:
        """7z's variable-length number: a mask byte, then that many bytes.

        The first byte's high bits say how many extra bytes follow; the low bits
        are the top of the value. It is the same idea as a UTF-8 length byte.
        """
        first = self.byte()
        mask = 0x80
        value = 0
        for index in range(8):
            if not first & mask:
                value |= (first & (mask - 1)) << (8 * index)
                return value
            value |= self.byte() << (8 * index)
            mask >>= 1
        return value

    def bit_vector(self, count: int) -> list[bool]:
        """`count` bits, most significant bit of each byte first."""
        bits: list[bool] = []
        current = 0
        mask = 0
        for _ in range(count):
            if mask == 0:
                current = self.byte()
                mask = 0x80
            bits.append(bool(current & mask))
            mask >>= 1
        return bits

    def defined_vector(self, count: int) -> list[bool]:
        """ "All are defined" byte, or a bit vector when it is zero."""
        if self.byte():
            return [True] * count
        return self.bit_vector(count)

    def skip_property(self, size: int) -> None:
        self.take(size)


# ---------------------------------------------------------------------------
# The header's structures
# ---------------------------------------------------------------------------


@dataclass
class Coder:
    """One step of a folder's dataflow."""

    codec: int
    properties: bytes = b""
    in_streams: int = 1
    out_streams: int = 1

    @property
    def name(self) -> str:
        return CODECS.get(self.codec, f"codec {self.codec:#x}")


@dataclass
class Folder:
    """A compression unit: coders, how they are wired, and its output size."""

    coders: list[Coder] = field(default_factory=list)
    bind_pairs: list[tuple[int, int]] = field(default_factory=list)
    packed_indices: list[int] = field(default_factory=list)
    unpacked_sizes: list[int] = field(default_factory=list)  # one per coder output
    crc: int | None = None
    num_unpack_substreams: int = 1

    @property
    def encrypted(self) -> bool:
        return any(coder.codec == AES_CODEC for coder in self.coders)

    @property
    def method(self) -> str:
        """Every coder, in the order they are declared."""
        return " + ".join(coder.name for coder in self.coders)

    @property
    def output_size(self) -> int:
        """The size of the folder's final output.

        The final output is the one no bind pair consumes. With a single coder it
        is simply its only output.
        """
        consumed = {out for _in, out in self.bind_pairs}
        for index in range(len(self.unpacked_sizes)):
            if index not in consumed:
                return self.unpacked_sizes[index]
        return self.unpacked_sizes[-1] if self.unpacked_sizes else 0

    @property
    def aes_properties(self) -> bytes:
        for coder in self.coders:
            if coder.codec == AES_CODEC:
                return coder.properties
        return b""


@dataclass
class StreamsInfo:
    """Where the compressed bytes are and what has to be done to them."""

    pack_position: int = 0
    pack_sizes: list[int] = field(default_factory=list)
    folders: list[Folder] = field(default_factory=list)
    substream_sizes: list[list[int]] = field(default_factory=list)  # per folder
    substream_crcs: list[int | None] = field(default_factory=list)  # flat, in order


@dataclass
class SevenZipEntry:
    """One file or directory in the archive."""

    name: str
    size: int = 0
    directory: bool = False
    empty: bool = False
    encrypted: bool = False
    method: str = ""
    crc: int | None = None
    folder: int | None = None
    attributes: int = 0
    data: bytes | None = None  # filled by extract() when the codec is decodable


@dataclass
class SevenZipArchive:
    """A parsed archive."""

    entries: list[SevenZipEntry] = field(default_factory=list)
    header_encrypted: bool = False
    streams: StreamsInfo | None = None
    kdf_iterations: int = 0
    salt: bytes = b""
    iv: bytes = b""
    notes: list[str] = field(default_factory=list)

    @property
    def any_encrypted(self) -> bool:
        return self.header_encrypted or any(entry.encrypted for entry in self.entries)

    @property
    def methods(self) -> list[str]:
        if not self.streams:
            return []
        seen: list[str] = []
        for folder in self.streams.folders:
            if folder.method not in seen:
                seen.append(folder.method)
        return seen


def is_sevenzip(data: bytes) -> bool:
    return data[:6] == SIGNATURE


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


def _read_folder(reader: Reader) -> Folder:
    """One folder: its coders and the bind pairs wiring them together."""
    folder = Folder()
    count = reader.number()
    if count == 0 or count > 32:
        raise SevenZipError(f"a folder with {count} coders is not a real folder")
    total_in = 0
    total_out = 0
    for _ in range(count):
        flags = reader.byte()
        id_size = flags & 0x0F
        codec = int.from_bytes(reader.take(id_size), "big")
        coder = Coder(codec=codec)
        if flags & 0x10:  # a complex coder states its own stream counts
            coder.in_streams = reader.number()
            coder.out_streams = reader.number()
        if flags & 0x20:
            coder.properties = reader.take(reader.number())
        if flags & 0x80:
            raise SevenZipError("alternative coder methods are not supported by any 7z either")
        total_in += coder.in_streams
        total_out += coder.out_streams
        folder.coders.append(coder)
    for _ in range(total_out - 1):
        folder.bind_pairs.append((reader.number(), reader.number()))
    packed = total_in - len(folder.bind_pairs)
    if packed == 1:
        # The one input that no bind pair feeds is the packed stream.
        fed = {in_index for in_index, _out in folder.bind_pairs}
        folder.packed_indices = [next(i for i in range(total_in) if i not in fed)]
    else:
        folder.packed_indices = [reader.number() for _ in range(packed)]
    return folder


def _read_streams_info(reader: Reader) -> StreamsInfo:
    """kPackInfo + kUnPackInfo + kSubStreamsInfo, in whichever order they come."""
    info = StreamsInfo()
    while True:
        kind = reader.number()
        if kind == kEnd:
            # kSubStreamsInfo is optional: without it, each folder holds exactly
            # one file, which is its whole output. 7z omits the block in that
            # case, so the default has to live here rather than be assumed.
            if not info.substream_sizes and info.folders:
                info.substream_sizes = [[folder.output_size] for folder in info.folders]
                info.substream_crcs = [folder.crc for folder in info.folders]
            return info
        if kind == kPackInfo:
            info.pack_position = reader.number()
            count = reader.number()
            if count > MAX_FOLDERS:
                raise SevenZipError(f"{count} pack streams is not a real archive")
            while True:
                inner = reader.number()
                if inner == kEnd:
                    break
                if inner == kSize:
                    info.pack_sizes = [reader.number() for _ in range(count)]
                elif inner == kCRC:
                    reader.defined_vector(count)
                    reader.take(4 * count)
                else:
                    raise SevenZipError(f"unexpected property {inner:#x} inside kPackInfo")
        elif kind == kUnPackInfo:
            _read_unpack_info(reader, info)
        elif kind == kSubStreamsInfo:
            _read_substreams_info(reader, info)
        else:
            raise SevenZipError(f"unexpected property {kind:#x} in a streams-info block")


def _read_unpack_info(reader: Reader, info: StreamsInfo) -> None:
    """The folders, then every coder's output size, then the folder CRCs."""
    if reader.number() != kFolder:
        raise SevenZipError("kUnPackInfo does not start with kFolder")
    count = reader.number()
    if count > MAX_FOLDERS:
        raise SevenZipError(f"{count} folders is not a real archive")
    external = reader.byte()
    if external:
        raise SevenZipError("folders stored in an external stream are not supported")
    info.folders = [_read_folder(reader) for _ in range(count)]
    if reader.number() != kCodersUnPackSize:
        raise SevenZipError("the folder list is not followed by kCodersUnPackSize")
    for folder in info.folders:
        outputs = sum(coder.out_streams for coder in folder.coders)
        folder.unpacked_sizes = [reader.number() for _ in range(outputs)]
    while True:
        kind = reader.number()
        if kind == kEnd:
            return
        if kind == kCRC:
            defined = reader.defined_vector(len(info.folders))
            for folder, is_defined in zip(info.folders, defined, strict=True):
                if is_defined:
                    folder.crc = reader.u32()
        else:
            reader.skip_property(reader.number())


def _read_substreams_info(reader: Reader, info: StreamsInfo) -> None:
    """How each folder's output is cut into files, with their sizes and CRCs."""
    counts = [1] * len(info.folders)
    sizes: list[list[int]] = []
    crcs: list[int | None] = []
    kind = reader.number()
    if kind == kNumUnPackStream:
        counts = [reader.number() for _ in info.folders]
        for folder, count in zip(info.folders, counts, strict=True):
            folder.num_unpack_substreams = count
        kind = reader.number()

    # Sizes: for each folder, every substream but the last is written; the last
    # is what is left of the folder's output.
    if kind == kSize:
        for folder, count in zip(info.folders, counts, strict=True):
            if count == 0:
                sizes.append([])
                continue
            written = [reader.number() for _ in range(count - 1)]
            sizes.append([*written, folder.output_size - sum(written)])
        kind = reader.number()
    else:
        sizes = [
            [folder.output_size] if count == 1 else [0] * count
            for folder, count in zip(info.folders, counts, strict=True)
        ]

    while kind != kEnd:
        if kind == kCRC:
            # Folders made of exactly one substream already have their CRC above.
            unknown = sum(
                count
                for folder, count in zip(info.folders, counts, strict=True)
                if not (count == 1 and folder.crc is not None)
            )
            defined = reader.defined_vector(unknown)
            values = [reader.u32() if is_defined else None for is_defined in defined]
            cursor = 0
            for folder, count in zip(info.folders, counts, strict=True):
                if count == 1 and folder.crc is not None:
                    crcs.append(folder.crc)
                    continue
                for _ in range(count):
                    crcs.append(values[cursor] if cursor < len(values) else None)
                    cursor += 1
        else:
            reader.skip_property(reader.number())
        kind = reader.number()
    info.substream_sizes = sizes
    info.substream_crcs = crcs


def _read_files_info(reader: Reader, archive: SevenZipArchive) -> list[SevenZipEntry]:
    """The names, and which entries have no stream (directories and empty files)."""
    count = reader.number()
    if count > MAX_FILES:
        raise SevenZipError(f"{count} files is not a real archive")
    names: list[str] = []
    empty_stream = [False] * count
    empty_file: list[bool] = []
    anti: list[bool] = []
    attributes: list[int] = []

    while True:
        kind = reader.number()
        if kind == kEnd:
            break
        size = reader.number()
        stop = reader.position + size
        if kind == kName:
            external = reader.byte()
            if external:
                raise SevenZipError("names stored in an external stream are not supported")
            # The names are one UTF-16LE string per file, each NUL-terminated and
            # all of them concatenated. Decoding first and splitting afterwards
            # is the only correct order: splitting the *bytes* on 00 00 cuts a
            # character like U+2000 in half.
            raw = reader.take(stop - reader.position)
            text = raw.decode("utf-16-le", "replace")
            names = [piece.replace("\\", "/") for piece in text.split("\x00") if piece]
        elif kind == kEmptyStream:
            empty_stream = reader.bit_vector(count)
        elif kind == kEmptyFile:
            empty_file = reader.bit_vector(sum(empty_stream))
        elif kind == kAnti:
            anti = reader.bit_vector(sum(empty_stream))
        elif kind == kWinAttributes:
            defined = reader.defined_vector(count)
            if reader.byte():
                raise SevenZipError("attributes in an external stream are not supported")
            attributes = [reader.u32() if is_defined else 0 for is_defined in defined]
        reader.position = stop  # every property states its size: trust it

    if len(names) < count:
        names += [f"(unnamed {index})" for index in range(len(names), count)]
    entries: list[SevenZipEntry] = []
    empty_index = 0
    for index in range(count):
        entry = SevenZipEntry(name=names[index])
        if index < len(attributes):
            entry.attributes = attributes[index]
        if empty_stream[index]:
            entry.empty = True
            is_file = empty_index < len(empty_file) and empty_file[empty_index]
            is_anti = empty_index < len(anti) and anti[empty_index]
            entry.directory = not is_file and not is_anti
            empty_index += 1
        entries.append(entry)
    if anti and any(anti):
        archive.notes.append(
            "the archive holds 'anti-files', which mark a file for *deletion* when "
            "extracted over an existing folder: a 7z backup trick, rare in the wild"
        )
    return entries


def _attach_streams(archive: SevenZipArchive, entries: list[SevenZipEntry]) -> None:
    """Match the files that do have a stream with their folder, size and CRC."""
    info = archive.streams
    if info is None:
        return
    flat: list[tuple[int, int, int | None]] = []  # (folder index, size, crc)
    crcs = info.substream_crcs
    position = 0
    for folder_index, sizes in enumerate(info.substream_sizes):
        for size in sizes:
            crc = crcs[position] if position < len(crcs) else None
            flat.append((folder_index, size, crc))
            position += 1
    cursor = 0
    for entry in entries:
        if entry.empty:
            continue
        if cursor >= len(flat):
            break
        folder_index, size, crc = flat[cursor]
        cursor += 1
        folder = info.folders[folder_index]
        entry.folder = folder_index
        entry.size = size
        entry.crc = crc
        entry.method = folder.method
        entry.encrypted = folder.encrypted


# ---------------------------------------------------------------------------
# Decoding a folder (used for the encoded header, and for extraction)
# ---------------------------------------------------------------------------


def _lzma_filters(coder: Coder) -> list[dict]:
    """Turn a coder's property bytes into the filter Python's lzma wants.

    LZMA1 writes one properties byte holding lc/lp/pb, then a 32-bit dictionary
    size. LZMA2 writes a single byte coding the dictionary size. Python can
    decode both in FORMAT_RAW as long as it is told these numbers.
    """
    if coder.codec == 0x030101:
        if len(coder.properties) < 5:
            raise SevenZipError("an LZMA coder without its 5 property bytes")
        encoded = coder.properties[0]
        literal_context = encoded % 9
        rest = encoded // 9
        literal_position = rest % 5
        position_bits = rest // 5
        dictionary = int.from_bytes(coder.properties[1:5], "little")
        return [
            {
                "id": lzma.FILTER_LZMA1,
                "dict_size": max(dictionary, 4096),
                "lc": literal_context,
                "lp": literal_position,
                "pb": position_bits,
            }
        ]
    if coder.codec == 0x21:
        code = coder.properties[0] if coder.properties else 24
        if code > 40:
            raise SevenZipError(f"LZMA2 dictionary code {code} is out of range")
        dictionary = 0xFFFFFFFF if code == 40 else (2 | (code & 1)) << (code // 2 + 11)
        return [{"id": lzma.FILTER_LZMA2, "dict_size": dictionary}]
    raise SevenZipError(f"{coder.name} is not an LZMA coder")


def decode_folder(packed: bytes, folder: Folder, limit: int = DECODE_LIMIT) -> bytes:
    """Decompress one folder's packed bytes, for the codecs Python can do.

    Only the straight single-coder chains are handled - which is what archives
    made by 7z actually contain for their headers and for ordinary files. A
    filtered or multi-coder folder (BCJ2, PPMd) is named and handed over.
    """
    if folder.encrypted:
        raise SevenZipError("this folder is AES-encrypted: the password is needed first")
    if len(folder.coders) != 1:
        raise SevenZipError(
            f"this folder chains {len(folder.coders)} coders ({folder.method}), which ctfc "
            "does not decode: use `7z x`"
        )
    coder = folder.coders[0]
    size = min(folder.output_size, limit)
    if coder.codec == 0x00:
        return packed[:size]
    if coder.codec in (0x030101, 0x21):
        # Building the decompressor can fail too, not only running it: a
        # corrupt properties byte asks lzma for a filter chain it refuses.
        try:
            decompressor = lzma.LZMADecompressor(
                format=lzma.FORMAT_RAW, filters=_lzma_filters(coder)
            )
            out = decompressor.decompress(packed, max_length=size)
        except (lzma.LZMAError, ValueError) as exc:
            raise SevenZipError(f"the LZMA stream does not decode: {exc}") from exc
        return out
    if coder.codec in (0x040108, 0x040109):
        try:
            return zlib.decompressobj(wbits=-15).decompress(packed, size)
        except zlib.error as exc:
            raise SevenZipError(f"the deflate stream does not decode: {exc}") from exc
    if coder.codec == 0x040202:
        try:
            return bz2.BZ2Decompressor().decompress(packed, max_length=size)
        except (OSError, ValueError) as exc:
            raise SevenZipError(f"the bzip2 stream does not decode: {exc}") from exc
    raise SevenZipError(f"{coder.name} is not a codec ctfc decodes: use `7z x`")


def _pack_offset(info: StreamsInfo, folder_index: int) -> tuple[int, int]:
    """Where folder `folder_index`'s packed bytes start, and how many there are.

    Pack streams are handed out to folders in order, as many each as the folder
    declares packed inputs.
    """
    position = 32 + info.pack_position
    index = 0
    for current, folder in enumerate(info.folders):
        count = max(1, len(folder.packed_indices))
        total = sum(info.pack_sizes[index : index + count])
        if current == folder_index:
            return position, total
        position += total
        index += count
    raise SevenZipError(f"folder {folder_index} is not in the pack stream list")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def read(data: bytes) -> SevenZipArchive:
    """Parse the archive: decode the header if it is compressed, then list it."""
    if not is_sevenzip(data):
        raise SevenZipError("not a .7z archive (the signature 377abcaf271c is missing)")
    if len(data) < 32:
        raise SevenZipError(f"truncated: {len(data)} bytes, the signature header alone is 32")
    next_offset = int.from_bytes(data[12:20], "little")
    next_size = int.from_bytes(data[20:28], "little")
    start = 32 + next_offset
    if next_size == 0:
        raise SevenZipError("the archive has no header: it is empty (or truncated to nothing)")
    if start + next_size > len(data):
        raise SevenZipError(
            f"the header should be {next_size} bytes at offset {start}, but the file "
            f"is {len(data)} bytes: it is truncated"
        )
    header = data[start : start + next_size]
    archive = SevenZipArchive()

    reader = Reader(header)
    kind = reader.number()
    if kind == kEncodedHeader:
        header, kind, reader = _decode_header(data, reader, archive)
        if archive.header_encrypted:
            return archive
    if kind != kHeader:
        raise SevenZipError(f"the header starts with property {kind:#x}, not kHeader")

    entries: list[SevenZipEntry] = []
    while True:
        kind = reader.number()
        if kind == kEnd:
            break
        if kind == kMainStreamsInfo:
            archive.streams = _read_streams_info(reader)
        elif kind == kFilesInfo:
            entries = _read_files_info(reader, archive)
        elif kind == kArchiveProperties:
            while True:
                property_type = reader.number()
                if property_type == kEnd:
                    break
                reader.skip_property(reader.number())
        elif kind == kAdditionalStreamsInfo:
            _read_streams_info(reader)
        else:
            raise SevenZipError(f"unexpected property {kind:#x} at the top of the header")

    _attach_streams(archive, entries)
    archive.entries = entries
    _add_notes(archive)
    return archive


def _decode_header(
    data: bytes, reader: Reader, archive: SevenZipArchive
) -> tuple[bytes, int, Reader]:
    """A kEncodedHeader: the file list is itself a compressed (or encrypted) folder."""
    info = _read_streams_info(reader)
    if not info.folders:
        raise SevenZipError("the encoded header declares no folder")
    folder = info.folders[0]
    offset, size = _pack_offset(info, 0)
    packed = data[offset : offset + size]
    if folder.encrypted:
        archive.header_encrypted = True
        archive.streams = info
        properties = folder.aes_properties
        _read_aes_properties(archive, properties)
        archive.notes.append(
            "the header itself is AES-encrypted (7z a -mhe=on -p): not even the file "
            "names can be listed without the password"
        )
        return b"", kEnd, Reader(b"")
    decoded = decode_folder(packed, folder)
    if folder.crc is not None and zlib.crc32(decoded) != folder.crc:
        archive.notes.append("the decoded header does not match its own CRC: it is damaged")
    inner = Reader(decoded)
    return decoded, inner.number(), inner


def _read_aes_properties(archive: SevenZipArchive, properties: bytes) -> None:
    """The AES coder's properties: the iteration count and the salt.

    Byte 0 holds the number of KDF rounds as a power of two in its low six bits
    (7z's default is 19, so 524288 rounds of SHA-256). Its top two bits say
    whether a salt and an IV are present; when either is, byte 1 splits their
    lengths between its two nibbles, and the bytes follow.
    """
    if not properties:
        return
    first = properties[0]
    archive.kdf_iterations = 1 << (first & 0x3F)
    if first & 0xC0 and len(properties) >= 2:
        salt_size = ((first >> 7) & 1) + (properties[1] >> 4)
        iv_size = ((first >> 6) & 1) + (properties[1] & 0x0F)
        archive.salt = properties[2 : 2 + salt_size]
        archive.iv = properties[2 + salt_size : 2 + salt_size + iv_size]
    archive.notes.append(
        f"key = SHA-256 applied {archive.kdf_iterations} times over the password "
        "(7z's own KDF, not PBKDF2)"
    )


def _add_notes(archive: SevenZipArchive) -> None:
    """The observations worth printing once the listing is in hand."""
    info = archive.streams
    if info is None:
        archive.notes.append("the archive has no streams: every entry is empty or a directory")
        return
    encrypted = [folder for folder in info.folders if folder.encrypted]
    if encrypted:
        _read_aes_properties(archive, encrypted[0].aes_properties)
        archive.notes.append(
            f"{len(encrypted)} folder(s) are AES-256 encrypted but the names are in clear "
            "(7z a -p without -mhe=on)"
        )
    solid = [folder for folder in info.folders if folder.num_unpack_substreams > 1]
    if solid:
        archive.notes.append(
            f"{len(solid)} folder(s) hold several files in one solid block: extracting the "
            "last file means decompressing everything before it"
        )
    undecodable = {
        folder.method for folder in info.folders if not folder.encrypted and len(folder.coders) != 1
    }
    if undecodable:
        archive.notes.append(
            "these folders chain several coders, so ctfc lists them but leaves the bytes "
            f"to 7z: {', '.join(sorted(undecodable))}"
        )


def extract(data: bytes, archive: SevenZipArchive | None = None) -> SevenZipArchive:
    """Fill in `data` for every entry whose folder Python can decompress."""
    archive = archive or read(data)
    info = archive.streams
    if info is None:
        return archive
    for folder_index, folder in enumerate(info.folders):
        members = [entry for entry in archive.entries if entry.folder == folder_index]
        if not members or folder.encrypted:
            # The encryption is already reported once, per archive; repeating it
            # per folder only buries the listing.
            continue
        try:
            offset, size = _pack_offset(info, folder_index)
            stream = decode_folder(data[offset : offset + size], folder)
        except SevenZipError as exc:
            archive.notes.append(f"folder {folder_index}: {exc}")
            continue
        position = 0
        for entry in members:
            entry.data = stream[position : position + entry.size]
            position += entry.size
            if entry.crc is not None and entry.data is not None:
                if zlib.crc32(entry.data) != entry.crc:
                    archive.notes.append(f"{entry.name}: the extracted bytes fail its CRC32")
    return archive
