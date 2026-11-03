"""Read a Windows shortcut (`.lnk`): what it points at, and what it would run.

A `.lnk` is the most under-rated file in forensics, for two reasons.

**It is a payload.** A shortcut carries a command line. An attachment called
`invoice.pdf.lnk` with a PDF icon runs whatever is in its arguments field -
`powershell -nop -w hidden -enc <base64>` - and that field is not shown anywhere
in Explorer's default view. Reading it is the whole analysis.

**It is a witness.** Windows writes a `.lnk` into `Recent/` whenever a file is
opened, and that shortcut records the file's path, its size, its timestamps, the
*volume serial number* of the disk it was on, and - in the tracker block - the
**MAC address and machine name of the computer that created it**. So a shortcut
proves a file existed, on which disk, on which machine, even after the file
itself is long gone.

The format (MS-SHLLINK) is a 76-byte header whose `LinkFlags` say which of the
optional parts follow, in a fixed order:

    header -> target ID list -> link info -> five strings -> extra data blocks

The five strings are the interesting ones (description, relative path, working
directory, **arguments**, icon location), each a 16-bit character count followed
by that many characters - two bytes each when the `IsUnicode` flag is set, which
is the detail that turns a parser into mojibake if missed.

Nothing is executed: the command line is read and reported as text.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ctfc.core.encodings import find_encoded_command
from ctfc.core.errors import FormatError
from ctfc.core.timestamps import from_filetime

HEADER_SIZE = 0x4C
CLSID = bytes.fromhex("01140200000000 00c000000000000046".replace(" ", ""))

# LinkFlags (MS-SHLLINK 2.1.1), the ones that change how the file is parsed or
# that say something worth reporting.
HAS_TARGET_ID_LIST = 0x00000001
HAS_LINK_INFO = 0x00000002
HAS_NAME = 0x00000004
HAS_RELATIVE_PATH = 0x00000008
HAS_WORKING_DIR = 0x00000010
HAS_ARGUMENTS = 0x00000020
HAS_ICON_LOCATION = 0x00000040
IS_UNICODE = 0x00000080
FORCE_NO_LINK_INFO = 0x00000100
HAS_EXP_STRING = 0x00000200
RUN_AS_USER = 0x00002000
RUN_WITH_SHIM_LAYER = 0x00020000
FLAG_NAMES = {
    HAS_TARGET_ID_LIST: "has a target ID list",
    HAS_LINK_INFO: "has link info (path, volume)",
    HAS_NAME: "has a description",
    HAS_RELATIVE_PATH: "has a relative path",
    HAS_WORKING_DIR: "has a working directory",
    HAS_ARGUMENTS: "has command line arguments",
    HAS_ICON_LOCATION: "has an icon location",
    IS_UNICODE: "strings are UTF-16",
    HAS_EXP_STRING: "has an environment-variable path (%TEMP%...)",
    RUN_AS_USER: "runs elevated",
    RUN_WITH_SHIM_LAYER: "runs with a compatibility shim",
}
# Extra data blocks.
BLOCK_ENVIRONMENT = 0xA0000001
BLOCK_CONSOLE = 0xA0000002
BLOCK_TRACKER = 0xA0000003
BLOCK_CONSOLE_FE = 0xA0000004
BLOCK_SPECIAL_FOLDER = 0xA0000005
BLOCK_DARWIN = 0xA0000006
BLOCK_ICON_ENVIRONMENT = 0xA0000007
BLOCK_SHIM = 0xA0000009
BLOCK_PROPERTY_STORE = 0xA000000B
BLOCK_KNOWN_FOLDER = 0xA000000B
BLOCK_VISTA_ID_LIST = 0xA000000C
DRIVE_TYPES = {
    0: "unknown",
    1: "no root directory",
    2: "removable (USB stick, floppy)",
    3: "fixed disk",
    4: "network share",
    5: "CD-ROM",
    6: "RAM disk",
}
SHOW_COMMANDS = {1: "normal window", 3: "maximised", 7: "minimised, not active"}
# Things in a command line that make a shortcut a dropper rather than a shortcut.
SUSPICIOUS = (
    ("powershell", "launches PowerShell"),
    ("-enc", "an encoded PowerShell command follows"),
    ("-encodedcommand", "an encoded PowerShell command follows"),
    ("-nop", "PowerShell with no profile, the dropper default"),
    ("-w hidden", "hides its window"),
    ("-windowstyle hidden", "hides its window"),
    ("bypass", "bypasses the execution policy"),
    ("iex", "Invoke-Expression: runs a string as code"),
    ("invoke-expression", "runs a string as code"),
    ("invoke-webrequest", "downloads something"),
    ("downloadstring", "downloads something"),
    ("downloadfile", "downloads something"),
    ("curl ", "downloads something"),
    ("certutil", "certutil, used to decode or download payloads"),
    ("mshta", "mshta runs an HTA script"),
    ("rundll32", "rundll32 runs a DLL export"),
    ("regsvr32", "regsvr32, often with a remote scriptlet"),
    ("wscript", "the Windows scripting host"),
    ("cscript", "the Windows scripting host"),
    ("cmd.exe /c", "runs a command and exits"),
    ("frombase64string", "decodes base64 inline"),
    ("%temp%", "writes to or runs from TEMP"),
    ("appdata", "writes to or runs from AppData"),
)
MAX_STRING = 0x8000


class LnkError(FormatError):
    """The data is not a shortcut we can read."""


@dataclass
class LnkReport:
    """What the shortcut says."""

    flags: int = 0
    attributes: int = 0
    created: str = ""
    accessed: str = ""
    written: str = ""
    target_size: int = 0
    show_command: str = ""
    description: str = ""
    relative_path: str = ""
    working_directory: str = ""
    arguments: str = ""
    icon_location: str = ""
    local_path: str = ""  # from the link info: the absolute target path
    path_suffix: str = ""
    network_path: str = ""
    volume_label: str = ""
    volume_serial: str = ""
    drive_type: str = ""
    machine_id: str = ""  # the computer that *created* the shortcut
    environment_path: str = ""
    id_list_names: list[str] = field(default_factory=list)
    blocks: list[str] = field(default_factory=list)
    decoded_commands: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def target(self) -> str:
        """The best single answer to "what does this point at?"."""
        if self.local_path:
            return self.local_path + self.path_suffix
        return self.network_path or self.environment_path or self.relative_path

    @property
    def command(self) -> str:
        """The target and its arguments, as a command line."""
        target = self.target
        if target and self.arguments:
            return f"{target} {self.arguments}"
        return target or self.arguments

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "command": self.command,
            "arguments": self.arguments,
            "description": self.description,
            "relative_path": self.relative_path,
            "working_directory": self.working_directory,
            "icon_location": self.icon_location,
            "local_path": self.local_path,
            "network_path": self.network_path,
            "environment_path": self.environment_path,
            "volume_label": self.volume_label,
            "volume_serial": self.volume_serial,
            "drive_type": self.drive_type,
            "machine_id": self.machine_id,
            "created": self.created,
            "accessed": self.accessed,
            "written": self.written,
            "target_size": self.target_size,
            "show_command": self.show_command,
            "id_list_names": list(self.id_list_names),
            "blocks": list(self.blocks),
            "decoded_commands": list(self.decoded_commands),
            "indicators": list(self.indicators),
            "notes": list(self.notes),
        }


def is_lnk(data: bytes) -> bool:
    """A shortcut announces itself twice: a size of 0x4C, then a fixed CLSID."""
    return (
        len(data) >= HEADER_SIZE
        and int.from_bytes(data[0:4], "little") == HEADER_SIZE
        and data[4:20] == CLSID
    )


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 4], "little")


def _ansi_at(data: bytes, offset: int) -> str:
    """A NUL-terminated code-page string at an absolute offset."""
    if not 0 <= offset < len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("cp1252", "replace")


def _utf16_at(data: bytes, offset: int) -> str:
    """A NUL-terminated UTF-16LE string at an absolute offset."""
    if not 0 <= offset < len(data):
        return ""
    end = offset
    while end + 1 < len(data) and data[end : end + 2] != b"\x00\x00":
        end += 2
    return data[offset:end].decode("utf-16-le", "replace")


def _counted_string(data: bytes, offset: int, unicode: bool) -> tuple[str, int]:
    """One StringData entry: a character count, then that many characters.

    The count is in *characters*, not bytes, and a character is two bytes when
    the IsUnicode flag is set. Getting that wrong is the classic `.lnk` parser
    bug: every string comes out half-length and full of NULs.
    """
    if offset + 2 > len(data):
        raise LnkError(f"a string at offset {offset} is past the end of the file")
    count = _u16(data, offset)
    if count > MAX_STRING:
        raise LnkError(f"a string of {count} characters is not a real shortcut field")
    size = count * (2 if unicode else 1)
    raw = data[offset + 2 : offset + 2 + size]
    if len(raw) < size:
        raise LnkError(f"a string at offset {offset} is cut short")
    text = raw.decode("utf-16-le" if unicode else "cp1252", "replace")
    return text.rstrip("\x00"), offset + 2 + size


def _id_list_strings(block: bytes) -> list[str]:
    """Readable names out of the shell-item list, without decoding shell items.

    The target ID list is a chain of shell items whose layout differs per item
    type (drive, folder, file, control panel...) and which would be a module of
    its own. But every file and folder item carries its name twice - once in the
    code page and once in UTF-16 - so the names can be lifted out without
    knowing the layouts. It is a best effort, and labelled as one.
    """
    names: list[str] = []
    for text in block.split(b"\x00\x00"):
        for piece in text.split(b"\x00"):
            if len(piece) >= 3 and piece.isascii() and piece.decode().isprintable():
                candidate = piece.decode()
                if candidate not in names and any(char.isalnum() for char in candidate):
                    names.append(candidate)
    return names[:40]


def analyse(data: bytes) -> LnkReport:
    """Read a shortcut: its target, its command line and its witness fields."""
    if not is_lnk(data):
        raise LnkError(
            "not a Windows shortcut: the first four bytes must be 4c 00 00 00 and be "
            "followed by the shortcut CLSID"
        )
    report = LnkReport(flags=_u32(data, 0x14), attributes=_u32(data, 0x18))
    unicode = bool(report.flags & IS_UNICODE)
    report.created = from_filetime(int.from_bytes(data[0x1C:0x24], "little"))
    report.accessed = from_filetime(int.from_bytes(data[0x24:0x2C], "little"))
    report.written = from_filetime(int.from_bytes(data[0x2C:0x34], "little"))
    report.target_size = _u32(data, 0x34)
    report.show_command = SHOW_COMMANDS.get(_u32(data, 0x3C), f"{_u32(data, 0x3C):#x}")

    position = HEADER_SIZE
    if report.flags & HAS_TARGET_ID_LIST:
        size = _u16(data, position)
        report.id_list_names = _id_list_strings(data[position + 2 : position + 2 + size])
        position += 2 + size
    if report.flags & HAS_LINK_INFO and not report.flags & FORCE_NO_LINK_INFO:
        position = _read_link_info(data, position, report)

    for flag, field_name in (
        (HAS_NAME, "description"),
        (HAS_RELATIVE_PATH, "relative_path"),
        (HAS_WORKING_DIR, "working_directory"),
        (HAS_ARGUMENTS, "arguments"),
        (HAS_ICON_LOCATION, "icon_location"),
    ):
        if report.flags & flag:
            text, position = _counted_string(data, position, unicode)
            setattr(report, field_name, text)

    _read_extra_blocks(data, position, report)
    _add_notes(report)
    return report


def _read_link_info(data: bytes, start: int, report: LnkReport) -> int:
    """The LinkInfo structure: the absolute path, and which volume it was on.

    Every offset inside it is relative to the start of the structure, which is
    what makes it readable at all after a file has been moved around.
    """
    if start + 4 > len(data):
        raise LnkError("the link info structure starts past the end of the file")
    size = _u32(data, start)
    if size < 0x1C or start + size > len(data):
        raise LnkError(f"the link info structure claims {size} bytes, which does not fit")
    header_size = _u32(data, start + 4)
    flags = _u32(data, start + 8)
    volume_offset = _u32(data, start + 12)
    local_path_offset = _u32(data, start + 16)
    network_offset = _u32(data, start + 20)
    suffix_offset = _u32(data, start + 24)
    unicode_local = _u32(data, start + 28) if header_size >= 0x24 else 0
    unicode_suffix = _u32(data, start + 32) if header_size >= 0x24 else 0

    if flags & 0x0001:  # VolumeIDAndLocalBasePath
        report.local_path = (
            _utf16_at(data, start + unicode_local)
            if unicode_local
            else _ansi_at(data, start + local_path_offset)
        )
        if volume_offset:
            volume = start + volume_offset
            report.drive_type = DRIVE_TYPES.get(
                _u32(data, volume + 4), f"type {_u32(data, volume + 4)}"
            )
            report.volume_serial = f"{_u32(data, volume + 8):08x}"
            label_offset = _u32(data, volume + 12)
            report.volume_label = _ansi_at(data, volume + label_offset)
    if flags & 0x0002 and network_offset:  # CommonNetworkRelativeLinkAndPathSuffix
        network = start + network_offset
        share_offset = _u32(data, network + 8)
        report.network_path = _ansi_at(data, network + share_offset)
    report.path_suffix = (
        _utf16_at(data, start + unicode_suffix)
        if unicode_suffix
        else _ansi_at(data, start + suffix_offset)
    )
    return start + size


def _read_extra_blocks(data: bytes, start: int, report: LnkReport) -> None:
    """The trailing blocks, of which the tracker one is the forensic prize."""
    position = start
    while position + 8 <= len(data):
        size = _u32(data, position)
        if size < 8 or position + size > len(data):
            break
        signature = _u32(data, position + 4)
        body = data[position + 8 : position + size]
        name = {
            BLOCK_ENVIRONMENT: "environment variable path",
            BLOCK_CONSOLE: "console settings",
            BLOCK_TRACKER: "tracker (machine that created it)",
            BLOCK_CONSOLE_FE: "console code page",
            BLOCK_SPECIAL_FOLDER: "special folder",
            BLOCK_DARWIN: "Darwin (Windows Installer) ID",
            BLOCK_ICON_ENVIRONMENT: "icon environment path",
            BLOCK_SHIM: "compatibility shim",
            BLOCK_KNOWN_FOLDER: "known folder / property store",
            BLOCK_VISTA_ID_LIST: "Vista+ target ID list",
        }.get(signature, f"block {signature:#010x}")
        report.blocks.append(name)
        if signature == BLOCK_ENVIRONMENT:
            # 260 bytes of code page, then 520 of UTF-16: the second wins.
            report.environment_path = (_utf16_at(body, 260) or _ansi_at(body, 0)).strip()
        elif signature == BLOCK_TRACKER and len(body) >= 24:
            # size(4) version(4) then 16 bytes of NetBIOS machine name.
            report.machine_id = body[8:24].split(b"\x00", 1)[0].decode("cp1252", "replace")
        elif signature == BLOCK_ICON_ENVIRONMENT and not report.icon_location:
            report.icon_location = (_utf16_at(body, 260) or _ansi_at(body, 0)).strip()
        position += size


def _add_notes(report: LnkReport) -> None:
    """Say what this shortcut is: a witness, a dropper, or both."""
    command = report.command.lower()
    for needle, why in SUSPICIOUS:
        if needle in command:
            report.indicators.append(f"{needle} - {why}")
    script = find_encoded_command(report.command.encode("utf-8", "replace"))
    if script is not None:
        report.decoded_commands.append(script.decode("utf-8", "replace"))

    if report.arguments:
        report.notes.append(
            "this shortcut carries a command line, which Explorer does not show: that "
            "is what it actually runs"
        )
    if report.indicators:
        report.notes.append(
            "the command line reads like a dropper, not a shortcut: run it through "
            "`ctfc lens` to pull the crypto and the URLs out of it"
        )
    if report.machine_id:
        report.notes.append(
            f"the tracker block names the machine that created the shortcut: {report.machine_id}"
        )
    if report.volume_serial and report.volume_serial != "00000000":
        report.notes.append(
            f"the target was on a {report.drive_type or 'disk'} with serial "
            f"{report.volume_serial}"
            + (f" labelled {report.volume_label!r}" if report.volume_label else "")
            + ": that identifies the disk even if the file is gone"
        )
    if report.target_size:
        report.notes.append(
            f"the target was {report.target_size} bytes when the shortcut was written"
        )
    if not report.target and not report.arguments:
        report.notes.append(
            "no path and no arguments: the target is described only by the shell item "
            "list, whose readable names are listed above"
        )
