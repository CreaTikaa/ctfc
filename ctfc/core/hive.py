"""Read a Windows registry hive file (SAM, SYSTEM, SOFTWARE, NTUSER.DAT).

A hive is a small database with its own allocator, which is why `strings` on one
is such a poor way to read it. The structure is simple once named:

- a **4096-byte header** starting `regf`, which says where the root key is. Every
  offset in the file is counted from the *end* of that header, not from zero;
- then **hive bins** (`hbin`), each cut into **cells**. A cell starts with a
  4-byte signed size: negative means allocated, positive means free. So a deleted
  key is still readable, which is why this is worth doing by hand;
- a **key node** (`nk`) holds a name, a parent, a list of subkeys and a list of
  values; a **value** (`vk`) holds a name, a type and either an offset to its data
  or - for four bytes or fewer - the data inline.

What it is used for here: reading the keys that matter in a forensics challenge
(Run keys, services, the computer name, a user's typed paths) without Windows,
and recovering the **boot key**, which is the first step of getting the password
hashes out of a SAM. The boot key is not stored as a value at all: it is hidden
in the *class names* of four keys under `Control\\Lsa`, then permuted.

Deliberately out of scope: decrypting the NT hashes themselves. That needs the
boot key plus RC4 or AES over the SAM's `F` and `V` structures, and there was no
real hive here to verify an implementation against - so this prints the exact
`samdump2` / `secretsdump.py` command instead of shipping crypto that has never
been run against a genuine file.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

MAGIC = b"regf"
HEADER_SIZE = 4096  # every cell offset is relative to the end of this
BIN_MAGIC = b"hbin"
# Value types we can present (winnt.h REG_*).
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_DWORD_BIG_ENDIAN = 5
REG_MULTI_SZ = 7
REG_QWORD = 11
TYPE_NAMES = {
    0: "REG_NONE",
    REG_SZ: "REG_SZ",
    REG_EXPAND_SZ: "REG_EXPAND_SZ",
    REG_BINARY: "REG_BINARY",
    REG_DWORD: "REG_DWORD",
    REG_DWORD_BIG_ENDIAN: "REG_DWORD_BE",
    6: "REG_LINK",
    REG_MULTI_SZ: "REG_MULTI_SZ",
    REG_QWORD: "REG_QWORD",
}
INLINE_FLAG = 0x80000000  # set in a value's size when the data is in the offset field
MAX_DEPTH = 32
MAX_KEYS = 100_000
# The four keys whose class names carry the boot key, in order.
BOOTKEY_KEYS = ("JD", "Skew1", "GBG", "Data")
# The boot key's bytes are stored shuffled; this is the order they go back in.
BOOTKEY_PERMUTATION = (8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7)


class HiveError(Exception):
    """The file is not a registry hive we can read."""


@dataclass
class Value:
    """One registry value."""

    name: str  # "" is the key's default value
    type: int
    data: bytes

    @property
    def type_name(self) -> str:
        return TYPE_NAMES.get(self.type, f"type {self.type}")

    @property
    def text(self) -> str:
        """The value rendered the way regedit would show it."""
        if self.type in (REG_SZ, REG_EXPAND_SZ):
            return self.data.decode("utf-16-le", "replace").rstrip("\x00")
        if self.type == REG_MULTI_SZ:
            parts = self.data.decode("utf-16-le", "replace").split("\x00")
            return "; ".join(part for part in parts if part)
        if self.type == REG_DWORD and len(self.data) >= 4:
            return str(int.from_bytes(self.data[:4], "little"))
        if self.type == REG_DWORD_BIG_ENDIAN and len(self.data) >= 4:
            return str(int.from_bytes(self.data[:4], "big"))
        if self.type == REG_QWORD and len(self.data) >= 8:
            return str(int.from_bytes(self.data[:8], "little"))
        return self.data.hex()


@dataclass
class Key:
    """One registry key node."""

    name: str
    offset: int
    class_name: str = ""
    subkey_offsets: list[int] = field(default_factory=list)
    values: list[Value] = field(default_factory=list)

    def value(self, name: str) -> Value | None:
        wanted = name.lower()
        for item in self.values:
            if item.name.lower() == wanted:
                return item
        return None


class Hive:
    """A parsed hive, read lazily: keys are decoded as they are asked for."""

    def __init__(self, data: bytes) -> None:
        if data[:4] != MAGIC:
            raise HiveError("not a registry hive (the file must start with 'regf')")
        if len(data) < HEADER_SIZE + 32:
            raise HiveError(f"truncated: {len(data)} bytes, the header alone is {HEADER_SIZE}")
        self.data = data
        self.root_offset = int.from_bytes(data[36:40], "little")
        self.name = data[48:112].decode("utf-16-le", "replace").rstrip("\x00")
        if data[HEADER_SIZE : HEADER_SIZE + 4] != BIN_MAGIC:
            raise HiveError("no hbin at offset 4096: the hive is damaged")

    # -- cells ------------------------------------------------------------
    def cell(self, offset: int) -> bytes:
        """The payload of the cell at `offset` (which is relative to 4096)."""
        start = HEADER_SIZE + offset
        if offset < 0 or start + 4 > len(self.data):
            raise HiveError(f"cell offset {offset} is outside the hive")
        size = struct.unpack("<i", self.data[start : start + 4])[0]
        # Negative means allocated; the absolute value includes these 4 bytes.
        length = abs(size) - 4
        if length <= 0 or start + 4 + length > len(self.data):
            raise HiveError(f"cell at {offset} has an impossible size {size}")
        return self.data[start + 4 : start + 4 + length]

    # -- keys -------------------------------------------------------------
    def key(self, offset: int) -> Key:
        """Decode the key node at `offset`."""
        cell = self.cell(offset)
        if cell[:2] != b"nk":
            raise HiveError(f"no key node at offset {offset} (found {cell[:2]!r})")
        name_length = int.from_bytes(cell[72:74], "little")
        class_length = int.from_bytes(cell[74:76], "little")
        flags = int.from_bytes(cell[2:4], "little")
        raw_name = cell[76 : 76 + name_length]
        # Flag 0x20 means the name is ASCII; otherwise it is UTF-16LE.
        name = (
            raw_name.decode("latin-1", "replace")
            if flags & 0x0020
            else raw_name.decode("utf-16-le", "replace")
        )
        key = Key(name=name, offset=offset)

        class_offset = int.from_bytes(cell[48:52], "little")
        if class_length and class_offset != 0xFFFFFFFF:
            try:
                key.class_name = self.cell(class_offset)[:class_length].decode(
                    "utf-16-le", "replace"
                )
            except HiveError:
                key.class_name = ""

        subkey_count = int.from_bytes(cell[20:24], "little")
        subkey_list = int.from_bytes(cell[28:32], "little")
        if subkey_count and subkey_list != 0xFFFFFFFF:
            key.subkey_offsets = self._subkey_list(subkey_list)

        value_count = int.from_bytes(cell[36:40], "little")
        value_list = int.from_bytes(cell[40:44], "little")
        if value_count and value_list != 0xFFFFFFFF:
            key.values = self._values(value_list, value_count)
        return key

    def _subkey_list(self, offset: int, depth: int = 0) -> list[int]:
        """Follow a subkey list, which comes in four flavours."""
        if depth > MAX_DEPTH:
            return []
        try:
            cell = self.cell(offset)
        except HiveError:
            return []
        signature = cell[:2]
        count = int.from_bytes(cell[2:4], "little")
        offsets: list[int] = []
        if signature in (b"lf", b"lh"):
            # Each entry is an offset plus a name hash we do not need.
            for index in range(min(count, MAX_KEYS)):
                at = 4 + index * 8
                if at + 4 > len(cell):
                    break
                offsets.append(int.from_bytes(cell[at : at + 4], "little"))
        elif signature == b"li":
            for index in range(min(count, MAX_KEYS)):
                at = 4 + index * 4
                if at + 4 > len(cell):
                    break
                offsets.append(int.from_bytes(cell[at : at + 4], "little"))
        elif signature == b"ri":
            # An index of further lists, used once a key has very many subkeys.
            for index in range(min(count, MAX_KEYS)):
                at = 4 + index * 4
                if at + 4 > len(cell):
                    break
                offsets += self._subkey_list(int.from_bytes(cell[at : at + 4], "little"), depth + 1)
        return offsets

    def _values(self, offset: int, count: int) -> list[Value]:
        try:
            listing = self.cell(offset)
        except HiveError:
            return []
        values: list[Value] = []
        for index in range(min(count, MAX_KEYS)):
            at = index * 4
            if at + 4 > len(listing):
                break
            try:
                values.append(self._value(int.from_bytes(listing[at : at + 4], "little")))
            except HiveError:
                continue
        return values

    def _value(self, offset: int) -> Value:
        cell = self.cell(offset)
        if cell[:2] != b"vk":
            raise HiveError(f"no value at offset {offset}")
        name_length = int.from_bytes(cell[2:4], "little")
        size = int.from_bytes(cell[4:8], "little")
        data_offset = int.from_bytes(cell[8:12], "little")
        value_type = int.from_bytes(cell[12:16], "little")
        flags = int.from_bytes(cell[16:18], "little")
        raw_name = cell[20 : 20 + name_length]
        name = (
            raw_name.decode("latin-1", "replace")
            if flags & 0x0001
            else raw_name.decode("utf-16-le", "replace")
        )
        if size & INLINE_FLAG:
            # Four bytes or fewer live in the offset field itself.
            length = size & 0x7FFFFFFF
            data = cell[8 : 8 + min(length, 4)]
        elif size == 0:
            data = b""
        else:
            try:
                data = self.cell(data_offset)[:size]
            except HiveError:
                data = b""
        return Value(name=name, type=value_type, data=data)

    # -- navigation -------------------------------------------------------
    def root(self) -> Key:
        return self.key(self.root_offset)

    def open(self, path: str) -> Key | None:
        r"""Resolve a key by path, e.g. `Microsoft\Windows\CurrentVersion\Run`.

        The root key's own name is not part of the path, which is what every
        registry tool does and what makes a path portable between hives.
        """
        current = self.root()
        for part in [piece for piece in path.replace("/", "\\").split("\\") if piece]:
            wanted = part.lower()
            found = None
            for offset in current.subkey_offsets:
                try:
                    child = self.key(offset)
                except HiveError:
                    continue
                if child.name.lower() == wanted:
                    found = child
                    break
            if found is None:
                return None
            current = found
        return current

    def subkeys(self, key: Key) -> list[Key]:
        out = []
        for offset in key.subkey_offsets:
            try:
                out.append(self.key(offset))
            except HiveError:
                continue
        return out

    def walk(self, key: Key | None = None, prefix: str = "", depth: int = 0):
        """Yield (path, Key) for the whole tree, depth-first."""
        key = key if key is not None else self.root()
        if depth > MAX_DEPTH:
            return
        yield prefix or key.name, key
        for child in self.subkeys(key):
            path = f"{prefix}\\{child.name}" if prefix else child.name
            yield from self.walk(child, path, depth + 1)


def boot_key(system: Hive) -> bytes | None:
    r"""Recover the boot key ("syskey") from a SYSTEM hive.

    It is not a value anywhere. Each of `Control\Lsa\JD`, `Skew1`, `GBG` and
    `Data` carries eight hex characters as its **class name**; concatenated they
    give sixteen bytes, which are then unshuffled with a fixed permutation. This
    is the first thing any SAM hash extraction needs.
    """
    select = system.open(r"Select")
    control_sets = []
    if select is not None:
        current = select.value("Current")
        if current is not None and current.data:
            number = int.from_bytes(current.data[:4], "little")
            control_sets.append(f"ControlSet{number:03d}")
    control_sets += ["CurrentControlSet", "ControlSet001"]

    scrambled = ""
    for control_set in control_sets:
        parts = []
        for name in BOOTKEY_KEYS:
            key = system.open(rf"{control_set}\Control\Lsa\{name}")
            if key is None or len(key.class_name) != 8:
                parts = []
                break
            parts.append(key.class_name)
        if parts:
            scrambled = "".join(parts)
            break
    if len(scrambled) != 32:
        return None
    try:
        raw = bytes.fromhex(scrambled)
    except ValueError:
        return None
    return bytes(raw[index] for index in BOOTKEY_PERMUTATION)


# Keys worth reading without being asked, with why they matter.
INTERESTING = (
    (r"Microsoft\Windows\CurrentVersion\Run", "programs started at logon (persistence)"),
    (r"Microsoft\Windows\CurrentVersion\RunOnce", "programs started once at logon"),
    (
        r"Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        "where the user's folders are",
    ),
    (r"Software\Microsoft\Windows\CurrentVersion\Run", "persistence, under Software"),
    (r"ControlSet001\Control\ComputerName\ComputerName", "the machine's name"),
    (r"CurrentControlSet\Control\ComputerName\ComputerName", "the machine's name"),
    (r"Microsoft\Windows NT\CurrentVersion", "Windows version and install date"),
    (r"SAM\Domains\Account\Users\Names", "the local account names"),
    (r"Domains\Account\Users\Names", "the local account names"),
)


@dataclass
class HiveReport:
    """What the hive holds."""

    name: str = ""
    kind: str = ""  # a guess at which hive it is
    keys: int = 0
    found: list[tuple[str, str, list[str]]] = field(default_factory=list)
    boot_key: bytes | None = None
    users: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "keys": self.keys,
            "found": [
                {"path": path, "why": why, "values": values} for path, why, values in self.found
            ],
            "boot_key": None if self.boot_key is None else self.boot_key.hex(),
            "users": list(self.users),
            "notes": list(self.notes),
            "commands": list(self.commands),
        }


def _guess_kind(hive: Hive) -> str:
    """Which hive this is, from its own recorded file name and its top keys."""
    lowered = hive.name.lower()
    for candidate in ("sam", "system", "software", "security", "ntuser.dat", "usrclass"):
        if candidate in lowered:
            return candidate.upper()
    names = {key.name.lower() for key in hive.subkeys(hive.root())}
    if "domains" in names:
        return "SAM"
    if "select" in names:
        return "SYSTEM"
    return "unknown"


def analyse(data: bytes) -> HiveReport:
    """Read the hive, report the keys that matter, and recover the boot key."""
    hive = Hive(data)
    report = HiveReport(name=hive.name or "(unnamed)", kind=_guess_kind(hive))
    report.keys = sum(1 for _ in hive.walk())

    for path, why in INTERESTING:
        key = hive.open(path)
        if key is None or not key.values:
            continue
        rendered = [
            f"{value.name or '(default)'} = {value.text[:200]}"
            for value in key.values
            if value.data
        ]
        if rendered:
            report.found.append((path, why, rendered))

    if report.kind == "SYSTEM":
        report.boot_key = boot_key(hive)
        if report.boot_key is not None:
            report.notes.append(
                f"boot key (syskey): {report.boot_key.hex()} - recovered from the class names "
                r"of Control\Lsa\{JD,Skew1,GBG,Data}, which is the first step of any SAM "
                "hash extraction"
            )
        else:
            report.notes.append(
                r"this looks like a SYSTEM hive but Control\Lsa\{JD,Skew1,GBG,Data} did not "
                "give a boot key: the hive may be partial, or from a version that stores it "
                "elsewhere"
            )

    if report.kind == "SAM":
        users = hive.open(r"SAM\Domains\Account\Users\Names") or hive.open(
            r"Domains\Account\Users\Names"
        )
        if users is not None:
            report.users = [key.name for key in hive.subkeys(users) if key.name]
        if report.users:
            report.notes.append(f"local accounts: {', '.join(report.users)}")
        report.notes.append(
            "the NT hashes are in this hive but encrypted with the boot key from the "
            "SYSTEM hive. ctfc stops here on purpose: decrypting them needs RC4 or AES "
            "over the F and V structures, and that code has not been verified against a "
            "real hive, so use a tool that has"
        )
        report.commands.append("samdump2 SYSTEM SAM")
        report.commands.append("secretsdump.py -sam SAM -system SYSTEM LOCAL")
        report.commands.append("# then paste a line into `ctfc hash` for the hashcat mode")

    if not report.found and not report.notes:
        report.notes.append(
            "none of the usual keys are in this hive. Use `--key <path>` to read one, "
            "or `--list` to see the tree"
        )
    return report
