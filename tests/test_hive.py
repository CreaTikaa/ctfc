"""Tests for reading a registry hive (core/hive.py).

The hives are built here, by hand, from the regf structures - there is no real
SAM on this machine, and a builder written from the format description is a
better check of the reader than a recording of its own output would be.
"""

from __future__ import annotations

import struct

import pytest

from ctfc.core import hive


class HiveBuilder:
    """Lay out cells in one hive bin and keep track of their offsets."""

    def __init__(self) -> None:
        self.cells = bytearray()

    def add(self, payload: bytes) -> int:
        """Append a cell and return its offset (relative to the end of the header)."""
        size = 4 + len(payload)
        size += -size % 8  # cells are multiples of 8 bytes
        offset = 32 + len(self.cells)  # 32 = the hbin header in front of the cells
        # A negative size means "allocated", which is how a live cell is marked.
        self.cells += struct.pack("<i", -size) + payload
        self.cells += bytes(size - 4 - len(payload))
        return offset

    def key(
        self,
        name: str,
        subkeys: list[int] | None = None,
        values: list[int] | None = None,
        class_name: str = "",
    ) -> int:
        """A key node (nk). Subkeys and values are offsets of cells already added."""
        subkey_list = self.add(self._fast_leaf(subkeys)) if subkeys else 0xFFFFFFFF
        value_list = (
            self.add(b"".join(struct.pack("<I", offset) for offset in values))
            if values
            else 0xFFFFFFFF
        )
        class_offset = 0xFFFFFFFF
        class_length = 0
        if class_name:
            encoded = class_name.encode("utf-16-le")
            class_offset = self.add(encoded)
            class_length = len(encoded)
        encoded_name = name.encode("latin-1")
        body = bytearray(76)
        body[0:2] = b"nk"
        body[2:4] = (0x0020).to_bytes(2, "little")  # the name is ASCII
        body[16:20] = (0xFFFFFFFF).to_bytes(4, "little")  # parent
        body[20:24] = len(subkeys or []).to_bytes(4, "little")
        body[28:32] = subkey_list.to_bytes(4, "little")
        body[36:40] = len(values or []).to_bytes(4, "little")
        body[40:44] = value_list.to_bytes(4, "little")
        body[48:52] = class_offset.to_bytes(4, "little")
        body[72:74] = len(encoded_name).to_bytes(2, "little")
        body[74:76] = class_length.to_bytes(2, "little")
        return self.add(bytes(body) + encoded_name)

    def _fast_leaf(self, offsets: list[int]) -> bytes:
        body = b"lf" + len(offsets).to_bytes(2, "little")
        for offset in offsets:
            body += struct.pack("<I", offset) + b"ABCD"  # the name hash is unused
        return body

    def value(self, name: str, value_type: int, data: bytes) -> int:
        """A value (vk). Four bytes or fewer are stored inline, as Windows does."""
        encoded_name = name.encode("latin-1")
        body = bytearray(20)
        body[0:2] = b"vk"
        body[2:4] = len(encoded_name).to_bytes(2, "little")
        body[16:18] = (0x0001).to_bytes(2, "little")  # the name is ASCII
        body[12:16] = value_type.to_bytes(4, "little")
        if len(data) <= 4 and data:
            body[4:8] = (len(data) | hive.INLINE_FLAG).to_bytes(4, "little")
            body[8 : 8 + len(data)] = data
        else:
            data_offset = self.add(data) if data else 0xFFFFFFFF
            body[4:8] = len(data).to_bytes(4, "little")
            body[8:12] = data_offset.to_bytes(4, "little")
        return self.add(bytes(body) + encoded_name)

    def build(self, root: int, file_name: str = "SYSTEM") -> bytes:
        header = bytearray(hive.HEADER_SIZE)
        header[0:4] = b"regf"
        header[36:40] = root.to_bytes(4, "little")
        name = file_name.encode("utf-16-le")[:64]
        header[48 : 48 + len(name)] = name
        bins = bytearray(32)
        bins[0:4] = b"hbin"
        bins[8:12] = (32 + len(self.cells)).to_bytes(4, "little")
        return bytes(header) + bytes(bins) + bytes(self.cells)


def simple_hive() -> bytes:
    r"""A hive shaped like `Microsoft\Windows\CurrentVersion\Run`."""
    builder = HiveBuilder()
    run_values = [
        builder.value("Updater", hive.REG_SZ, "C:\\Temp\\evil.exe".encode("utf-16-le")),
        builder.value("Count", hive.REG_DWORD, (7).to_bytes(4, "little")),
    ]
    run = builder.key("Run", values=run_values)
    current = builder.key("CurrentVersion", subkeys=[run])
    windows = builder.key("Windows", subkeys=[current])
    microsoft = builder.key("Microsoft", subkeys=[windows])
    root = builder.key("ROOT", subkeys=[microsoft])
    return builder.build(root, "NTUSER.DAT")


# ---------------------------------------------------------------------------
# The format
# ---------------------------------------------------------------------------


def test_a_non_hive_is_refused():
    with pytest.raises(hive.HiveError, match="not a registry hive"):
        hive.Hive(b"PK\x03\x04" + bytes(5000))


def test_a_truncated_hive_is_refused():
    with pytest.raises(hive.HiveError, match="truncated"):
        hive.Hive(b"regf" + bytes(100))


def test_a_hive_without_an_hbin_is_refused():
    data = bytearray(b"regf" + bytes(hive.HEADER_SIZE + 60))
    with pytest.raises(hive.HiveError, match="no hbin"):
        hive.Hive(bytes(data))


def test_the_root_key_is_found():
    parsed = hive.Hive(simple_hive())
    assert parsed.root().name == "ROOT"
    assert parsed.name == "NTUSER.DAT"


def test_a_key_is_resolved_by_path():
    parsed = hive.Hive(simple_hive())
    key = parsed.open(r"Microsoft\Windows\CurrentVersion\Run")
    assert key is not None
    assert key.name == "Run"


def test_a_path_with_forward_slashes_works_too():
    parsed = hive.Hive(simple_hive())
    assert parsed.open("Microsoft/Windows/CurrentVersion/Run") is not None


def test_a_missing_path_returns_none_rather_than_raising():
    parsed = hive.Hive(simple_hive())
    assert parsed.open(r"Microsoft\Nope") is None


def test_a_string_value_is_rendered_as_text():
    parsed = hive.Hive(simple_hive())
    key = parsed.open(r"Microsoft\Windows\CurrentVersion\Run")
    value = key.value("Updater")
    assert value.type_name == "REG_SZ"
    assert value.text == "C:\\Temp\\evil.exe"


def test_a_dword_stored_inline_is_read():
    """Four bytes or fewer live in the offset field itself, not in their own cell."""
    parsed = hive.Hive(simple_hive())
    key = parsed.open(r"Microsoft\Windows\CurrentVersion\Run")
    assert key.value("Count").text == "7"


def test_a_multi_sz_value_is_split():
    builder = HiveBuilder()
    data = "first\x00second\x00\x00".encode("utf-16-le")
    value = builder.value("List", hive.REG_MULTI_SZ, data)
    root = builder.key("ROOT", values=[value])
    parsed = hive.Hive(builder.build(root))
    assert parsed.root().value("List").text == "first; second"


def test_a_qword_value_is_read():
    builder = HiveBuilder()
    value = builder.value("Big", hive.REG_QWORD, (2**40).to_bytes(8, "little"))
    root = builder.key("ROOT", values=[value])
    parsed = hive.Hive(builder.build(root))
    assert parsed.root().value("Big").text == str(2**40)


def test_a_binary_value_falls_back_to_hex():
    builder = HiveBuilder()
    value = builder.value("Blob", hive.REG_BINARY, bytes(range(8)))
    root = builder.key("ROOT", values=[value])
    parsed = hive.Hive(builder.build(root))
    assert parsed.root().value("Blob").text == "0001020304050607"


def test_walking_yields_every_key_with_its_path():
    parsed = hive.Hive(simple_hive())
    paths = [path for path, _ in parsed.walk()]
    assert r"Microsoft\Windows\CurrentVersion\Run" in paths


def test_a_cell_offset_outside_the_file_is_refused():
    parsed = hive.Hive(simple_hive())
    with pytest.raises(hive.HiveError, match="outside the hive"):
        parsed.cell(10_000_000)


def test_an_li_subkey_list_is_followed():
    """The other list flavour: offsets with no hashes."""
    builder = HiveBuilder()
    child = builder.key("Child")
    listing = builder.add(b"li" + (1).to_bytes(2, "little") + struct.pack("<I", child))
    body = bytearray(76)
    body[0:2] = b"nk"
    body[2:4] = (0x0020).to_bytes(2, "little")
    body[20:24] = (1).to_bytes(4, "little")
    body[28:32] = listing.to_bytes(4, "little")
    body[40:44] = (0xFFFFFFFF).to_bytes(4, "little")
    body[48:52] = (0xFFFFFFFF).to_bytes(4, "little")
    body[72:74] = (4).to_bytes(2, "little")
    root = builder.add(bytes(body) + b"ROOT")
    parsed = hive.Hive(builder.build(root))
    assert [key.name for key in parsed.subkeys(parsed.root())] == ["Child"]


# ---------------------------------------------------------------------------
# The boot key
# ---------------------------------------------------------------------------


def system_hive(parts: tuple[str, str, str, str], select: int | None = 1) -> bytes:
    """A SYSTEM hive whose Lsa subkeys carry the boot key in their class names."""
    builder = HiveBuilder()
    lsa_children = [
        builder.key(name, class_name=value)
        for name, value in zip(hive.BOOTKEY_KEYS, parts, strict=True)
    ]
    lsa = builder.key("Lsa", subkeys=lsa_children)
    control = builder.key("Control", subkeys=[lsa])
    control_set = builder.key("ControlSet001", subkeys=[control])
    subkeys = [control_set]
    if select is not None:
        current = builder.value("Current", hive.REG_DWORD, select.to_bytes(4, "little"))
        subkeys.append(builder.key("Select", values=[current]))
    root = builder.key("ROOT", subkeys=subkeys)
    return builder.build(root, "SYSTEM")


def test_the_boot_key_is_assembled_and_unshuffled():
    """The four class names concatenate to 16 bytes, then get permuted."""
    parts = ("00112233", "44556677", "8899aabb", "ccddeeff")
    parsed = hive.Hive(system_hive(parts))
    raw = bytes.fromhex("".join(parts))
    expected = bytes(raw[index] for index in hive.BOOTKEY_PERMUTATION)
    assert hive.boot_key(parsed) == expected


def test_the_boot_key_needs_all_four_class_names():
    parsed = hive.Hive(system_hive(("00112233", "44556677", "8899aabb", "")))
    assert hive.boot_key(parsed) is None


def test_a_class_name_that_is_not_hex_gives_no_boot_key():
    parsed = hive.Hive(system_hive(("zzzzzzzz", "44556677", "8899aabb", "ccddeeff")))
    assert hive.boot_key(parsed) is None


def test_select_current_chooses_the_control_set():
    """`Select\\Current` says which ControlSet is live; 1 means ControlSet001."""
    parsed = hive.Hive(system_hive(("00112233", "44556677", "8899aabb", "ccddeeff"), select=1))
    assert hive.boot_key(parsed) is not None


def test_the_boot_key_is_found_without_a_select_key():
    """A partial hive may have no Select; ControlSet001 is tried anyway."""
    parsed = hive.Hive(system_hive(("00112233", "44556677", "8899aabb", "ccddeeff"), select=None))
    assert hive.boot_key(parsed) is not None


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------


def test_the_report_surfaces_a_run_key():
    report = hive.analyse(simple_hive())
    paths = [path for path, _, _ in report.found]
    assert r"Microsoft\Windows\CurrentVersion\Run" in paths
    values = next(values for path, _, values in report.found if path.endswith("Run"))
    assert any("evil.exe" in line for line in values)


def test_a_system_hive_is_recognised_and_gives_the_boot_key():
    report = hive.analyse(system_hive(("00112233", "44556677", "8899aabb", "ccddeeff")))
    assert report.kind == "SYSTEM"
    assert report.boot_key is not None
    assert any("boot key" in note for note in report.notes)


def test_a_sam_hive_hands_over_rather_than_guessing():
    """ctfc stops before the hash crypto on purpose, and says which tool to use."""
    builder = HiveBuilder()
    names = builder.key("Names", subkeys=[builder.key("Administrator"), builder.key("alice")])
    users = builder.key("Users", subkeys=[names])
    account = builder.key("Account", subkeys=[users])
    domains = builder.key("Domains", subkeys=[account])
    root = builder.key("ROOT", subkeys=[domains])
    report = hive.analyse(builder.build(root, "SAM"))
    assert report.kind == "SAM"
    assert report.users == ["Administrator", "alice"]
    assert any("has not been verified against a" in note for note in report.notes)
    assert any("samdump2" in command for command in report.commands)
