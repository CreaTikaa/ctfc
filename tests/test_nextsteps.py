"""Next steps: when `ctfc solve` finds no flag, say what was found and what to run.

Each test builds the shape of a challenge ctfc cannot finish on its own (a
spectrogram WAV, a JPEG with steghide, a WPA capture, an encrypted blob...) and
checks that the advice names the right tools, with the right file in the
command. The table itself (data/leads.toml) is checked for typos: every tool id
must exist in tools.toml and every ctfc command must be a real subcommand.
"""

from __future__ import annotations

import io
import os
import struct
import wave
import zlib
from pathlib import Path

import pytest

from ctfc.config import ConfigError, find_wordlist, load_config
from ctfc.core import nextsteps, tools
from ctfc.core.repair import byte_order, repair, swap_words
from ctfc.core.solve import solve

FIXTURES = Path(__file__).parent / "fixtures"


def wav_of(seconds: float = 0.2, rate: int = 8000) -> bytes:
    """A WAV of a plain 440 Hz-ish square tone: nothing hidden in its low bits."""
    out = io.BytesIO()
    with wave.open(out, "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(rate)
        frames = int(seconds * rate)
        samples = [8000 if (index // 9) % 2 else -8000 for index in range(frames)]
        handle.writeframes(struct.pack(f"<{frames}h", *samples))
    return out.getvalue()


def png_of(width: int = 16, height: int = 16) -> bytes:
    """A flat grey PNG: a valid image with nothing in its low bits."""

    def chunk(kind: bytes, body: bytes) -> bytes:
        crc = zlib.crc32(kind + body) & 0xFFFFFFFF
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", crc)

    raw = b"".join(b"\x00" + b"\x80\x80\x80" * width for _ in range(height))
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def jpeg_of() -> bytes:
    """Enough of a JPEG to be recognised: SOI + JFIF APP0 + filler + EOI."""
    app0 = b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    return b"\xff\xd8" + app0 + bytes(range(256)) * 4 + b"\xff\xd9"


def rules_of(report) -> list[str]:
    return [step.rule for step in report.next_steps]


def step_for(report, rule: str) -> nextsteps.NextStep:
    for step in report.next_steps:
        if step.rule == rule:
            return step
    raise AssertionError(f"no {rule!r} step in {rules_of(report)}")


# ---------------------------------------------------------------------------
# The table itself
# ---------------------------------------------------------------------------


def test_every_tool_id_in_the_table_exists():
    known = {tool.id for tool in tools.load_tools()}
    for rule in nextsteps.load_rules():
        missing = [tool_id for tool_id in rule.tools if tool_id not in known]
        assert not missing, f"leads.toml rule {rule.id!r} names unknown tools {missing}"


def test_every_ctfc_command_in_the_table_is_a_real_subcommand():
    from ctfc.cli import build_parser

    parser = build_parser()
    subcommands = next(
        action for action in parser._actions if action.__class__.__name__ == "_SubParsersAction"
    ).choices
    for rule in nextsteps.load_rules():
        for command in rule.ctfc:
            words = command.split()
            assert words[0] == "ctfc", command
            assert words[1] in subcommands, f"{rule.id}: no `ctfc {words[1]}`"


def test_rule_ids_are_unique_and_every_rule_has_a_trigger():
    rules = nextsteps.load_rules()
    ids = [rule.id for rule in rules]
    assert len(ids) == len(set(ids))
    for rule in rules:
        assert rule.when, rule.id
        assert rule.meaning and rule.found, rule.id
        assert 0 < rule.weight <= 1, rule.id


def test_gui_tools_are_never_run():
    audacity = tools.tool_by_id("audacity")
    assert audacity.gui
    result = tools.run_tool(audacity, {"input": "/tmp/x.wav"})
    assert "opens a window" in result.error


# ---------------------------------------------------------------------------
# Each challenge shape gets the right advice
# ---------------------------------------------------------------------------


def test_a_plain_wav_points_at_the_spectrogram_and_morse():
    report = solve(wav_of(), "song.wav")
    assert report.flags == []
    step = step_for(report, "audio")
    ids = [tool.tool.id for tool in step.tools]
    assert ids[:2] == ["sox_spectrogram", "multimon_morse"]
    spectrogram = step.tools[0]
    assert spectrogram.command[:2] == ["sox", "song.wav"]  # the real file, filled in
    assert "spectrogram" in spectrogram.command
    assert "video" not in rules_of(report)  # a WAV is RIFF, but not a video


def test_a_png_with_nothing_in_its_low_bits_points_at_zsteg_and_stegsolve():
    report = solve(png_of(), "image.png")
    step = step_for(report, "image.lossless")
    ids = [tool.tool.id for tool in step.tools]
    assert "zsteg" in ids and "stegsolve" in ids
    assert "ctfc repair image.png" in step.ctfc


def test_a_jpeg_points_at_steghide_and_is_not_called_broken():
    report = solve(jpeg_of(), "photo.jpg")
    rules = rules_of(report)
    assert "image.jpeg" in rules
    assert "reader.failed" not in rules  # no EXIF block is normal for a JPEG
    ids = [tool.tool.id for tool in step_for(report, "image.jpeg").tools]
    assert ids[0] == "steghide_empty" and "stegseek" in ids


def test_random_bytes_are_called_encrypted_and_point_at_the_key_hunt():
    blob = os.urandom(4096)
    report = solve(blob, "secret.bin")
    step = step_for(report, "encrypted.blob")
    assert "ctfc sym secret.bin" in step.ctfc
    assert any("workspace" in command for command in step.ctfc)
    assert "unknown" not in rules_of(report)  # the specific rule wins


def test_a_wpa_capture_points_at_aircrack_with_the_wordlist():
    data = (FIXTURES / "wifi_wpa.pcap").read_bytes()
    report = solve(data, "wifi.pcap", wordlist="/wl/rockyou.txt")
    step = step_for(report, "pcap.wpa")
    assert report.next_steps[0].rule == "pcap.wpa"  # the most specific first
    aircrack = step.tools[0]
    assert aircrack.command == ["aircrack-ng", "-w", "/wl/rockyou.txt", "wifi.pcap"]
    assert "pcap" not in rules_of(report)  # the generic capture advice is redundant


def test_a_byte_swapped_jpeg_is_put_back_and_then_advised_on():
    swapped = swap_words(jpeg_of() + b"\x00" * 2, 4)
    report = solve(swapped, "mystery")
    step = step_for(report, "image.jpeg")
    # The advice is about the repaired piece, with the command that writes it.
    assert step.trail == ["ctfc repair mystery --out out1"]
    assert step.disk.startswith("out1/") and step.disk.endswith(".jpg")
    assert step.on_input is False  # a tool run from the page would see the wrong bytes


def test_no_next_steps_when_the_flag_is_found():
    report = solve(b"look: CYBN{next_steps_are_not_needed}", "flag.txt")
    assert report.flags and report.next_steps == []


def test_offline_drops_the_online_tools():
    report = solve(png_of(), "image.png", offline=True)
    for step in report.next_steps:
        assert all(tool.tool.offline_safe for tool in step.tools), step.rule


def test_the_report_carries_the_steps_in_json():
    import json

    report = solve(wav_of(), "song.wav")
    payload = json.loads(json.dumps(report.to_dict()))
    first = payload["next_steps"][0]
    assert first["rule"] == "audio"
    assert first["tools"][0]["command_line"].startswith("sox song.wav")
    assert first["on_input"] is True


def test_a_note_condition_is_required_when_the_rule_has_one():
    rule = next(rule for rule in nextsteps.load_rules() if rule.id == "pcap.wpa")
    assert not rule.matches({"reader:pcap"}, ["12 TCP streams"])
    assert rule.matches({"reader:pcap"}, ["WPA handshake captured for SecureNet"])


def test_the_same_rule_on_many_pieces_is_one_step():
    seen = [
        nextsteps.observe(png_of(), "a.zip > one.png", "out1/one.png", reader="stego", depth=1),
        nextsteps.observe(png_of(8, 8), "a.zip > two.png", "out1/two.png", reader="stego", depth=1),
    ]
    steps = nextsteps.plan(seen)
    assert [step.rule for step in steps] == ["image.lossless"]
    assert steps[0].also == ["a.zip > two.png"]


# ---------------------------------------------------------------------------
# Byte order (the endianness challenge shape) in `ctfc repair`
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("width", [2, 4, 8])
def test_byte_order_finds_a_file_written_in_swapped_words(width):
    original = png_of()
    original += b"\x00" * (-len(original) % width)
    found = byte_order(swap_words(original, width))
    assert found is not None
    sig, fixed, how = found
    assert sig.ext == "png" and fixed == original and str(width) in how


def test_byte_order_finds_a_file_written_backwards():
    sig, fixed, how = byte_order(jpeg_of()[::-1])
    assert sig.ext == "jpg" and fixed == jpeg_of() and how == "the whole file"


def test_byte_order_leaves_normal_and_random_files_alone():
    assert byte_order(png_of()) is None
    assert byte_order(bytes(range(256)) * 8) is None


def test_repair_hands_the_swapped_file_back_as_a_carved_piece():
    report = repair(swap_words(jpeg_of(), 4))
    assert report.carved and report.carved[0].offset == 0
    assert report.carved[0].data[:3] == b"\xff\xd8\xff"
    assert any("byte order" in note for note in report.notes)


# ---------------------------------------------------------------------------
# Config: the wordlist and the programs behind an alias
# ---------------------------------------------------------------------------


def test_tool_paths_and_wordlist_come_from_the_config(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("password\n")
    config_file = tmp_path / "config.toml"
    config_file.write_text(
        f'wordlist = "{wordlist}"\n[tool_paths]\nvol = ["python3", "/opt/vol/vol.py"]\n'
    )
    config = load_config(config_file)
    assert find_wordlist(config) == str(wordlist)
    assert config.tool_paths == {"vol": ["python3", "/opt/vol/vol.py"]}


def test_a_bad_tool_path_is_a_clear_config_error(tmp_path):
    config_file = tmp_path / "config.toml"
    config_file.write_text("[tool_paths]\nvol = 3\n")
    with pytest.raises(ConfigError, match="tool_paths.vol"):
        load_config(config_file)


def test_a_program_behind_tool_paths_is_shown_with_its_real_command(tmp_path):
    script = tmp_path / "vol.py"
    script.write_text("# stand-in\n")
    paths = {"vol": ["python3", str(script)]}
    assert tools.program_argv("vol", paths) == ["python3", str(script)]
    assert tools.tool_available(tools.tool_by_id("vol_info"), paths)
    seen = nextsteps.observe(b"PAGEDU64" + bytes(4096), "mem.dmp", "mem.dmp")
    steps = nextsteps.plan([seen], tool_paths=paths)
    vol = next(tool for tool in steps[0].tools if tool.tool.id == "vol_info")
    assert vol.command == ["python3", str(script), "-f", "mem.dmp", "windows.info"]
    assert vol.available


def test_cli_prints_the_next_steps(tmp_path):
    from tests.test_cli import run_ctfc

    target = tmp_path / "song.wav"
    target.write_bytes(wav_of())
    result = run_ctfc("solve", str(target))
    out = result.stdout.decode()
    assert "Next steps" in out
    assert "sox" in out and "multimon-ng" in out


# ---------------------------------------------------------------------------
# False advice seen on the public corpus (2026-11-12), each one pinned
# ---------------------------------------------------------------------------


def test_plain_english_and_html_are_not_called_a_classical_cipher():
    """`ctfc detect` said "transposition" on a README and "substitution" on an
    HTTP 301 page: their letter pairs are ordinary, so they are text in clear."""
    from ctfc.core.classical import READABLE_BIGRAMS, bigram_rate
    from ctfc.core.detect import detect

    readme = (
        b"# Just hang, man\n\nA completely regular conversation of two people playing hangman.\n"
    )
    page = (
        b"<html><head><title>301 Moved Permanently</title></head><body><center><h1>301 Moved "
        b"Permanently</h1></center><hr><center>cloudflare</center></body></html>\r\n"
        b"HTTP/1.1 301 Moved Permanently\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n"
    )
    log = (
        b"[2024-01-19 12:59:11] Server listening on 0.0.0.0 port 2221.\n"
        b"[2024-01-28 15:24:23] Connection from 100.72.1.95 port 47721 on port 2221\n"
        b"[2024-01-28 15:24:24] Failed publickey for root from 100.72.1.95 port 47721 ssh2\n"
        b"[2024-01-28 15:24:25] Accepted password for root from 100.72.1.95 port 47721 ssh2\n"
    )
    vba = (
        b'Attribute VB_Name = "ThisDocument"\r\nAttribute VB_Base = "1Normal.ThisDocument"\r\n'
        b"Attribute VB_GlobalNameSpace = False\r\nAttribute VB_Creatable = False\r\n"
        b"Attribute VB_PredeclaredId = True\r\nAttribute VB_Exposed = True\r\n"
    )
    for text in (readme, page, log, vba):
        assert bigram_rate(text) >= READABLE_BIGRAMS
        rules = {guess.rule for guess in detect(text).guesses}
        assert not rules & {"classical.transposition", "classical.monoalphabetic"}
    # ...while the real ciphertexts keep their guesses.
    railfence = (FIXTURES / "classical_railfence.txt").read_bytes()
    assert bigram_rate(railfence) < READABLE_BIGRAMS
    assert "classical.transposition" in {guess.rule for guess in detect(railfence).guesses}


def test_an_mp3_without_an_id3_tag_is_a_sound_not_random_bytes():
    # MPEG-1 Layer III, 128 kbit/s, 44.1 kHz: a frame is 417 bytes.
    frame = b"\xff\xfb\x90\x64" + os.urandom(413)
    seen = nextsteps.observe(frame * 6, "song.mp3", "song.mp3")
    assert "magic:mp3" in seen.facts
    assert "entropy:high" not in seen.facts
    assert [step.rule for step in nextsteps.plan([seen])] == ["audio"]
    # One `ff fb` with no second frame behind it is a coincidence, not an MP3.
    assert "magic:mp3" not in nextsteps.observe(b"\xff\xfb" + os.urandom(900), "x", "x").facts


def test_an_elf_core_file_is_memory_not_a_program():
    core = b"\x7fELF\x02\x01\x01" + bytes(9) + b"\x04\x00\x3e\x00" + bytes(2000)
    seen = nextsteps.observe(core, "dump", "dump", reader="exe")
    rules = [step.rule for step in nextsteps.plan([seen])]
    assert rules[0] == "core" and "executable" not in rules


def test_a_sam_hive_points_at_secretsdump():
    note = "the NT hashes are in this hive but encrypted with the boot key from the SYSTEM hive"
    seen = nextsteps.observe(
        b"regf" + bytes(600), "sam.bak", "sam.bak", reader="hive", notes=[note]
    )
    steps = nextsteps.plan([seen])
    assert [step.rule for step in steps] == ["windows.sam"]  # the generic advice is dropped
    assert steps[0].tools[0].command[:3] == ["secretsdump.py", "-sam", "sam.bak"]


def test_a_zip_that_is_not_encrypted_is_not_called_password_protected():
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("notes.txt", "nothing to see here, just a plain note " * 4)
    report = solve(buffer.getvalue(), "plain.zip")
    assert "encrypted.container" not in rules_of(report)


def test_a_zipcrypto_archive_is_called_password_protected():
    report = solve((FIXTURES / "audit_zipcrypto.zip").read_bytes(), "locked.zip")
    step = step_for(report, "encrypted.container")
    assert any(tool.tool.id == "bkcrack" for tool in step.tools)


def test_an_empty_argument_is_shown_quoted_so_the_copied_command_works():
    """`steghide extract -sf x -p "" -f`: printed as `-p  -f`, a shell would read
    `-f` as the passphrase. The displayed line is shell-quoted."""
    report = solve(jpeg_of(), "photo.jpg")
    steghide = step_for(report, "image.jpeg").tools[0]
    assert steghide.to_dict()["command_line"] == "steghide extract -sf photo.jpg -p '' -f"


def test_a_member_bigger_than_8_mb_is_followed_not_dropped_in_silence():
    """HTB Fake Boost / DUCTF Thats_Not_My_Name: a 22 MB capture in an archive.
    The old 8 MB cap dropped it without a word and solve said "nothing came out"."""
    import zipfile

    big = b"\x00" * (9 * 1024 * 1024) + b"CYBN{big_member_is_read}"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("capture.bin", big)
    report = solve(buffer.getvalue(), "big.zip")
    assert [flag.text for flag in report.flags] == ["CYBN{big_member_is_read}"]


def test_a_member_too_big_to_follow_is_named_in_a_note():
    from ctfc.core import readers

    huge = readers.Child("huge.bin", "test", b"\x00" * (readers.CHILD_MAX_SIZE + 1))
    kept, notes = readers._too_big([huge, readers.Child("small.txt", "test", b"hello")])
    assert [child.name for child in kept] == ["small.txt"]
    assert "huge.bin" in notes[0] and "too big" in notes[0]


def test_a_tls_key_log_says_where_it_goes():
    keylog = b"CLIENT_RANDOM " + b"ab" * 32 + b" " + b"cd" * 48 + b"\n"
    report = solve(keylog * 3, "sslkeylogfile.txt")
    step = step_for(report, "tls.keylog")
    assert any("tls.keylog_file:sslkeylogfile.txt" in text for text in step.by_hand)


def test_an_android_boot_image_and_an_mft_are_named():
    boot = nextsteps.observe(b"ANDROID!" + os.urandom(4096), "boot.img", "boot.img")
    assert "magic:androidboot" in boot.facts and "entropy:high" not in boot.facts
    assert [step.rule for step in nextsteps.plan([boot])] == ["disk"]
    mft = nextsteps.observe(b"FILE0\x00\x03\x00" + bytes(1016), "z.mft", "z.mft")
    assert [step.rule for step in nextsteps.plan([mft])] == ["windows.logs"]


def test_a_png_pdf_polyglot_gets_the_image_advice_too():
    polyglot = png_of() + b"%PDF-1.4\n1 0 obj << >> endobj\ntrailer << >>\n%%EOF\n"
    seen = nextsteps.observe(polyglot, "poly.pdf", "poly.pdf", reader="pdf")
    rules = [step.rule for step in nextsteps.plan([seen])]
    assert "image.lossless" in rules and "pdf" in rules


def test_a_wordlist_of_wrong_passwords_never_crashes_the_zip_cracker():
    """One wrong ZipCrypto password in 256 passes the check byte; the inflater
    then raised zlib.error and `ctfc zip --wordlist rockyou` died. 3000 wrong
    words go through it 10+ times."""
    from ctfc.core import zipinfo

    data = (FIXTURES / "audit_zipcrypto.zip").read_bytes()
    report = zipinfo.analyse(data, "locked.zip")
    words = tuple(f"wrong{index}".encode() for index in range(3000))
    zipinfo.crack_with_wordlist(data, report, words)
    assert report.password in ("", "s3cr3t")


def test_a_hex_value_before_a_brace_is_not_a_flag():
    """DUCTF samiam: "F2B3AF0D{_naWsidNBB1E11E}" in a SAM hive stopped the walk
    as a flag, hiding the SAM advice. A hex number is not a CTF name."""
    from ctfc.core.flags import find_flags

    text = "value F2B3AF0D{_naWsidNBB1E11E} and DEADFACE{real_looking_flag_here}"
    strong = [hit.text for hit in find_flags(text.encode()) if hit.strength > 0.45]
    assert "F2B3AF0D{_naWsidNBB1E11E}" not in strong
    assert "DEADFACE{real_looking_flag_here}" in strong


def test_a_utf16_flag_in_a_big_file_is_still_found_around_its_brace():
    """Above 8 MB the UTF-16 search reads only the bytes around a UTF-16 brace
    (4.5 s -> 0.5 s on a 69 MB capture); a flag there is still found."""
    from ctfc.core.flags import UTF16_FULL_SCAN, hunt

    wide = "CYBN{wide_flag_far_in}".encode("utf-16-le")
    middle = UTF16_FULL_SCAN // 2
    data = b"\x01" * middle + wide + b"\x02" * (UTF16_FULL_SCAN // 2 + 1000)
    assert len(data) > UTF16_FULL_SCAN
    assert "CYBN{wide_flag_far_in}" in [flag.text for flag in hunt(data).flags]


def test_tools_list_works_without_an_input():
    from tests.test_cli import run_ctfc

    result = run_ctfc("tools", "--list")
    assert result.returncode == 0
    assert "sox_spectrogram" in result.stdout.decode()


def test_a_flag_txt_behind_hundreds_of_members_is_still_followed():
    """picoCTF Mob psycho: res/color/flag.txt was member ~700 of an APK, past the
    120-piece cap, and was never looked at. Promising names now go first."""
    import zipfile

    from ctfc.core import readers

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for index in range(300):
            archive.writestr(f"res/drawable/icon_{index}.bin", os.urandom(40))
        archive.writestr("res/color/flag.txt", b"CYBN{".hex() + b"past_the_cap}".hex())
    data = buffer.getvalue()
    opened = readers.open_with("zip", data)
    assert len(opened.children) == readers.CHILD_LIMIT
    assert opened.children[0].name == "res/color/flag.txt"
    assert any("only 120 followed" in note for note in opened.notes)
    report = solve(data, "app.apk")
    assert [flag.text for flag in report.flags] == ["CYBN{past_the_cap}"]


def test_trailing_whitespace_points_at_stegsnow():
    """DUCTF i-love-scomo: the text stegseek pulls out has spaces and tabs at
    the ends of its lines - SNOW, the next layer."""
    lines = [b"Australians all let us rejoice, \t \t", b"For we are young and free;\t  \t"] * 4
    seen = nextsteps.observe(b"\n".join(lines) + b"\n", "secret.txt", "secret.txt")
    assert "kind:whitespace" in seen.facts
    steps = nextsteps.plan([seen])
    assert [step.rule for step in steps] == ["whitespace"]
    assert steps[0].tools[0].command == ["stegsnow", "-C", "secret.txt"]
    plain = nextsteps.observe(b"just a line\nand another one\n" * 4, "a.txt", "a.txt")
    assert "kind:whitespace" not in plain.facts
