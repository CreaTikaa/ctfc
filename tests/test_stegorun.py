"""ctfc runs the installed stego tools and reads their output (core/stegorun.py).

The interpreters are pure: given what a tool printed, they decide flag vs lead.
Those are tested here without a subprocess. One end-to-end test embeds a payload
with the real steghide and checks ctfc extracts the flag, skipped when steghide
is not installed.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from ctfc.core import stegorun
from ctfc.core.flags import default_flagset
from ctfc.core.solve import solve

FLAG = "CYBN{stego_tool_reads_it_back}"


def _ctx(tool: str, stdout: str = "", stderr: str = "", returncode: int = 0,
         outdir: Path | None = None) -> stegorun.RunContext:
    run = stegorun.MediaToolRun()
    return stegorun.RunContext(
        tool=tool,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        infile=Path("input.png"),
        outdir=outdir or Path("/nonexistent"),
        flagset=default_flagset(),
        run=run,
    )


# ---------------------------------------------------------------- scan gating


def test_scan_promotes_a_strong_flag_and_drops_noise():
    ctx = _ctx("zsteg", stdout=f'b1,rgb,lsb,xy       .. text: "{FLAG}"\n')
    stegorun._interpret_zsteg(ctx)
    assert [hit.text for hit in ctx.run.flags] == [FLAG]
    assert ctx.run.flags[0].how.startswith("zsteg")


def test_scan_rejects_a_chance_flag_shape():
    # A short, prefix-less {...} shape zsteg throws up on a noisy channel is not
    # promoted: it stays below the weak-generic bar.
    ctx = _ctx("zsteg", stdout='b2,g,lsb,xy    .. text: "W1{!x}"\n')
    stegorun._interpret_zsteg(ctx)
    assert ctx.run.flags == []


# ---------------------------------------------------------------- zbarimg


def test_zbar_decoded_flag_is_promoted():
    ctx = _ctx("zbarimg", stdout=f"QR-Code:{FLAG}\n")
    stegorun._interpret_zbar(ctx)
    assert [hit.text for hit in ctx.run.flags] == [FLAG]


def test_zbar_decoded_non_flag_becomes_a_lead():
    ctx = _ctx("zbarimg", stdout="QR-Code:https://example.com/next?token=abcdef\n")
    stegorun._interpret_zbar(ctx)
    assert not ctx.run.flags
    assert ctx.run.leads and ctx.run.leads[0].tool == "zbarimg"
    assert "example.com" in ctx.run.leads[0].preview


# ---------------------------------------------------------------- multimon-ng


def test_multimon_transcript_is_a_lead():
    ctx = _ctx("multimon-ng", stderr="MORSE: THE FLAG IS CYBN OPEN BRACE\n")
    stegorun._interpret_multimon(ctx)
    assert ctx.run.leads and ctx.run.leads[0].tool == "multimon-ng"
    assert "MORSE" in ctx.run.leads[0].preview


def test_multimon_silence_yields_nothing():
    ctx = _ctx("multimon-ng", stderr="Enabled demodulators: MORSE_CW\n")
    stegorun._interpret_multimon(ctx)
    assert not ctx.run.leads and not ctx.run.flags


# ---------------------------------------------------------------- steghide payload


def test_steghide_payload_file_is_hunted(tmp_path):
    (tmp_path / "steghide.out").write_bytes(f"here: {FLAG}".encode())
    ctx = _ctx("steghide", returncode=0, outdir=tmp_path)
    stegorun._interpret_steghide(ctx)
    assert [hit.text for hit in ctx.run.flags] == [FLAG]


def test_steghide_nonzero_exit_is_ignored(tmp_path):
    ctx = _ctx("steghide", returncode=1, outdir=tmp_path)
    stegorun._interpret_steghide(ctx)
    assert not ctx.run.flags and not ctx.run.leads


# ---------------------------------------------------------------- applicability


def test_no_tools_run_for_a_non_media_reader():
    run = stegorun.run_media_tools(b"PK\x03\x04", "x.zip", "zip")
    assert run.ran == [] and run.flags == [] and run.leads == []


# ---------------------------------------------------------------- end to end


def _bmp(width: int = 32, height: int = 32) -> bytes:
    row = b"\x20\x40\x60" * width
    row += b"\x00" * ((4 - (len(row) % 4)) % 4)
    pixels = row * height
    size = 54 + len(pixels)
    header = b"BM" + struct.pack("<IHHI", size, 0, 0, 54) + struct.pack(
        "<IiiHHIIiiII", 40, width, height, 1, 24, 0, len(pixels), 2835, 2835, 0, 0
    )
    return header + pixels


@pytest.mark.skipif(shutil.which("steghide") is None, reason="steghide not installed")
def test_steghide_empty_passphrase_is_extracted_end_to_end(tmp_path):
    cover = tmp_path / "cover.bmp"
    cover.write_bytes(_bmp())
    secret = tmp_path / "secret.txt"
    secret.write_text(FLAG)
    embedded = subprocess.run(
        ["steghide", "embed", "-cf", str(cover), "-ef", str(secret), "-p", "", "-f"],
        capture_output=True,
    )
    assert embedded.returncode == 0, embedded.stderr
    report = solve(cover.read_bytes(), "cover.bmp", run_tools=True)
    assert FLAG in [flag.text for flag in report.flags]
    assert any(flag.how.startswith("steghide") for flag in report.flags)


def test_run_tools_off_by_default_leaves_the_walk_pure_python():
    # Without run_tools the stego reader still only *names* the tools (a lead),
    # it does not launch anything - the corpus harness depends on this.
    report = solve(_bmp(), "cover.bmp")
    assert not report.flags
    joined = " ".join(lead.command for lead in report.leads)
    assert "zsteg" in joined or "stegsolve" in joined or "steghide" in joined
