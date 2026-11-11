"""Run the commands of `docs/HANDOFF.md` section 7 and fail if any of them breaks.

That list is the demo: "here is what the tool does, try it". It was checked by
hand, which means it was checked when someone remembered. This script runs it.

Each entry is a command plus what proves it worked - the exit code it should
return and, where there is one, a string that must appear in the output (a
flag, a verdict, a recovered password). A command that needs something this
machine may not have (a .git folder, a .NET install, mingw) is listed at the
bottom and skipped with its reason printed, never silently.

    make demo            run everything
    make demo ARGS=-v    print each command's output as well

Nothing here writes outside a temporary folder, and nothing reaches the network.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = "tests/fixtures"


@dataclass
class Demo:
    """One command, and what proves it worked."""

    args: list[str]
    expect: str = ""  # a string the output must contain
    code: int = 0  # the exit code it should return
    why: str = ""  # what it demonstrates, for the listing
    needs: list[Path] = field(default_factory=list)  # files that must exist


def f(name: str) -> str:
    return f"{FIXTURES}/{name}"


def commands(scratch: Path) -> list[Demo]:
    """The demo list. One line per thing the tool can do."""
    out = scratch / "out"
    return [
        # --- the two commands that run the whole decision tree ---------------
        Demo(["solve", f("archive_lzma.7z")], "CYBN{sevenzip_lzma}", why="solve: a 7z"),
        Demo(["solve", f("audit_macro.docm")], "CYBN{fixture_vba_macro}", why="solve: a macro"),
        Demo(["solve", f("audit_malicious.pdf")], "CYBN{", why="solve: a PDF"),
        Demo(
            ["solve", f("hunt_dns_tunnel.pcap")],
            "CYBN{dns_tunn3l_in_cl34r}",
            why="solve: DNS tunnel, hex",
        ),
        Demo(
            ["solve", f("hunt_split_flag.zip")],
            "CYBN{h4lf_0n3_4nd_h4lf_tw0!}",
            why="solve: two halves",
        ),
        Demo(
            ["solve", f("hunt_two_stage.ps1")],
            "CYBN{st4g3_tw0_r3v3rs3d_b64}",
            why="solve: reversed stage 2",
        ),
        Demo(["solve", f("hunt_utf16.bin")], "CYBN{wid3_ch4r_fl4g}", why="solve: UTF-16 flag"),
        Demo(["solve", f("gpp_groups.xml")], "CYBN{gpp_pub1ished_k3y}", why="solve: GPP cpassword"),
        Demo(["solve", f("compressed_flag.tar.gz")], "CYBN{flag_in_a_tar_gz}", why="solve: tar.gz"),
        Demo(
            ["solve", f("fiveview_http.pcap")], "CYBN{fiveview_capture}", why="solve: 5View capture"
        ),
        Demo(
            ["solve", f("dns_literal.pcap")],
            "CYBN{literal_dns_name}",
            why="solve: literal DNS name",
        ),
        Demo(["solve", f("usb_typed.pcap")], "CYBN{ll_held_keys}", why="solve: USB keystrokes"),
        Demo(["solve", f("wifi_open.pcap")], "CYBN{open_wifi_flag}", why="solve: open 802.11"),
        Demo(["pcap", f("wifi_wpa.pcap")], "hashcat -m 22000", why="pcap: WPA handshake"),
        Demo(
            ["solve", f("corrupt_magic.pcap")],
            "CYBN{fixture_pcap_http}",
            why="solve: recovered pcap magic",
        ),
        Demo(
            ["solve", f("iso_flag.iso")],
            "CYBN{iso_9660_reader}",
            why="solve: file inside an ISO",
        ),
        Demo(
            ["disk", f("disk_fat12.img")],
            "CYBN{deleted_but_recovered}",
            why="disk: recover a deleted file (needs TSK)",
            needs=[Path("/usr/bin/fls")],
        ),
        Demo(
            ["solve", f("disk_fat12.img")],
            "CYBN{fat12_disk_reader}",
            why="solve: a file in a disk image",
        ),
        Demo(["timeline", f("winartifact_dropper.lnk")], "shortcut target", why="timeline: a .lnk"),
        Demo(
            ["timeline", FIXTURES, "--no-filesystem"],
            "event log record",
            why="timeline: a folder",
        ),
        # --- encodings and chains --------------------------------------------
        Demo(["auto", f("layers_b64_zlib_hex.txt"), "--show-code"], "CYBN{", why="base64+zlib+hex"),
        Demo(["auto", f("longtail_base45.txt")], "CYBN{", why="RFC 9285 base45"),
        # Morse has no braces, so the flag arrives as CYBNFLAG IN MORSE CODE.
        Demo(["auto", f("longtail_morse.txt")], "CYBNFLAG", why="Morse"),
        Demo(["auto", f("longtail_uu.txt")], "CYBN{", why="uuencode"),
        Demo(["auto", f("audit_message.pb")], "CYBN{", why="a protobuf message"),
        Demo(["auto", f("audit_evtx_dropper.evtx")], "CYBN{", why="UTF-16 -enc in a log"),
        Demo(["detect", f("png_with_zip.png")], "polyglot", why="a PNG with a ZIP behind it"),
        # --- XOR and symmetric ------------------------------------------------
        Demo(["xor", f("xor_two_layers.bin")], "CYBN{", why="two XOR layers"),
        Demo(
            ["blob", f("key_iv_blob.b64"), "--against", f("aes_cbc_keyiv_blob.bin")],
            "CYBN{",
            why="a 48-byte key||iv blob",
        ),
        Demo(["sym", f("openssl_salted_pbkdf2.bin"), "--passwords"], "CYBN{", why="openssl enc"),
        Demo(["sym", f("xtea_cbc.bin"), "--pass", "tiny", "--cipher", "xtea"], "CYBN{", why="XTEA"),
        # --- the folder-wide commands ----------------------------------------
        Demo(["scan", FIXTURES, "--min-interest", "0.9"], "CYBN{", why="rank a folder"),
        Demo(["keys", f("memdump_aes.bin"), "--against", f("memdump_aes_ct.bin")], "CYBN{"),
        # --- code lens --------------------------------------------------------
        Demo(["lens", f("lens_dropper.ps1"), "--show-code"], "AES", why="a PowerShell dropper"),
        Demo(["lens", f("lens_layers.py")], "base64", why="layered Python"),
        Demo(["lens", f("lens_webshell.php")], "CYBN{", why="a PHP web shell"),
        Demo(
            [
                "lens",
                f("writeup_cave_ransom.ps1"),
                "--against",
                f("writeup_cave_map.pdf.secured"),
            ],
            "CYBN{",
            why="mirror the encryptor on its own output",
        ),
        # --- RSA, hashes, JWT -------------------------------------------------
        Demo(
            ["rsa", "--key", f("rsa_fermat.pub.pem"), "--decrypt", f("rsa_fermat.bin"), "--attack"],
            "CYBN{",
            why="Fermat",
        ),
        Demo(
            ["rsa", "--key", f("rsa_private.pem"), "--check", f("rsa_public.pem")],
            "same modulus",
        ),
        Demo(["hash", "482c811da5d5b4bc6d497ffa98491e38"], "hashcat", why="identify + crack"),
        Demo(["crc", "27d829b4"], "dragon", why="CRC32 run backwards"),
        # --- file formats -----------------------------------------------------
        Demo(["pcap", f("capture.pcap")], "CYBN{", why="a capture"),
        Demo(["pcap", f("audit_radius.pcap")], "CYBN{", why="RADIUS PAP"),
        Demo(["pcap", f("audit_usb_keyboard.pcap")], "CYBN{", why="USB keystrokes"),
        Demo(["pcap", f("audit_mail_imap.pcap")], "CYBN{", why="IMAP + attachment"),
        Demo(["mail", f("mailfile_message.eml")], "CYBN{", why="an .eml on disk"),
        Demo(["office", f("audit_macro.doc")], "CYBN{", why="a .doc macro"),
        Demo(["pdf", f("audit_malicious.pdf")], "CYBN{", why="three flags in a PDF"),
        Demo(["stego", f("audit_lsb.png"), "--show-code"], "CYBN{", why="LSB"),
        Demo(["stego", f("exif_photo.jpg")], "CYBN{", why="EXIF + GPS"),
        Demo(["stego", f("audio_lsb.wav")], "CYBN{", why="LSB in a WAV"),
        Demo(["sqlite", f("audit_notes.sqlite")], "CYBN{", why="deleted rows"),
        Demo(["zip", f("audit_zipcrypto.zip")], "bkcrack", why="ZipCrypto"),
        Demo(["archive", f("archive_encoded_header.7z")], "CYBN{", why="7z encoded header"),
        Demo(["archive", f("archive_aes.7z")], "7z2john", why="7z AES: hand over"),
        Demo(["archive", f("archive_mszip.cab")], "CYBN{", why="a cabinet"),
        Demo(["archive", f("archive_appended.tar")], "CYBN{", why="past the end marker"),
        Demo(["archive", f("archive_docker_image.tar")], "CYBN{", why="Docker layers"),
        Demo(["msg", f("compound_message.msg")], "CYBN{", why="an Outlook message"),
        Demo(["msi", f("compound_installer.msi")], "CYBN{", why="an installer"),
        Demo(["winartifact", f("winartifact_powershell.pf")], "run", why="prefetch"),
        Demo(
            ["winartifact", f("winartifact_jumplist.automaticDestinations-ms")],
            "CYBN_jumplist",
            why="a jump list: the paths of what was opened",
        ),
        Demo(["exe", f("executable_secret.jar")], "CYBN{", why="a JAR's constant pools"),
        Demo(["exe", f("executable_app.dex")], "CYBN{", why="a DEX string table"),
        Demo(["evtx", f("audit_security.evtx")], "CYBN{", why="an event log"),
        Demo(["repair", f("png_with_zip.png")], "carved", why="carve what follows"),
        Demo(["classical", f("classical_beaufort.txt")], "CYBN{", why="Beaufort, key blind"),
        Demo(["classical", "text:PLOA{fvzcyr_fuvsg}"], "simple", why="ROT13"),
        Demo(["time", "133476575820000000"], "FILETIME", why="read a timestamp"),
        Demo(["tools", f("audit_zipcrypto.zip")], "bkcrack", why="the tool bridge"),
        Demo(["cheatsheet"], "cheat sheet", why="the decision tree"),
        # --- the ones that write somewhere -----------------------------------
        Demo(["pcap", f("capture.pcap"), "--extract", str(out / "objs")], "ctfc scan"),
        Demo(["scan", str(out / "objs")], "CYBN{", why="then scan what came out"),
        Demo(["pdf", f("audit_malicious.pdf"), "--extract", str(out / "pdf")], "CYBN{"),
        Demo(["mail", f("mailfile_message.eml"), "--extract", str(out / "mail")], "wrote"),
        Demo(["watch", str(out / "objs"), "--once"], "CYBN{", why="triage a folder once"),
        # --- a real file from this machine, when it is there ------------------
        Demo(["exe", "/bin/ls"], "elf", why="a real ELF", needs=[Path("/bin/ls")]),
    ]


def run(demo: Demo, verbose: bool) -> tuple[bool, str]:
    """Run one command and say whether it did what it is supposed to."""
    result = subprocess.run(
        [sys.executable, "-m", "ctfc", *demo.args],
        cwd=ROOT,
        capture_output=True,
        timeout=180,
    )
    output = (result.stdout + result.stderr).decode("utf-8", "replace")
    if verbose:
        print(output)
    if result.returncode != demo.code:
        return False, f"exit {result.returncode}, expected {demo.code}"
    if demo.expect and demo.expect not in output:
        return False, f"{demo.expect!r} not in the output"
    return True, ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-v", "--verbose", action="store_true", help="print each output")
    parser.add_argument("-k", help="only the commands whose text contains this")
    args = parser.parse_args()

    scratch = Path(tempfile.mkdtemp(prefix="ctfc-demo-"))
    failures: list[tuple[Demo, str]] = []
    skipped: list[tuple[Demo, str]] = []
    ran = 0
    try:
        for demo in commands(scratch):
            line = "ctfc " + " ".join(demo.args)
            if args.k and args.k not in line:
                continue
            missing = [str(path) for path in demo.needs if not path.exists()]
            if missing:
                skipped.append((demo, f"needs {', '.join(missing)}"))
                print(f"SKIP  {line}\n      ({skipped[-1][1]})")
                continue
            ok, why = run(demo, args.verbose)
            ran += 1
            mark = "ok  " if ok else "FAIL"
            print(f"{mark}  {line}" + (f"   <- {why}" if why else ""))
            if not ok:
                failures.append((demo, why))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    print(f"\n{ran} command(s) run, {len(failures)} failed, {len(skipped)} skipped")
    for demo, why in failures:
        print(f"  FAILED: ctfc {' '.join(demo.args)}   ({why})")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
