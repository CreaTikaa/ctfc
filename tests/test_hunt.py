"""Lot I: the flag one layer down (flags.hunt, fragments, and what solve does with them).

Each shape here comes from a public challenge the 2026-11-11 audit ran ctfc on,
where ctfc had already decoded the bytes holding the flag and never looked
inside them. The fixtures (`hunt_*`) rebuild those shapes with fake flags.
"""

from __future__ import annotations

import base64
import random
from pathlib import Path

import pytest

from ctfc.core import readers
from ctfc.core.auto import auto_decode
from ctfc.core.encodings import reverse_ok
from ctfc.core.flags import (
    WEAK_GENERIC_STRENGTH,
    assemble,
    default_flagset,
    find_flags,
    hunt,
    plain_hits,
)
from ctfc.core.scoring import score
from ctfc.core.solve import embedded_blobs, solve

FIXTURES = Path(__file__).parent / "fixtures"


def texts(hits) -> list[str]:
    return [hit.text for hit in hits]


# --- the deep hunt: one layer down ------------------------------------------


def test_base64_flag_with_an_unknown_prefix_is_decoded():
    # picoCTF "CanYouSee": base64 in metadata, a prefix nobody configured.
    data = b'<rdf:li url="' + base64.b64encode(b"CTF{unkn0wn_pr3fix}") + b'"/>'
    assert find_flags(data) == []  # the cheap search does not decode it...
    found = hunt(data).flags
    assert texts(found) == ["CTF{unkn0wn_pr3fix}"]  # ... the deep one does
    assert found[0].how == "base64"


def test_hex_stream_is_unhexed_and_searched():
    # DUCTF "Thats_Not_My_Name": the flag is in clear in a hex DNS stream.
    junk = bytes(range(200))
    data = (junk + b"CYBN{in_th3_h3x}" + junk).hex().encode()
    found = hunt(data).flags
    assert "CYBN{in_th3_h3x}" in texts(found)
    assert found[0].how == "hex"


def test_reversed_flag_and_reversed_base64_run():
    assert texts(hunt(b"x = '" + b"CYBN{b4ckw4rds}"[::-1] + b"'").flags) == ["CYBN{b4ckw4rds}"]
    blob = base64.b64encode(b"Write-Output 'CYBN{r3v3rs3d_run_0f_b64}'")[::-1]
    found = hunt(b'$s = "' + blob + b'"').flags
    assert texts(found) == ["CYBN{r3v3rs3d_run_0f_b64}"]
    assert found[0].how == "reversed base64"


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be"])
def test_utf16_flag_is_found_and_not_shifted(encoding):
    # GPP cpassword / .NET strings decrypt to UTF-16. The BE pattern also
    # matches inside LE text one byte later ("UCTF{..."): that must not appear.
    noise = bytes(random.Random(1).randrange(1, 256) for _ in range(64))
    data = noise + "DUCTF{w1de_str1ng}".encode(encoding) + noise
    assert texts(find_flags(data)) == ["DUCTF{w1de_str1ng}"]


def test_utf16_hit_scores_as_a_flag():
    # The scorer uses find_flags, so a decrypted UTF-16 plaintext now ranks.
    value, reasons = score("password: CYBN{utf16_pl41n}".encode("utf-16-le"))
    assert value >= 0.8
    assert any("flag" in reason for reason in reasons)


# --- fragments -----------------------------------------------------------------


def test_split_flag_fragments_and_assembly():
    # HTB "It Has Begun": one half backwards in an SSH key comment, the other
    # half in base64 in a crontab line.
    data = (
        b"ssh-rsa AAAAB3Nza user@" + b"CYBN{h4lf_0n3_"[::-1] + b"\n"
        b"* * * * * root sh -c '" + base64.b64encode(b"4nd_tw0!}") + b"'\n"
    )
    found = hunt(data)
    assert found.flags == []
    sides = {(fragment.side, fragment.text) for fragment in found.fragments}
    assert ("open", "CYBN{h4lf_0n3_") in sides
    assert ("close", "4nd_tw0!}") in sides
    assert assemble(found.fragments) == ["CYBN{h4lf_0n3_4nd_tw0!}"]


def test_a_whole_flag_is_not_also_a_fragment():
    found = hunt(b"the flag is CYBN{wh0l3_fl4g} " + base64.b64encode(b"CYBN{wh0l3_fl4g}"))
    assert texts(found.flags) == ["CYBN{wh0l3_fl4g}"]
    assert found.fragments == []


def test_fragments_need_a_flag_shaped_body():
    # Template syntax and ordinary braces are not fragments.
    data = b"${HOME}/bin {Default} if (x) {return_value; } TEMPLATE{name} %{Var} "
    assert hunt(data).fragments == []


def test_assemble_refuses_pieces_that_do_not_make_a_flag():
    found = hunt(b"CYBN{st4rt_0nly " + base64.b64encode(b"x y z}"))
    assert assemble(found.fragments) == []


# --- chance must not pass for a flag -------------------------------------------


def test_random_bytes_yield_no_flag_and_no_fragment():
    rng = random.Random(2026)
    for _ in range(3):
        data = bytes(rng.randrange(256) for _ in range(400_000))
        found = hunt(data)
        assert [hit for hit in found.flags if hit.strength > WEAK_GENERIC_STRENGTH] == []
        assert found.fragments == []


@pytest.mark.parametrize(
    "text",
    [
        "x(F@Kt:@u}8uyd;Bztr K4J{btBs&7p!G}z(>*Jt",  # punctuation soup (HTB Fake Boost)
        "zq7#W1{!Tgxk3b}p0",  # a short body, no underscore, an anonymous prefix
        "\x9a\xe1\xff\x93AB{c4fe_b4be}\xfa\x81\xee\x99",  # a hit between high bytes
    ],
)
def test_chance_hits_are_weak(text):
    hits = plain_hits(text, default_flagset())
    assert hits and all(strength <= WEAK_GENERIC_STRENGTH for _f, strength, _p in hits)


@pytest.mark.parametrize(
    "flag",
    ["HTB{w1ll_y0u_St4nd}", "picoCTF{ME74D47A}", "FLAG{5d41402abc4b2a76b9719d911017c592}"],
)
def test_real_shapes_stay_strong(flag):
    hits = plain_hits(f"note: {flag}\n", default_flagset())
    assert [(found, strength > WEAK_GENERIC_STRENGTH) for found, strength, _p in hits] == [
        (flag, True)
    ]


def test_configured_prefix_is_never_weakened():
    hits = plain_hits("\x9a\xe1\xff\x93CYBN{ab}\xfa\x81\xee\x99", default_flagset())
    assert any(found == "CYBN{ab}" and strength > 0.8 for found, strength, _p in hits)


# --- auto: reversed base64 with no padding ---------------------------------------


def test_reverse_is_offered_for_long_unpadded_base64():
    script = b"Write-Host 'CYBN{n0_p4dd1ng_r3v3rs3d}' ; " * 3
    script += b"#" * (-len(script) % 3)
    blob = base64.b64encode(script)[::-1]
    assert not blob.startswith(b"=")  # the old rule only fired on a leading "="
    assert reverse_ok(blob)
    best = auto_decode(blob, top_n=1)[0]
    assert best.label == "reverse -> base64"
    assert b"CYBN{n0_p4dd1ng_r3v3rs3d}" in best.data


def test_short_base64_is_not_reversed():
    assert not reverse_ok(b"SGVsbG8gd29ybGQ")


# --- solve: embedded blobs and the pcap order ---------------------------------------


def test_embedded_blobs_only_keep_readable_or_known_files():
    stage = b"Write-Output 'next stage, plain readable text right here'"
    text = (
        b'$a = "' + base64.b64encode(stage) + b'"\n'
        b'$b = "' + base64.b64encode(bytes(range(256)) * 2) + b'"\n'
    )
    found = embedded_blobs(text)
    assert [decoded for _label, decoded in found] == [stage]
    assert found[0][0].startswith("base64 string at offset")


def test_pcap_children_put_the_big_dns_tunnel_before_the_noise():
    data = (FIXTURES / "hunt_dns_tunnel.pcap").read_bytes()
    opened = readers.open_with("pcap", data, None, "hunt_dns_tunnel.pcap")
    assert opened.children[0].name == "dns_example_invalid.txt"


@pytest.mark.parametrize(
    "name, flag, how",
    [
        ("hunt_xmp_base64.jpg", "CTF{x1mp_m3tad4ta_b4s364}", "base64"),
        ("hunt_dns_tunnel.pcap", "CYBN{dns_tunn3l_in_cl34r}", "hex"),
        ("hunt_split_flag.zip", "CYBN{h4lf_0n3_4nd_h4lf_tw0!}", "assembled from two fragments"),
        ("hunt_utf16.bin", "CYBN{wid3_ch4r_fl4g}", "utf-16-le"),
        ("hunt_two_stage.ps1", "CYBN{st4g3_tw0_r3v3rs3d_b64}", "assembled from two fragments"),
    ],
)
def test_solve_gets_the_flag_one_layer_down(name, flag, how):
    report = solve((FIXTURES / name).read_bytes(), path=f"tests/fixtures/{name}")
    assert [found.text for found in report.flags] == [flag]
    assert how in report.flags[0].how


def test_solve_does_not_stop_on_a_chance_flag():
    # Before lot I, "K4J{btBs&7p!G}" out of rot13 -> rot47 -> reverse ended the walk.
    report = solve(b"x(F@Kt:@u}8uyd;Bztr K4J{btBs&7p!G}z(>*Jt:saFFAI$=AK$d)!IEDuIp!")
    assert report.flags == []


def test_solve_json_carries_the_fragments():
    data = (FIXTURES / "hunt_split_flag.zip").read_bytes()
    payload = solve(data, path="hunt_split_flag.zip").to_dict()
    assert {fragment["side"] for fragment in payload["fragments"]} == {"open", "close"}
    assert all(fragment["where"] for fragment in payload["fragments"])
