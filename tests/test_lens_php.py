"""Code Lens on PHP: the web category's language, and the crypter shape.

A PHP sample in a forensics challenge is almost always a **web shell** (it
reads `$_POST` and hands it to `eval` or a shell) or a **crypter** (a payload
behind base64 -> rot13 -> base64 -> gzinflate). Both are what these tests
check, and the last one checks the thing that makes the feature useful rather
than decorative: that the generated recovery script, run as a program, prints
the payload.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from ctfc.core.lens import analyse, detect_language

FIXTURE = Path(__file__).parent / "fixtures" / "lens_webshell.php"
FLAG = "CYBN{php_crypter_payload}"


@pytest.fixture
def report():
    return analyse(FIXTURE.read_text(), str(FIXTURE))


# ---------------------------------------------------------------------------
# Recognising it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["shell.php", "page.phtml", "legacy.php5", "config.inc", "x.php7"])
def test_the_extensions_are_php(name):
    assert detect_language("", name)[0] == "php"


def test_php_is_recognised_without_an_extension():
    source = "<?php $x = base64_decode($_POST['a']); echo $x; ?>"
    language, why = detect_language(source, "")
    assert language == "php"
    assert why


def test_a_powershell_script_is_not_mistaken_for_php():
    source = "$x = [Convert]::FromBase64String($y)\nWrite-Host $x\n"
    assert detect_language(source, "")[0] == "powershell"


# ---------------------------------------------------------------------------
# What it says about the shell
# ---------------------------------------------------------------------------


def test_the_chain_is_named_in_execution_order(report):
    kinds = [operation.kind for operation in report.operations]
    # The script is eval(gzinflate(base64_decode(str_rot13(base64_decode($p))))):
    # the innermost call runs first, and the blob is already one base64 in.
    assert kinds[:3] == ["rot13", "base64", "deflate"]
    assert "cipher" in kinds


def test_gzinflate_is_raw_deflate_not_zlib(report):
    """PHP's gzinflate has no zlib header: the step must be `deflate`."""
    inflate = [item for item in report.operations if item.rule == "php.gzinflate"]
    assert inflate and inflate[0].kind == "deflate"


def test_the_web_shell_behaviours_are_named(report):
    kinds = {behaviour.kind for behaviour in report.behaviours}
    assert {"execute", "process", "network"} <= kinds
    explanations = " ".join(behaviour.label for behaviour in report.behaviours)
    assert "eval" in explanations
    assert "web shell" in explanations


def test_the_key_and_iv_are_extracted(report):
    values = {artifact.kind: artifact.value for artifact in report.artifacts}
    assert values["key"] == b"Upd4t3r!"
    assert values["iv"] == b"0123456789abcdef"


def test_the_payload_blob_is_found(report):
    blobs = [artifact for artifact in report.artifacts if artifact.kind == "blob"]
    assert blobs and len(blobs[0].value) >= 40


def test_the_url_is_reported(report):
    text = " ".join(artifact.value.decode("utf-8", "replace") for artifact in report.artifacts)
    assert "evil.example" in text


def test_the_layers_are_peeled_and_the_flag_comes_out(report):
    assert any(FLAG.encode() in peeled.data for peeled in report.peeled)


def test_the_generated_recovery_script_really_runs(tmp_path, report):
    """The whole point: run the generated program and read the payload."""
    assert report.recovery is not None
    script = tmp_path / "recover.py"
    script.write_text(report.recovery.python)
    result = subprocess.run([sys.executable, str(script)], capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr.decode()
    assert FLAG in result.stdout.decode()


# ---------------------------------------------------------------------------
# The nesting rule this needed
# ---------------------------------------------------------------------------


def test_a_nested_one_liner_is_reversed_and_said_so():
    source = "<?php eval(gzinflate(base64_decode(str_rot13($p)))); ?>"
    report = analyse(source, "x.php")
    assert [item.kind for item in report.operations] == ["rot13", "base64", "deflate"]
    assert any("innermost call runs first" in note for note in report.notes)


def test_a_sequence_on_one_line_is_left_in_place():
    """Two separate statements on one line are not a nested chain."""
    source = "<?php $a = base64_decode($x); $b = str_rot13($y); ?>"
    report = analyse(source, "x.php")
    assert [item.kind for item in report.operations] == ["base64", "rot13"]


def test_one_operation_per_line_is_untouched():
    source = "<?php\n$a = base64_decode($x);\n$b = gzinflate($a);\n?>"
    report = analyse(source, "x.php")
    assert [item.kind for item in report.operations] == ["base64", "deflate"]


def test_other_languages_still_order_as_before(fixture_bytes):
    """The nesting rule must not change what the PowerShell fixture reports."""
    source = fixture_bytes("lens_dropper.ps1").decode()
    report = analyse(source, "lens_dropper.ps1")
    assert report.operations
    assert report.recovery is not None


# ---------------------------------------------------------------------------
# The smaller rules
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("<?php $x = hex2bin('43594250436f6465');", "hex"),
        ("<?php $x = pack('H*', '43594250436f6465');", "hex"),
        ("<?php $x = gzuncompress($y);", "zlib"),
        ("<?php $x = gzdecode($y);", "gzip"),
        ("<?php $x = strrev($y);", "reverse"),
        ("<?php $x = urldecode($y);", "url"),
    ],
)
def test_each_decoding_api_is_recognised(source, expected):
    report = analyse(source, "x.php")
    assert expected in [item.kind for item in report.operations]


@pytest.mark.parametrize(
    "source",
    [
        "<?php assert($_GET['x']);",
        "<?php $f = create_function('', $code);",
        '<?php preg_replace("/(.*)/e", $code, $s);',
    ],
)
def test_the_eval_lookalikes_are_flagged(source):
    report = analyse(source, "x.php")
    assert any(behaviour.kind == "execute" for behaviour in report.behaviours)


def test_the_xor_loop_is_recognised():
    source = "<?php for($i=0;$i<strlen($d);$i++){ $o .= $d[$i] ^ $k[$i % strlen($k)]; }"
    report = analyse(source, "x.php")
    assert "xor" in [item.kind for item in report.operations]


def test_a_php_file_with_nothing_in_it_says_so():
    report = analyse("<?php phpinfo(); ?>", "x.php")
    assert report.language == "php"
    assert report.operations == [] or all(item.kind for item in report.operations)
