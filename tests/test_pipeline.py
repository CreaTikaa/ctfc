"""Tests for recipes (core/pipeline.py): load, save, run, and failing steps."""

import base64
import json
import subprocess
import sys

import pytest

from ctfc.core import pipeline
from ctfc.core.codegen import Step
from ctfc.core.pipeline import RecipeError

LAYERS = [Step("base64", {}), Step("zlib", {}), Step("xor", {"key": "4b337921"})]


def blob_steps(fixture_bytes) -> list[Step]:
    """The key||iv fixture as one explicit AES-256-CBC step."""
    blob = base64.b64decode(fixture_bytes("key_iv_blob.b64"))
    params = {
        "cipher": "aes",
        "mode": "cbc",
        "key": blob[:32].hex(),
        "iv": blob[32:].hex(),
        "unpad": "pkcs7",
    }
    return [Step("cipher", params)]


def test_layered_fixture_runs_step_by_step(fixture_bytes):
    result = pipeline.run(fixture_bytes("layers_b64_zlib_xor.txt"), LAYERS, "layers")
    assert result.ok
    assert [step.label for step in result.steps][:2] == ["base64", "zlib"]
    assert b"CYBN{" in result.output
    # every step keeps its own intermediate output
    assert result.steps[0].data.startswith(b"x\x9c")
    assert result.steps[-1].data == result.output
    assert result.steps[-1].score > result.steps[0].score
    assert result.notes[0].startswith("chain: base64 -> zlib -> xor")


def test_layered_recipe_exports(fixture_bytes):
    result = pipeline.run(fixture_bytes("layers_b64_zlib_xor.txt"), LAYERS)
    assert result.cyberchef.startswith("From_Base64(")
    assert "Zlib_Inflate(" in result.cyberchef
    assert "zlib.decompress" in result.python


def test_generated_script_reproduces_the_recipe(fixture_bytes, tmp_path):
    data = fixture_bytes("layers_b64_zlib_xor.txt")
    result = pipeline.run(data, LAYERS)
    script = tmp_path / "reproduce.py"
    script.write_text(result.python)
    run = subprocess.run(
        [sys.executable, "-I", str(script)], cwd=tmp_path, capture_output=True, timeout=30
    )
    assert run.returncode == 0, run.stderr.decode()
    assert result.output.decode() in run.stdout.decode()


def test_cipher_step(fixture_bytes):
    result = pipeline.run(fixture_bytes("aes_cbc_keyiv_blob.bin"), blob_steps(fixture_bytes))
    assert result.ok
    assert b"CYBN{fixture_key_iv_blob}" in result.output
    assert result.cyberchef.startswith("AES_Decrypt(")


def test_failing_step_keeps_the_earlier_output(fixture_bytes):
    """zlib on already-inflated data fails: the zlib output must still be there."""
    steps = [Step("base64", {}), Step("zlib", {}), Step("zlib", {})]
    result = pipeline.run(fixture_bytes("layers_b64_zlib_xor.txt"), steps)
    assert not result.ok
    assert len(result.steps) == 3
    assert result.steps[2].error
    assert result.output == result.steps[1].data
    assert any("step 3 (zlib) failed" in note for note in result.notes)
    assert any("output of step 2" in note for note in result.notes)
    # the export only covers the steps that worked
    assert result.python.count("zlib.decompress") == 1


def test_failing_first_step_keeps_the_input():
    result = pipeline.run(b"not base64 at all!!!", [Step("base64", {})])
    assert not result.ok
    assert result.output == b"not base64 at all!!!"
    assert "the input itself" in result.notes[0]
    assert result.python == ""


def test_save_and_load_round_trip(tmp_path):
    path = tmp_path / "r.json"
    pipeline.dump("stage1", LAYERS, path)
    name, steps = pipeline.load(path)
    assert name == "stage1"
    assert steps == LAYERS
    # steps without arguments are written without an "args" key
    assert json.loads(path.read_text())["steps"][0] == {"op": "base64"}


def test_load_accepts_bare_lists_and_names(tmp_path):
    path = tmp_path / "short.json"
    path.write_text('["base64", {"op": "hex"}]')
    name, steps = pipeline.load(path)
    assert name == "short"  # falls back to the file name
    assert [step.name for step in steps] == ["base64", "hex"]


def test_bad_json_says_so(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json")
    with pytest.raises(RecipeError, match="not valid JSON"):
        pipeline.load(path)


def test_missing_file_says_so(tmp_path):
    with pytest.raises(RecipeError, match="cannot read"):
        pipeline.load(tmp_path / "nope.json")


def test_missing_steps_key(tmp_path):
    path = tmp_path / "r.json"
    path.write_text('{"name": "x"}')
    with pytest.raises(RecipeError, match='"steps"'):
        pipeline.load(path)


@pytest.mark.parametrize(
    "raw,message",
    [
        ([{"op": "rot1000"}], "unknown operation 'rot1000'"),
        ([{"op": "xor"}], "xor needs"),
        ([{"op": "cipher", "args": {"cipher": "aes"}}], "cipher needs"),
        ([{"op": "base64_custom"}], "base64_custom needs"),
        ([{"op": "base64", "args": "x"}], '"args" must be an object'),
        ([42], "expected"),
    ],
)
def test_bad_steps_are_explained(raw, message):
    with pytest.raises(RecipeError, match=message):
        pipeline.parse_steps(raw)


def test_unknown_cipher_and_mode_are_step_errors():
    result = pipeline.run(b"x" * 16, [Step("cipher", {"cipher": "enigma", "key": "00"})])
    assert "unknown cipher" in result.steps[0].error
    bad_mode = Step("cipher", {"cipher": "aes", "mode": "xts", "key": "00" * 16})
    result = pipeline.run(b"x" * 16, [bad_mode])
    assert "has no mode" in result.steps[0].error


def test_result_serialises_to_json(fixture_bytes):
    result = pipeline.run(fixture_bytes("layers_b64_zlib_xor.txt"), LAYERS)
    payload = json.loads(json.dumps(result.to_dict()))
    assert payload["ok"] is True
    assert len(payload["steps"]) == 3
    assert "CYBN{" in payload["output_text"]


def run_script(tmp_path, source: str) -> bytes:
    script = tmp_path / "reproduce.py"
    script.write_text(source)
    done = subprocess.run(
        [sys.executable, "-I", str(script)], cwd=tmp_path, capture_output=True, timeout=30
    )
    assert done.returncode == 0, source + "\n" + done.stderr.decode()
    return done.stdout


def test_cipher_step_with_iv_prefix_agrees_with_its_script(fixture_bytes, tmp_path):
    """The recipe and the Python it exports must read iv_from the same way."""
    key = fixture_bytes("aes_cbc_iv_prefix.key").decode().strip()
    step = Step(
        "cipher",
        {"cipher": "aes", "mode": "cbc", "key": key, "iv_from": "prefix", "unpad": "pkcs7"},
    )
    result = pipeline.run(fixture_bytes("aes_cbc_iv_prefix.bin"), [step])
    assert result.ok, result.notes
    assert result.output.startswith(b"CYBN{fixture_iv_prefixed}")
    assert result.cyberchef is None  # an IV read from the data has no recipe
    assert b"CYBN{fixture_iv_prefixed}" in run_script(tmp_path, result.python)


def test_gcm_step_with_nonce_and_tag_in_the_data(fixture_bytes, tmp_path):
    data = fixture_bytes("aes_gcm_nonce_ct_tag.bin")
    key = fixture_bytes("aes_cbc_iv_prefix.key").decode().strip()
    params = {
        "cipher": "aes",
        "mode": "gcm",
        "key": key,
        "iv_from": "prefix",
        "iv_size": 12,
        "tag": data[-16:].hex(),
    }
    result = pipeline.run(data, [Step("cipher", params)])
    assert result.ok, result.notes
    assert result.output == b"CYBN{fixture_gcm_nonce_ct_tag}"
    assert b"CYBN{fixture_gcm_nonce_ct_tag}" in run_script(tmp_path, result.python)


def test_gcm_tag_that_is_not_at_the_end_is_refused(fixture_bytes):
    data = fixture_bytes("aes_gcm_nonce_ct_tag.bin")
    key = fixture_bytes("aes_cbc_iv_prefix.key").decode().strip()
    params = {
        "cipher": "aes",
        "mode": "gcm",
        "key": key,
        "iv_from": "prefix",
        "iv_size": 12,
        "tag": "00" * 16,
    }
    result = pipeline.run(data, [Step("cipher", params)])
    assert "does not end with the tag" in result.steps[0].error


def test_wrong_key_with_pkcs7_is_an_error_not_garbage(fixture_bytes):
    """Like `unpad()` in the exported script: a bad padding stops the recipe."""
    step = Step(
        "cipher",
        {"cipher": "aes", "mode": "cbc", "key": "00" * 32, "iv": "00" * 16, "unpad": "pkcs7"},
    )
    result = pipeline.run(fixture_bytes("aes_cbc_keyiv_blob.bin"), [step])
    assert not result.ok
    assert "invalid PKCS7 padding" in result.steps[0].error


def test_mode_defaults_to_cbc(fixture_bytes):
    blob = base64.b64decode(fixture_bytes("key_iv_blob.b64"))
    step = Step(
        "cipher", {"cipher": "aes", "key": blob[:32].hex(), "iv": blob[32:].hex(), "unpad": "pkcs7"}
    )
    result = pipeline.run(fixture_bytes("aes_cbc_keyiv_blob.bin"), [step])
    assert result.ok
    assert result.steps[0].step.params["mode"] == "cbc"


def test_unknown_cipher_is_refused_when_loading():
    with pytest.raises(RecipeError, match="step 1: unknown cipher"):
        pipeline.parse_steps([{"op": "cipher", "args": {"cipher": "enigma", "key": "00"}}])
