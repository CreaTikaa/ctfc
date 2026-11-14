"""`ctfc config` writes the config back, `ctfc doctor` is the pre-flight check.

The day of the CTF, the flag format has to be set (so a flag stops the walk) and
the tools have to be reachable. These two commands make that a ten-second job
instead of hand-editing TOML, so they are tested: the serialiser must round-trip
through the stdlib reader, and setting a flag must make that flag rate strong.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ctfc import config as C
from ctfc.cli import main
from ctfc.core.flags import build_flagset, rate


def test_flag_to_prefix_and_regex_accepts_the_usual_shapes():
    for given in ("SHARKY{", "SHARKY", "SHARKY{...}"):
        prefix, regex = C.flag_to_prefix_and_regex(given)
        assert prefix == "SHARKY{"
        import re

        assert re.search(regex, "SHARKY{y0u_f0und_me}")
        assert not re.search(regex, "OTHER{nope}")


def test_flag_name_with_odd_characters_is_escaped():
    prefix, regex = C.flag_to_prefix_and_regex("my-ctf.2025{")
    assert prefix == "my-ctf.2025{"
    import re

    assert re.search(regex, "my-ctf.2025{abcd}")


def test_empty_flag_name_is_rejected():
    with pytest.raises(C.ConfigError):
        C.flag_to_prefix_and_regex("{")


def test_dumps_config_round_trips_through_the_reader(tmp_path):
    data = {
        "offline": True,
        "wordlist": "~/rockyou.txt",
        "flag_prefixes": ["SHARKY{"],
        "flag_regexes": [r"SHARKY\{[^}\n]{1,120}\}"],  # backslashes must survive
        "tool_paths": {"vol": ["python3", "/x/vol.py"]},
    }
    path = tmp_path / "config.toml"
    C.write_raw_config(data, path)
    back = C.read_raw_config(path)
    assert back == data
    loaded = C.load_config(path)
    assert loaded.offline is True
    assert "SHARKY{" in loaded.flag_prefixes
    assert loaded.tool_paths == {"vol": ["python3", "/x/vol.py"]}


def test_config_flag_sets_a_prefix_that_rates_strong(tmp_path):
    path = tmp_path / "config.toml"
    # A short, prefix-less body is weak until the CTF's format is configured.
    assert rate("SHARKY{a1b2}") is None or rate("SHARKY{a1b2}") < 0.9
    code = main(["config", "--config", str(path), "--flag", "SHARKY{"])
    assert code == 0
    loaded = C.load_config(path)
    flagset = build_flagset(loaded.flag_regexes, loaded.flag_prefixes)
    assert rate("SHARKY{a1b2}", flagset) >= 0.9


def test_config_preserves_unrelated_keys_when_setting_a_flag(tmp_path):
    path = tmp_path / "config.toml"
    C.write_raw_config({"offline": True, "tool_paths": {"vol": ["python3", "/x/vol.py"]}}, path)
    main(["config", "--config", str(path), "--flag", "ABC{", "--wordlist", "~/rockyou.txt"])
    raw = C.read_raw_config(path)
    assert raw["offline"] is True
    assert raw["tool_paths"] == {"vol": ["python3", "/x/vol.py"]}
    assert raw["flag_prefixes"] == ["ABC{"]
    assert raw["wordlist"] == "~/rockyou.txt"


def test_config_flag_is_idempotent(tmp_path):
    path = tmp_path / "config.toml"
    main(["config", "--config", str(path), "--flag", "ABC{"])
    main(["config", "--config", str(path), "--flag", "ABC{"])
    raw = C.read_raw_config(path)
    assert raw["flag_prefixes"] == ["ABC{"]  # not ["ABC{", "ABC{"]


def test_config_show_runs(tmp_path, capsys):
    path = tmp_path / "config.toml"
    code = main(["config", "--config", str(path)])
    assert code == 0
    out = capsys.readouterr().out
    assert "flag prefixes" in out and "CYBN{" in out


def test_doctor_runs_and_reports(tmp_path, capsys):
    path = tmp_path / "config.toml"
    code = main(["doctor", "--config", str(path)])
    assert code == 0
    out = capsys.readouterr().out
    assert "flag format" in out
    assert "exiftool" in out  # the stego auto-run table
    # With only the default prefix, doctor nudges the user to set the CTF's one.
    assert "XYZ{" in out or "CYBN{" in out


def test_doctor_sees_a_configured_flag_as_ready(tmp_path, capsys):
    path = tmp_path / "config.toml"
    main(["config", "--config", str(path), "--flag", "SHARKY{"])
    capsys.readouterr()  # drop the config output
    main(["doctor", "--config", str(path)])
    out = capsys.readouterr().out
    assert "SHARKY{" in out


def test_default_config_path_is_under_home():
    assert C.DEFAULT_CONFIG_PATH == Path.home() / ".ctfc" / "config.toml"
