"""Tests for ctfc.config."""

import pytest

from ctfc.config import DEFAULT_FLAG_REGEXES, ConfigError, load_config


def test_defaults_when_file_missing(tmp_path):
    config = load_config(tmp_path / "nope.toml")
    assert config.offline is False
    assert config.flag_regexes == DEFAULT_FLAG_REGEXES
    assert "CYBN{" in config.flag_prefixes


def test_user_regexes_are_added(tmp_path):
    path = tmp_path / "config.toml"
    # TOML 'literal strings' keep backslashes as-is, like Python raw strings.
    path.write_text(r"offline = true" "\n" r"flag_regexes = ['BZHCTF\{.*?\}']" "\nfoo = 1\n")
    config = load_config(path)
    assert config.offline is True
    assert config.flag_regexes[: len(DEFAULT_FLAG_REGEXES)] == DEFAULT_FLAG_REGEXES
    assert r"BZHCTF\{.*?\}" in config.flag_regexes
    assert any("foo" in w for w in config.warnings)


def test_bad_type_is_an_error(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('offline = "yes"\n')
    with pytest.raises(ConfigError, match="offline"):
        load_config(path)


def test_bad_regex_is_an_error(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text("flag_regexes = ['(unclosed']\n")
    with pytest.raises(ConfigError, match="invalid"):
        load_config(path)
