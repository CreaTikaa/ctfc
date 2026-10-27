"""Hash identification tests.

ctfc does not crack hashes, it recognises them and prints the right command, so
the tests check exactly that: the format, the hashcat mode, and the honesty of
the confidence (32 hex characters must *not* be announced as "definitely MD5").
"""

import hashlib

import pytest

from ctfc.core.hashes import identify, load_formats


def ids_of(report) -> list[str]:
    return [match.format.id for match in report.matches]


# ---------------------------------------------------------------------------
# The table itself
# ---------------------------------------------------------------------------


def test_every_format_is_well_formed():
    seen = set()
    for candidate in load_formats():
        assert candidate.id not in seen, f"duplicate id {candidate.id}"
        seen.add(candidate.id)
        assert candidate.name, candidate.id
        assert 0 < candidate.confidence <= 1, candidate.id
        assert candidate.hashcat is not None or candidate.john, candidate.id
        # Each row must be recognisable by something.
        assert candidate.prefix or candidate.regex or candidate.length, candidate.id


def test_every_example_is_recognised_as_its_own_format():
    """The example in the table must match the row it belongs to.

    This is the test that catches a typo in a regex: an example that no longer
    matches its own rule would silently stop identifying real hashes.
    """
    for candidate in load_formats():
        if not candidate.example:
            continue
        report = identify(candidate.example, try_passwords=False)
        assert candidate.id in ids_of(report), (
            f"{candidate.id}: its own example {candidate.example[:40]!r} is not matched"
        )


def test_commands_are_ready_to_run():
    for candidate in load_formats():
        command = candidate.hashcat_command("h.txt")
        if command is not None:
            assert command.startswith(f"hashcat -m {candidate.hashcat} ")
            assert "h.txt" in command
        john = candidate.john_command("h.txt")
        if john is not None:
            assert john.startswith(f"john --format={candidate.john}")


# ---------------------------------------------------------------------------
# Identification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("5f4dcc3b5aa765d61d8327deb882cf99", "md5"),
        ("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", "sha1"),
        ("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", "sha224"),
        ("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "sha256"),
        ("$2y$10$3FsIFkRaKqDvx3s9zfkcAeNvYZ.mN8W1FbGn2m7ql0BBx1HKMiMVO", "bcrypt"),
        ("$1$salt1234$ABCDEFGHIJKLMNOPQRSTU.", "md5crypt"),
        ("$apr1$salt1234$ABCDEFGHIJKLMNOPQRSTU.", "apr1"),
        ("{SSHA}abcdefghijklmnopqrstuvwxyz0123456789AB", "ssha"),
        ("pbkdf2_sha256$260000$saltsalt$aGFzaGhhc2hoYXNoaGFzaA==", "django_pbkdf2"),
        ("aad3b435b51404ee", "lm"),
    ],
)
def test_identifies_the_right_format(value, expected):
    report = identify(value, try_passwords=False)
    assert ids_of(report)[0] == expected, ids_of(report)


def test_mysqlna_fixture(fixture_bytes):
    """The MySQL native-auth hash CLAUDE.md asks for: sniffed from a pcap."""
    report = identify(fixture_bytes("mysqlna_hash.txt").decode().strip(), try_passwords=False)
    best = report.matches[0]
    assert best.format.id == "mysqlna"
    assert best.format.hashcat == 11200
    assert best.confidence > 0.95
    assert "hashcat -m 11200" in best.format.hashcat_command()


def test_jwt_fixture_points_at_the_decoding(fixture_bytes):
    report = identify(fixture_bytes("jwt.txt").decode().strip(), try_passwords=False)
    assert report.matches[0].format.id == "jwt"
    assert "not encrypted" in report.matches[0].format.notes


def test_netntlmv2_shape():
    value = "user::DOMAIN:1122334455667788:1234567890abcdef1234567890abcdef:0101000000"
    report = identify(value, try_passwords=False)
    assert report.matches[0].format.id == "netntlmv2"


def test_ambiguous_length_lists_every_candidate():
    """32 hex characters is md5, NTLM and md4: say so instead of guessing."""
    report = identify("8846f7eaee8fb117ad06bdd830b7586c", try_passwords=False)
    assert {"md5", "ntlm", "md4"} <= set(ids_of(report))
    assert report.matches[0].confidence < 0.6, "no format may claim certainty here"
    assert any("cannot tell them apart" in note for note in report.notes)


def test_unknown_string_says_what_to_try():
    report = identify("this is not a hash", try_passwords=False)
    assert not report.matches
    assert any("ctfc detect" in note for note in report.notes)


def test_empty_input():
    report = identify("   ", try_passwords=False)
    assert not report.matches and any("empty" in note for note in report.notes)


def test_facts_describe_the_string():
    facts = dict(identify("$6$salt$hash", try_passwords=False).facts)
    assert facts["length"] == "12 characters"
    assert "$ fields" in facts


# ---------------------------------------------------------------------------
# The free offline try
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "algorithm,password",
    [("md5", b"password123"), ("sha1", b"letmein"), ("sha256", b"infected")],
)
def test_embedded_password_list_cracks_unsalted_hashes(algorithm, password):
    digest = hashlib.new(algorithm, password).hexdigest()
    report = identify(digest)
    best = report.matches[0]
    assert best.cracked == password.decode()
    assert best.confidence == 1.0
    assert any("cracked offline" in note for note in report.notes)


def test_ntlm_is_cracked_as_utf16():
    """NTLM is md4 of the UTF-16LE password: the list try must do that encoding."""
    try:
        digest = hashlib.new("md4", "password123".encode("utf-16-le")).hexdigest()
    except ValueError:
        pytest.skip("this OpenSSL build has no md4")
    report = identify(digest)
    cracked = [match for match in report.matches if match.cracked]
    assert cracked and cracked[0].format.id == "ntlm"


def test_password_list_is_not_tried_on_salted_formats():
    """A salted format cannot be tested one hash at a time: leave it to hashcat."""
    report = identify("$6$saltsalt$" + "a" * 86)
    assert report.matches[0].format.id == "sha512crypt"
    assert all(match.cracked is None for match in report.matches)


def test_no_passwords_flag_skips_the_try():
    digest = hashlib.md5(b"password123").hexdigest()
    assert identify(digest, try_passwords=False).matches[0].cracked is None
    assert identify(digest, try_passwords=True).matches[0].cracked == "password123"
