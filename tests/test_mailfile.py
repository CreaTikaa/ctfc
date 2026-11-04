"""`.eml` / `.mbox` on disk, and `--wordlist`.

`core/mail.py` was written for a reassembled capture; these tests cover the
file on disk - the shape a challenge usually hands over - and the fact that
registering it in `core/readers.py` makes it reachable from the Files tab,
`ctfc solve` and `ctfc timeline` at the same time.
"""

from __future__ import annotations

import base64

import pytest

from ctfc.core import mail, readers
from ctfc.core.datafiles import load_wordlist
from ctfc.core.solve import solve

ATTACHED = "CYBN{in_the_attachment}"

EML = (
    b"From: admin@corp.local\r\n"
    b"To: victim@corp.local\r\n"
    b"Subject: backup of the quarter\r\n"
    b"Date: Fri, 17 May 2024 09:30:00 +0000\r\n"
    b"MIME-Version: 1.0\r\n"
    b'Content-Type: multipart/mixed; boundary="xx"\r\n'
    b"\r\n"
    b"--xx\r\n"
    b"Content-Type: text/plain\r\n"
    b"\r\n"
    b"The password is hunter2. Do not share.\r\n"
    b"--xx\r\n"
    b"Content-Type: application/octet-stream\r\n"
    b'Content-Disposition: attachment; filename="flag.txt"\r\n'
    b"Content-Transfer-Encoding: base64\r\n"
    b"\r\n" + base64.b64encode(ATTACHED.encode()) + b"\r\n"
    b"--xx--\r\n"
)


def test_a_plain_eml_is_recognised_and_read():
    assert mail.looks_like_mail(EML)
    messages = mail.read_file(EML)
    assert len(messages) == 1
    message = messages[0]
    assert message.subject == "backup of the quarter"
    assert message.headers["From"] == "admin@corp.local"
    names = [part.filename for part in message.parts]
    assert "flag.txt" in names
    attachment = next(part for part in message.parts if part.filename == "flag.txt")
    assert attachment.data == ATTACHED.encode()


def test_an_mbox_is_split_into_its_messages():
    one = b"From sender@host Fri May 17 09:30:00 2024\r\n" + EML
    two = b"From other@host Sat May 18 10:00:00 2024\r\n" + EML.replace(
        b"Subject: backup of the quarter", b"Subject: second message"
    )
    messages = mail.read_file(one + b"\n" + two)
    subjects = [message.subject for message in messages]
    assert "backup of the quarter" in subjects
    assert "second message" in subjects


def test_a_text_file_that_merely_quotes_a_header_is_not_a_mail():
    assert not mail.looks_like_mail(b"Notes from the meeting\nFrom: nobody, as quoted above\n")
    assert not mail.looks_like_mail(b"")
    assert not mail.looks_like_mail(b"\x00\x01\x02 binary")


# ---------------------------------------------------------------------------
# One registration, four front-ends
# ---------------------------------------------------------------------------


def test_the_reader_registry_claims_it():
    assert readers.sniff(EML) == "mail"


def test_the_parts_come_back_as_children_and_the_date_as_an_event():
    opened = readers.open_with("mail", EML, None, "message.eml")
    origins = {child.name: child.origin for child in opened.children}
    assert "body.txt" in origins
    assert origins["flag.txt"].startswith("attachment")
    assert [event.when for event in opened.events] == ["2024-05-17 09:30:00 UTC"]


def test_solve_walks_into_an_attachment():
    report = solve(EML, "message.eml")
    assert ATTACHED in [flag.text for flag in report.flags]


def test_the_web_tab_renders_it():
    from ctfc.web import formats

    answer = formats.analyse(EML)
    assert answer["reader"] == "mail"
    assert ATTACHED in answer["flags"]


def test_the_password_in_the_body_is_a_workspace_candidate(tmp_path):
    from ctfc.core import workspace
    from ctfc.core.budget import Budget

    (tmp_path / "message.eml").write_bytes(EML)
    report = workspace.analyse(tmp_path, budget=Budget(max_attempts=100_000, max_seconds=10))
    assert "hunter2" in {found.value for found in report.secrets}


# ---------------------------------------------------------------------------
# --wordlist
# ---------------------------------------------------------------------------


def test_a_wordlist_is_read_in_order_without_duplicates(tmp_path):
    path = tmp_path / "list.txt"
    path.write_bytes(b"123456\nhunter2\nhunter2\n\nMonkey99\n")
    words, note = load_wordlist(path)

    assert words == (b"123456", b"hunter2", b"Monkey99")
    assert "3 password(s) used" in note
    assert "duplicates and blanks dropped" in note


def test_the_limit_is_stated_rather_than_silent(tmp_path):
    path = tmp_path / "list.txt"
    path.write_bytes(b"\n".join(f"pw{index}".encode() for index in range(50)))
    words, note = load_wordlist(path, limit=10)

    assert len(words) == 10
    assert "the first 10 unique of 50 line(s)" in note
    assert "hashcat" in note  # the honest hand-over for a real list


def test_a_missing_wordlist_is_an_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_wordlist(tmp_path / "nope.txt")


def test_the_wordlist_replaces_the_embedded_list(tmp_path):
    """A password that is *not* in the embedded 10000 must still be found."""
    import subprocess

    from ctfc.core.budget import Budget
    from ctfc.core.symmetric import solve_symmetric

    password = "Zyx!tr0ub4dor-77"
    target = tmp_path / "vault.enc"
    subprocess.run(
        [
            "openssl",
            "enc",
            "-aes-256-cbc",
            "-pbkdf2",
            "-pass",
            f"pass:{password}",
            "-out",
            str(target),
        ],
        input=b"CYBN{found_with_a_wordlist}\n",
        check=True,
        capture_output=True,
    )
    words = (b"nope", password.encode(), b"later")

    without = solve_symmetric(
        target.read_bytes(), try_passwords=True, budget=Budget(max_seconds=5), top_n=1
    )
    assert not any(candidate.score >= 0.9 for candidate in without.candidates)

    with_list = solve_symmetric(
        target.read_bytes(), passwords=words, budget=Budget(max_seconds=10), top_n=1
    )
    assert with_list.candidates
    assert b"CYBN{found_with_a_wordlist}" in with_list.candidates[0].data
    assert any("from the given list" in note for note in with_list.notes)
