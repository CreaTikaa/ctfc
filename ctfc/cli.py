"""Command line interface. Only parses arguments, calls `ctfc.core`, and displays results.

Each command is one small `cmd_<name>(args, config)` function returning an exit code.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
import tempfile
from pathlib import Path

from rich.console import Console

from ctfc import __version__, render
from ctfc.config import Config, ConfigError, load_config
from ctfc.core import classical, keyhunt, pipeline
from ctfc.core import session as sessions
from ctfc.core import tools as toolbox
from ctfc.core.auto import auto_decode
from ctfc.core.budget import Budget
from ctfc.core.cyberchef import PUBLIC_URL, deep_link
from ctfc.core.detect import detect
from ctfc.core.flags import FlagSet, build_flagset
from ctfc.core.hashes import identify as identify_hash
from ctfc.core.inputs import InputError, parse_input
from ctfc.core.lens import analyse as analyse_script
from ctfc.core.lens_against import mirror_against
from ctfc.core.pcap import PcapError
from ctfc.core.pcap import solve as solve_pcap
from ctfc.core.pipeline import RecipeError
from ctfc.core.report import build_report
from ctfc.core.rsa import RsaError, build_key, keys_match, parse_key, solve_rsa
from ctfc.core.scan import scan as scan_folder
from ctfc.core.symmetric import CryptoError, SolveReport, solve_symmetric
from ctfc.core.types import Input
from ctfc.core.xor import guess_key_lengths, solve_xor, xor_inputs
from ctfc.strings import t

# Commands that exist in the interface but are built in a later milestone.
PLANNED: dict[str, str] = {}


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser with one sub-command per feature."""
    # Options shared by every sub-command, so they can be written after the command name.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help=t("opt_json"))
    common.add_argument("--show-code", action="store_true", help=t("opt_show_code"))
    common.add_argument("--offline", action="store_true", help=t("opt_offline"))
    common.add_argument("--config", type=Path, default=None, help=t("opt_config"))
    common.add_argument("--top", type=int, default=None, help=t("opt_top"))
    common.add_argument("--session", help=t("opt_session"))

    parser = argparse.ArgumentParser(
        prog="ctfc", description=t("app_description"), epilog=t("app_epilog")
    )
    parser.add_argument("--version", action="version", version=f"ctfc {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    def add(name: str) -> argparse.ArgumentParser:
        return sub.add_parser(
            name,
            parents=[common],
            help=t(f"cmd_{name}"),
            description=t(f"cmd_{name}"),
            epilog=t(f"cmd_{name}_ex"),
        )

    p = add("detect")
    p.add_argument("input", help=t("arg_input"))

    p = add("auto")
    p.add_argument("input", help=t("arg_input"))

    p = add("xor")
    p.add_argument("input", help=t("arg_input"))
    p.add_argument("--key", help=t("opt_xor_key"))
    p.add_argument("--keylen", type=int, help=t("opt_xor_keylen"))
    p.add_argument("--crib", help=t("opt_xor_crib"))
    p.add_argument("--with", dest="other", help=t("opt_xor_with"))
    p.add_argument("--hashed-keys", action="store_true", help=t("opt_xor_hashed"))

    p = add("sym")
    p.add_argument("input", help=t("arg_input"))
    p.add_argument("--cipher", help=t("opt_sym_cipher"))
    p.add_argument("--mode", help=t("opt_sym_mode"))
    p.add_argument("--key", help=t("opt_sym_key"))
    p.add_argument("--iv", help=t("opt_sym_iv"))
    p.add_argument("--blob", help=t("opt_sym_blob"))
    p.add_argument("--pass", dest="passphrase", help=t("opt_sym_pass"))
    p.add_argument("--passwords", action="store_true", help=t("opt_sym_passwords"))
    p.add_argument("--seconds", type=float, default=30.0, help=t("opt_seconds"))

    p = add("blob")
    p.add_argument("input", help=t("arg_input"))
    p.add_argument("--against", required=True, help=t("opt_blob_against"))
    p.add_argument("--seconds", type=float, default=30.0, help=t("opt_seconds"))

    p = add("rsa")
    p.add_argument("--key", help=t("opt_rsa_key"))
    p.add_argument("--pass", dest="passphrase", help=t("opt_rsa_pass"))
    p.add_argument("--decrypt", help=t("opt_rsa_decrypt"))
    p.add_argument("--attack", action="store_true", help=t("opt_rsa_attack"))
    p.add_argument("--other", action="append", default=[], help=t("opt_rsa_other"))
    p.add_argument("--check", help=t("opt_rsa_check"))
    p.add_argument("--n", help=t("opt_rsa_n"))
    p.add_argument("--e", help=t("opt_rsa_e"))
    p.add_argument("--d", help=t("opt_rsa_d"))
    p.add_argument("--p", help=t("opt_rsa_p"))
    p.add_argument("--q", help=t("opt_rsa_q"))
    p.add_argument("--seconds", type=float, default=20.0, help=t("opt_seconds"))

    p = add("hash")
    p.add_argument("hash", help=t("arg_hash"))
    p.add_argument("--no-passwords", action="store_true", help=t("opt_hash_no_passwords"))

    p = add("classical")
    p.add_argument("input", help=t("arg_input"))
    p.add_argument("--cipher", choices=list(classical.OPERATIONS), help=t("opt_classical_cipher"))
    p.add_argument("--key", help=t("opt_classical_key"))

    p = add("lens")
    p.add_argument("script", help=t("arg_script"))
    p.add_argument("--against", help=t("opt_lens_against"))

    p = add("office")
    p.add_argument("document", help=t("arg_document"))
    p.add_argument("--save-macros", help=t("opt_office_save"))

    p = add("pdf")
    p.add_argument("input", help=t("arg_input"))
    p.add_argument("--extract", help=t("opt_pdf_extract"))

    p = add("stego")
    p.add_argument("input", help=t("arg_image"))
    p.add_argument("--seconds", type=float, default=20.0, help=t("opt_seconds"))

    p = add("git")
    p.add_argument("folder", help=t("arg_repo"))
    p.add_argument("--extract", help=t("opt_git_extract"))

    p = add("sqlite")
    p.add_argument("input", help=t("arg_database"))

    p = add("jwt")
    p.add_argument("token", help=t("arg_token"))
    p.add_argument("--secret", help=t("opt_jwt_secret"))
    p.add_argument("--no-secrets", action="store_true", help=t("opt_jwt_no_secrets"))

    p = add("keys")
    p.add_argument("dump", help=t("arg_dump"))
    p.add_argument("--against", help=t("opt_keys_against"))
    p.add_argument("--cipher", help=t("opt_sym_cipher"))
    p.add_argument("--mode", help=t("opt_sym_mode"))
    p.add_argument("--seconds", type=float, default=60.0, help=t("opt_seconds"))

    p = add("recipe")
    p.add_argument("action", choices=["run", "save", "show"], help=t("arg_recipe_action"))
    p.add_argument("recipe", help=t("arg_recipe"))
    p.add_argument("input", nargs="?", help=t("arg_input"))
    p.add_argument("--cyberchef", action="store_true", help=t("opt_recipe_cyberchef"))

    p = add("pcap")
    p.add_argument("input", help=t("arg_input"))
    p.add_argument("--extract", help=t("opt_pcap_extract"))
    p.add_argument("--seconds", type=float, default=30.0, help=t("opt_seconds"))

    p = add("radius")
    p.add_argument("input", help=t("arg_radius_input"))
    p.add_argument("--authenticator", required=True, help=t("opt_radius_authenticator"))
    p.add_argument("--secret", help=t("opt_radius_secret"))

    p = add("scan")
    p.add_argument("folder", help=t("arg_folder"))
    p.add_argument("--no-recursive", action="store_true", help=t("opt_scan_no_recursive"))
    p.add_argument("--seconds", type=float, default=120.0, help=t("opt_seconds"))
    p.add_argument("--per-file", type=float, default=3.0, help=t("opt_scan_per_file"))
    p.add_argument("--min-interest", type=float, default=0.4, help=t("opt_scan_min"))

    p = add("tools")
    p.add_argument("input", help=t("arg_input"))
    p.add_argument("--list", action="store_true", help=t("opt_tools_list"))
    p.add_argument("--run", help=t("opt_tools_run"))
    p.add_argument("--wordlist", help=t("opt_tools_wordlist"))
    p.add_argument("--password", help=t("opt_tools_password"))

    p = add("session")
    p.add_argument(
        "action",
        choices=["new", "use", "list", "show", "note", "flag", "stop"],
        help=t("arg_session_action"),
    )
    p.add_argument("name", nargs="?", help=t("arg_session"))
    p.add_argument("text", nargs="*", help=t("arg_session_text"))
    p.add_argument("--title", help=t("opt_session_title"))
    p.add_argument("--ctf", help=t("opt_session_ctf"))
    p.add_argument("--category", help=t("opt_session_category"))
    p.add_argument("--description", help=t("opt_session_description"))

    p = add("report")
    p.add_argument("name", nargs="?", help=t("arg_session"))
    p.add_argument("--lang", choices=["en", "fr"], default="en", help=t("opt_report_lang"))
    p.add_argument("--out", help=t("opt_report_out"))
    p.add_argument("--all", action="store_true", help=t("opt_report_all"))

    p = add("repair")
    p.add_argument("input", help=t("arg_input"))
    p.add_argument("--out", help=t("opt_repair_out"))

    p = add("cheatsheet")
    p.add_argument("--raw", action="store_true", help=t("opt_cheatsheet_raw"))

    p = add("serve")
    p.add_argument("--port", type=int, default=None, help=t("opt_port"))
    p.add_argument("--host", default=None, help=t("opt_host"))

    return parser


def flagset_from(config: Config) -> FlagSet:
    return build_flagset(config.flag_regexes, config.flag_prefixes)


def input_to_dict(inp: Input) -> dict:
    return {"source": inp.source, "length": len(inp.data), "notes": inp.notes}


def lens_candidates(report) -> list:
    """Code Lens result as a Candidate (the best peeled blob + the recovery script)."""
    from ctfc.core.types import Candidate

    if not report.peeled or report.recovery is None:
        return []
    best = report.peeled[0]
    return [
        Candidate(
            label=best.label,
            data=best.data,
            score=best.score,
            reasons=best.reasons,
            python=report.recovery.python,
        )
    ]


def recipe_candidate(result):
    """A recipe run as a Candidate (its final output, its script and recipe)."""
    from ctfc.core.scoring import score
    from ctfc.core.types import Candidate

    value, reasons = score(result.output)
    return Candidate(
        label=f"recipe {result.name}",
        data=result.output,
        score=value,
        reasons=reasons,
        python=result.python,
        cyberchef=result.cyberchef,
    )


def sessions_dir(config: Config) -> Path:
    return Path(config.sessions_dir).expanduser() if config.sessions_dir else sessions.DEFAULT_DIR


def remember(
    args: argparse.Namespace,
    config: Config,
    data: bytes | None = None,
    input_name: str = "",
    candidates: list | None = None,
    summary: list[str] | None = None,
) -> None:
    """Record this command in the session (--session, or the one `ctfc session use` set).

    Without a session this does nothing: recording is opt-in.
    """
    base = sessions_dir(config)
    name = getattr(args, "session", None) or sessions.current_session(base)
    if not name:
        return
    # The command as typed, minus what only matters on screen.
    shown, skip = [], False
    for word in sys.argv[1:]:
        if skip:
            skip = False
            continue
        if word in ("--session", "--config"):
            skip = True  # and its value
            continue
        if word in ("--json", "--show-code") or word.startswith(("--session=", "--config=")):
            continue
        shown.append(word)
    session = sessions.Session.open(name, base)
    session.add_step(
        tool=args.command,
        command="ctfc " + " ".join(shlex.quote(word) for word in shown),
        data=data,
        input_name=input_name,
        candidates=candidates,
        summary=summary,
        flagset=flagset_from(config),
    )
    print(t("session_recorded", name=name), file=sys.stderr)


def cmd_session(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Create, choose, list and annotate the sessions that `ctfc report` writes up."""
    base = sessions_dir(config)
    if args.action == "list":
        current = sessions.current_session(base)
        for item in sessions.list_sessions(base):
            meta = item.meta()
            marker = "*" if item.name == current else " "
            steps = sum(1 for entry in item.entries() if entry.kind == "step")
            console.print(f"{marker} {item.name:24} {steps:3} steps  {render.safe(meta.title)}")
        return 0
    if args.action == "stop":
        sessions.use_session(None, base)
        print(t("session_stopped"), file=sys.stderr)
        return 0
    name = args.name or sessions.current_session(base)
    if args.action in ("note", "flag") and args.name:
        # `ctfc session note "some text"`: the first word is not a session name,
        # it is the start of the note, for the current session.
        if not sessions.NAME_RE.fullmatch(args.name) or not (base / args.name).is_dir():
            args.text = [args.name, *args.text]
            name = sessions.current_session(base)
    if not name:
        raise sessions.SessionError(t("session_needs_name"))
    if args.action in ("new", "use"):
        session = sessions.Session.open(name, base)
        session.update_meta(
            title=args.title, ctf=args.ctf, category=args.category, description=args.description
        )
        if args.action == "use" or not sessions.current_session(base):
            sessions.use_session(name, base)
        print(t("session_ready", name=name, folder=session.folder), file=sys.stderr)
        return 0
    session = sessions.Session.open(name, base, create=False)
    if args.action == "note":
        text = " ".join(args.text).strip()
        if not text:
            raise sessions.SessionError("ctfc session note <name> <text of the note>")
        session.add_note(text)
        return 0
    if args.action == "flag":
        if not args.text:
            raise sessions.SessionError("ctfc session flag <name> <flag>")
        session.update_meta(flag=" ".join(args.text).strip())
        return 0
    render.print_session(console, session)  # show
    return 0


def cmd_repair(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Fix a broken magic, carve what follows the end marker, undo a pasted header."""
    from ctfc.core.repair import repair

    inp = parse_input(args.input, decode_bare=False)
    report = repair(inp.data)
    written: list[tuple[str, str]] = []  # (path, what to run next)
    if args.out:
        folder = Path(args.out)
        folder.mkdir(parents=True, exist_ok=True)
        stem = Path(args.input).name if Path(args.input).is_file() else "input"
        if report.fixes and report.repaired != inp.data:
            target = folder / f"{stem}.repaired"
            target.write_bytes(report.repaired)
            written.append((str(target), ""))
        for index, item in enumerate(report.carved, start=1):
            target = folder / item.filename(index)
            target.write_bytes(item.data)
            written.append((str(target), item.next_command(str(target))))
    summary = report.notes + [f"wrote {path}" for path, _ in written]
    remember(args, config, inp.data, args.input, summary=summary)
    if args.json:
        payload = {"input": input_to_dict(inp), **report.to_dict()}
        payload["written"] = [{"path": path, "next": nxt} for path, nxt in written]
        print(json.dumps(payload, indent=2))
        return 0 if report.changed else 1
    render.print_input_notes(console, inp)
    render.print_repair(console, report, args.input, written)
    return 0 if report.changed else 1


def cmd_cheatsheet(args: argparse.Namespace, config: Config, console: Console) -> int:
    """The one-page decision tree, in the terminal."""
    from rich.markdown import Markdown

    from ctfc.core.datafiles import load_cheatsheet

    text = load_cheatsheet()
    if args.raw or args.json:
        sys.stdout.write(text)
    else:
        console.print(Markdown(text))
    return 0


def cmd_report(args: argparse.Namespace, config: Config, console: Console) -> int:
    """The Markdown write-up of a session."""
    base = sessions_dir(config)
    name = args.name or sessions.current_session(base)
    if not name:
        raise sessions.SessionError(t("session_needs_name"))
    session = sessions.Session.open(name, base, create=False)
    text = build_report(session, lang=args.lang, include_all=args.all)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(t("report_written", path=args.out), file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


def cmd_detect(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Fingerprint the input and print ranked guesses."""
    inp = parse_input(args.input, decode_bare=False)
    report = detect(inp.data, flagset_from(config))
    guesses = [f"{g.label} ({g.confidence:.2f})" for g in report.guesses[:6]]
    remember(args, config, inp.data, args.input, summary=guesses)
    if args.json:
        print(json.dumps({"input": input_to_dict(inp), "report": report.to_dict()}, indent=2))
        return 0
    render.print_input_notes(console, inp)
    render.print_detect(console, report)
    return 0


def cmd_auto(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Peel encoding layers until the output looks meaningful."""
    inp = parse_input(args.input, decode_bare=False)
    budget = Budget(max_attempts=config.auto_budget, max_seconds=30)
    candidates = auto_decode(
        inp.data,
        flagset=flagset_from(config),
        max_depth=config.auto_max_depth,
        budget=budget,
        top_n=config.top_n,
    )
    remember(args, config, inp.data, args.input, candidates)
    if args.json:
        payload = {
            "input": input_to_dict(inp),
            "budget": budget.summary(),
            "candidates": [candidate.to_dict() for candidate in candidates],
        }
        print(json.dumps(payload, indent=2))
        return 0
    render.print_input_notes(console, inp)
    render.print_candidates(console, candidates, show_code=args.show_code, title="auto decode")
    console.print(f"[dim]{budget.summary()}[/]")
    return 0 if candidates else 1


def cmd_xor(args: argparse.Namespace, config: Config, console: Console) -> int:
    """XOR solver: given key, single byte, repeating key, known plaintext, two inputs."""
    inp = parse_input(args.input)
    flagset = flagset_from(config)
    crib = parse_input(args.crib, decode_bare=False).data if args.crib else None
    budget = Budget(max_attempts=2000, max_seconds=60)
    lengths = []

    if args.other:
        other = parse_input(args.other).data
        candidates = xor_inputs(inp.data, other, flagset, crib, top_n=config.top_n)
    else:
        key = parse_input(args.key).data if args.key else None
        cribs = [prefix.encode() for prefix in config.flag_prefixes]
        if crib:
            cribs.insert(0, crib)
        if not key and not args.keylen:
            lengths = guess_key_lengths(inp.data)[:5]
        candidates = solve_xor(
            inp.data,
            flagset,
            key=key,
            keylen=args.keylen,
            cribs=cribs,
            budget=budget,
            top_n=config.top_n,
            try_hashed=True if args.hashed_keys else None,
        )

    remember(args, config, inp.data, args.input, candidates)
    if args.json:
        payload = {
            "input": input_to_dict(inp),
            "key_lengths": [vars(guess) for guess in lengths],
            "candidates": [candidate.to_dict() for candidate in candidates],
        }
        print(json.dumps(payload, indent=2))
        return 0
    render.print_input_notes(console, inp)
    if lengths:
        render.print_key_lengths(console, lengths)
    render.print_candidates(console, candidates, show_code=args.show_code, title="xor")
    return 0 if candidates else 1


def cmd_keys(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Key hunting: candidate keys in a dump, tested against a ciphertext."""
    dump = parse_input(args.dump, decode_bare=False)
    ciphertext = parse_input(args.against).data if args.against else None
    budget = Budget(max_attempts=1_000_000, max_seconds=args.seconds)
    report = keyhunt.hunt(
        dump.data,
        ciphertext,
        flagset_from(config),
        cipher=args.cipher,
        mode=args.mode,
        budget=budget,
        top_n=config.top_n,
    )
    found = (
        [f"key at offset 0x{report.winner.offset:x}: {report.winner.how}"] if report.winner else []
    )
    if report.luks:
        found.append(f"LUKS master key confirmed by the header: {report.luks['built_from']}")
        found += report.luks["commands"][:2]
    remember(args, config, None, args.dump, report.results, found + report.notes[:3])
    if args.json:
        print(json.dumps({"input": input_to_dict(dump), **report.to_dict()}, indent=2))
    else:
        render.print_key_hunt(console, report, show_code=args.show_code)
    if ciphertext is None:
        return 0 if report.candidates else 1
    # Success: a key that decrypts the ciphertext, or a LUKS master key the header confirms.
    return 0 if (report.winner or report.luks) else 1


def cmd_classical(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Caesar, affine, Atbash, Vigenère, rail fence: brute force + scoring, or a given key."""
    # The ciphertext is text: never auto-decode it as hex/base64.
    inp = parse_input(args.input, decode_bare=False)
    if args.key and not args.cipher:
        raise classical.ClassicalError("--key needs --cipher (caesar, affine, vigenere, railfence)")
    params = classical.parse_key(args.cipher, args.key) if args.key else None
    candidates = classical.solve_classical(
        inp.data,
        flagset_from(config),
        cipher=args.cipher,
        params=params,
        top_n=config.top_n,
    )
    notes = classical.stats_notes(classical.analyse(inp.data))
    remember(args, config, inp.data, args.input, candidates)
    if args.json:
        payload = {
            "input": input_to_dict(inp),
            "notes": notes,
            "candidates": [candidate.to_dict() for candidate in candidates],
        }
        print(json.dumps(payload, indent=2))
        return 0 if candidates else 1
    render.print_input_notes(console, inp)
    render.print_notes(console, notes)
    render.print_candidates(console, candidates, show_code=args.show_code, title="classical")
    return 0 if candidates else 1


def _material(spec: str | None) -> bytes | None:
    """Read a --key / --iv / --blob option.

    Bare text is *not* decoded here: the solver tries the raw bytes and their hex
    or base64 readings itself, and says which one worked.
    """
    if not spec:
        return None
    return parse_input(spec, decode_bare=False).data


def print_sym_report(
    args: argparse.Namespace,
    config: Config,
    inp: Input,
    report: SolveReport,
    console: Console,
    title: str,
) -> int:
    """Shared output for `sym` and `blob`."""
    remember(args, config, inp.data, getattr(args, "input", ""), report.candidates)
    if args.json:
        print(json.dumps({"input": input_to_dict(inp), **report.to_dict()}, indent=2))
        return 0 if report.candidates else 1
    render.print_input_notes(console, inp)
    render.print_notes(console, report.notes)
    render.print_candidates(console, report.candidates, show_code=args.show_code, title=title)
    if report.budget_summary:
        console.print(f"[dim]{report.budget_summary}[/]")
    return 0 if report.candidates else 1


def cmd_sym(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Symmetric ciphers, with the unknown-layout solver."""
    inp = parse_input(args.input)
    budget = Budget(max_attempts=1_000_000, max_seconds=args.seconds)
    report = solve_symmetric(
        inp.data,
        flagset=flagset_from(config),
        cipher=args.cipher,
        mode=args.mode,
        key=_material(args.key),
        iv=_material(args.iv),
        blob=_material(args.blob),
        passphrase=args.passphrase.encode() if args.passphrase else None,
        try_passwords=args.passwords,
        budget=budget,
        top_n=config.top_n,
    )
    return print_sym_report(args, config, inp, report, console, "symmetric")


def cmd_blob(args: argparse.Namespace, config: Config, console: Console) -> int:
    """An unknown key/iv blob, tested against a ciphertext."""
    blob = parse_input(args.input, decode_bare=False)
    ciphertext = parse_input(args.against)
    budget = Budget(max_attempts=1_000_000, max_seconds=args.seconds)
    report = solve_symmetric(
        ciphertext.data,
        flagset=flagset_from(config),
        blob=blob.data,
        budget=budget,
        top_n=config.top_n,
    )
    return print_sym_report(args, config, ciphertext, report, console, "blob splits")


def cmd_lens(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Static analysis of a script: what it does to the data, and how to undo it."""
    inp = parse_input(args.script, decode_bare=False)
    flagset = flagset_from(config)
    report = analyse_script(inp.data, filename=args.script, flagset=flagset)
    mirrored = []
    if args.against:
        # With the file the script produced, its literals can simply be tried as keys.
        encrypted = parse_input(args.against, decode_bare=False).data
        mirrored = mirror_against(inp.data, report, encrypted, flagset, top_n=config.top_n)
    what = [line for line in report.summary if not line.startswith("peeled")]
    remember(args, config, inp.data, args.script, mirrored or lens_candidates(report), what)
    if args.json:
        payload = {"input": input_to_dict(inp), **report.to_dict()}
        payload["against"] = [candidate.to_dict() for candidate in mirrored]
        print(json.dumps(payload, indent=2))
        return 0 if (mirrored if args.against else report.operations) else 1
    render.print_input_notes(console, inp)
    render.print_lens(console, report, show_code=args.show_code and not mirrored)
    if args.against:
        render.print_candidates(
            console, mirrored, show_code=args.show_code, title="the encrypted file, decrypted"
        )
        return 0 if mirrored else 1
    return 0 if report.operations else 1


def cmd_office(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Extract an Office document's VBA macros and read them with Code Lens."""
    from ctfc.core import office

    inp = parse_input(args.document, decode_bare=False)
    report = office.analyse(inp.data)
    flagset = flagset_from(config)
    # The recovered source is VBS-flavoured, which Code Lens already handles: so
    # the macro is not just printed, it is understood (keys, blobs, the flag).
    lens = (
        analyse_script(report.source.encode(), filename="macro.vbs", flagset=flagset)
        if (report.macros)
        else None
    )
    if args.save_macros:
        folder = Path(args.save_macros)
        folder.mkdir(parents=True, exist_ok=True)
        for macro in report.macros:
            name = re.sub(r"[^A-Za-z0-9._-]", "_", macro.module) + ".vbs"
            (folder / name).write_text(macro.code, encoding="utf-8")
        console.print(f"[green]saved {len(report.macros)} module(s)[/] to {folder}")
    candidates = lens_candidates(lens) if lens is not None else []
    remember(args, config, inp.data, args.document, candidates, report.indicators[:4])
    if args.json:
        payload = {"input": input_to_dict(inp), **report.to_dict()}
        payload["lens"] = lens.to_dict() if lens is not None else None
        print(json.dumps(payload, indent=2))
        return 0 if report.macros else 1
    render.print_input_notes(console, inp)
    render.print_office(console, report)
    if lens is not None:
        render.print_lens(console, lens, show_code=args.show_code)
    return 0 if report.macros else 1


def cmd_pdf(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Static analysis of a PDF: actions, JavaScript, embedded files, revisions."""
    from ctfc.core import pdf as pdf_module

    inp = parse_input(args.input, decode_bare=False)
    flagset = flagset_from(config)
    report = pdf_module.analyse(inp.data, flagset)
    # The JavaScript is a script like any other: Code Lens already reads it.
    source = "\n\n".join(code for _, code in report.javascript)
    lens = analyse_script(source.encode(), filename="pdf.js", flagset=flagset) if source else None
    saved = []
    if args.extract:
        folder = Path(args.extract)
        folder.mkdir(parents=True, exist_ok=True)
        for name, blob in report.embedded:
            target = folder / (re.sub(r"[^A-Za-z0-9._-]", "_", name).lstrip(".") or "embedded.bin")
            target.write_bytes(blob)
            saved.append(str(target))
        # Earlier revisions hold what looks removed: hand the first one over too.
        if report.revisions > 1:
            cut = inp.data.find(b"%%EOF")
            first = folder / "revision_1.pdf"
            first.write_bytes(inp.data[: cut + 5])
            saved.append(str(first))
    candidates = lens_candidates(lens) if lens is not None else []
    remember(args, config, inp.data, args.input, candidates, report.indicators[:4])
    if args.json:
        payload = {"input": input_to_dict(inp), **report.to_dict()}
        payload["lens"] = lens.to_dict() if lens is not None else None
        payload["saved"] = saved
        print(json.dumps(payload, indent=2))
        return 0 if report.objects else 1
    render.print_input_notes(console, inp)
    render.print_pdf(console, report, saved)
    if lens is not None:
        render.print_lens(console, lens, show_code=args.show_code)
    return 0 if report.objects else 1


def cmd_stego(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Look for a message hidden in the low bits of a PNG or BMP."""
    from ctfc.core import stego

    inp = parse_input(args.input, decode_bare=False)
    budget = Budget(max_attempts=10_000, max_seconds=args.seconds)
    report = stego.analyse(
        inp.data, flagset=flagset_from(config), budget=budget, top_n=config.top_n
    )
    remember(args, config, inp.data, args.input, report.candidates, report.notes[:3])
    if args.json:
        print(json.dumps({"input": input_to_dict(inp), **report.to_dict()}, indent=2))
        return 0 if report.candidates else 1
    render.print_input_notes(console, inp)
    render.print_stego(console, report, show_code=args.show_code)
    return 0 if report.candidates else 1


def cmd_git(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Find what a .git still holds that the current files no longer show."""
    from ctfc.core import gitrepo

    report = gitrepo.analyse(Path(args.folder), flagset=flagset_from(config))
    saved = []
    if args.extract:
        folder = Path(args.extract)
        folder.mkdir(parents=True, exist_ok=True)
        for blob in report.lost:
            stem = re.sub(r"[^A-Za-z0-9._-]", "_", blob.names[0]) if blob.names else "blob"
            target = folder / f"{blob.sha[:10]}_{stem.lstrip('.') or 'blob'}"
            target.write_bytes(blob.data)
            saved.append(str(target))
    summary = [f"{blob.names or blob.sha[:10]}: {blob.why[:60]}" for blob in report.lost[:4]]
    remember(args, config, None, args.folder, summary=summary)
    if args.json:
        print(json.dumps({**report.to_dict(), "saved": saved}, indent=2))
        return 0 if report.lost else 1
    render.print_git(console, report, saved)
    return 0 if report.lost else 1


def cmd_sqlite(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Read a SQLite database, including the rows it thinks it deleted."""
    from ctfc.core import sqlitedb

    inp = parse_input(args.input, decode_bare=False)
    # The live tables are read through sqlite3, which needs a real file; carving
    # only needs the bytes, so a pasted database still gets the deleted rows.
    path = Path(args.input)
    report = sqlitedb.analyse(
        inp.data, path if path.is_file() else None, flagset=flagset_from(config)
    )
    summary = [f"{row.rowid}: {row.text[:60]}" for row in report.deleted[:4]]
    remember(args, config, None, args.input, summary=summary)
    if args.json:
        print(json.dumps({"input": input_to_dict(inp), **report.to_dict()}, indent=2))
        return 0 if report.deleted else 1
    render.print_input_notes(console, inp)
    render.print_sqlite(console, report)
    return 0 if report.deleted else 1


def cmd_jwt(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Decode a JWT and report what is wrong with it."""
    from ctfc.core import jwt as jwt_module

    secrets = [args.secret.encode()] if args.secret else None
    report = jwt_module.analyse(
        args.token,
        flagset=flagset_from(config),
        secrets=secrets,
        try_secrets=not args.no_secrets,
    )
    summary = [f"{finding.rule}: {finding.what}" for finding in report.findings[:4]]
    remember(args, config, None, args.token, summary=summary)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0 if report.findings else 1
    render.print_jwt(console, report, show_code=args.show_code)
    return 0 if report.findings else 1


def parse_number(text: str | None) -> int | None:
    """Read a big integer written in decimal or as 0x hex."""
    if not text:
        return None
    cleaned = text.strip().replace("_", "").replace(" ", "")
    try:
        return int(cleaned, 16) if cleaned.lower().startswith("0x") else int(cleaned)
    except ValueError as exc:
        raise RsaError(f"{text!r} is not a number (use decimal, or 0x for hex)") from exc


def read_modulus(spec: str) -> int:
    """--other accepts a key file or a bare modulus."""
    path = Path(spec)
    if len(spec) < 4096 and path.is_file():
        return parse_key(path.read_bytes()).n
    number = parse_number(spec)
    if number is None:
        raise RsaError(f"could not read a modulus from {spec!r}")
    return number


def cmd_rsa(args: argparse.Namespace, config: Config, console: Console) -> int:
    """RSA: inspect a key, compare two keys, decrypt, or attack a weak key."""
    if args.key:
        key = parse_key(parse_input(args.key, decode_bare=False).data, args.passphrase)
    else:
        key = build_key(
            n=parse_number(args.n),
            e=parse_number(args.e),
            d=parse_number(args.d),
            p=parse_number(args.p),
            q=parse_number(args.q),
        )

    if args.check:
        other = parse_key(parse_input(args.check, decode_bare=False).data)
        same, why = keys_match(key, other)
        if args.json:
            print(json.dumps({"match": same, "reason": why}, indent=2))
        else:
            render.print_key_comparison(console, key, other, same, why)
        return 0 if same else 1

    ciphertext = parse_input(args.decrypt).data if args.decrypt else None
    budget = Budget(max_attempts=50_000_000, max_seconds=args.seconds)
    report = solve_rsa(
        key,
        ciphertext=ciphertext,
        flagset=flagset_from(config),
        attack=args.attack,
        other_moduli=[read_modulus(spec) for spec in args.other],
        budget=budget,
        top_n=config.top_n,
    )
    remember(args, config, ciphertext, args.decrypt or "", report.candidates, report.notes[:4])
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0 if report.candidates else 1
    render.print_rsa(console, report, show_code=args.show_code)
    return 0 if report.candidates or not ciphertext else 1


def cmd_hash(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Identify a hash and print the hashcat / john command for it."""
    report = identify_hash(args.hash, try_passwords=not args.no_passwords)
    found = []
    for match in report.matches[:4]:
        line = match.format.name
        if match.format.hashcat is not None:
            line += f" (hashcat -m {match.format.hashcat})"
        if match.cracked:
            line += f": cracked, the password is {match.cracked!r}"
        found.append(line)
    remember(args, config, None, "", summary=report.notes[:2] + found)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0 if report.matches else 1
    render.print_hash(console, report)
    return 0 if report.matches else 1


def cmd_pcap(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Pull the payloads out of a capture and decode them."""
    inp = parse_input(args.input, decode_bare=False)
    budget = Budget(max_attempts=10_000_000, max_seconds=args.seconds)
    report, findings = solve_pcap(inp.data, args.input, flagset=flagset_from(config), budget=budget)
    saved = []
    if args.extract:
        folder = Path(args.extract)
        folder.mkdir(parents=True, exist_ok=True)
        for finding in findings:
            target = folder / finding.extracted.name
            target.write_bytes(finding.extracted.data)
            saved.append(str(target))
    best = [finding.best for finding in findings if finding.best is not None]
    remember(args, config, None, args.input, best, [f.extracted.name for f in findings[:8]])
    if args.json:
        payload = {
            **report.to_dict(),
            "findings": [finding.to_dict() for finding in findings],
            "saved": saved,
        }
        print(json.dumps(payload, indent=2))
        return 0 if findings else 1
    render.print_pcap(console, report, findings, saved, show_code=args.show_code)
    return 0 if findings else 1


def cmd_radius(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Recover a RADIUS PAP password from the User-Password attribute + authenticator."""
    from ctfc.core import radius

    encrypted = parse_input(args.input, decode_bare=False).data
    authenticator = parse_input(args.authenticator, decode_bare=False).data
    if len(authenticator) != 16:
        raise ValueError(
            f"the Request Authenticator must be 16 bytes, got {len(authenticator)} "
            "(pass it as hex:... or b64:...)"
        )
    secrets = [args.secret.encode()] if args.secret else None
    found = radius.recover(encrypted, authenticator, secrets, flagset=flagset_from(config))
    best = found[0] if found else None
    remember(
        args,
        config,
        best.password if best else None,
        args.input,
        summary=[
            f"secret {best.secret.decode('utf-8', 'replace')!r}: {best.password!r}"
            for best in found[:3]
        ],
    )
    if args.json:
        print(
            json.dumps(
                {
                    "recovered": [
                        {
                            "secret": r.secret.decode("utf-8", "replace"),
                            "password": r.password.decode("utf-8", "replace"),
                            "is_flag": r.is_flag,
                        }
                        for r in found
                    ]
                },
                indent=2,
            )
        )
        return 0 if found else 1
    render.print_radius(console, found, bool(args.secret))
    return 0 if found else 1


def cmd_scan(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Run detect + auto on every file of a folder and rank them."""
    budget = Budget(max_attempts=10_000_000, max_seconds=args.seconds)
    report = scan_folder(
        Path(args.folder),
        flagset=flagset_from(config),
        recursive=not args.no_recursive,
        budget=budget,
        per_file_seconds=args.per_file,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0 if report.interesting(args.min_interest) else 1
    render.print_scan(console, report, args.min_interest, show_code=args.show_code)
    return 0 if report.interesting(args.min_interest) else 1


def cmd_recipe(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Run a saved recipe, or turn an auto result into one."""
    if args.action == "show":
        name, steps = pipeline.load(args.recipe)
        print(pipeline.dump(name, steps))
        return 0

    if args.action == "save":
        # Save what `auto` found on this input as a reusable recipe.
        if not args.input:
            raise RecipeError("recipe save needs an input: ctfc recipe save out.json <input>")
        inp = parse_input(args.input, decode_bare=False)
        candidates = auto_decode(inp.data, flagset=flagset_from(config), top_n=1)
        if not candidates:
            print(t("recipe_nothing_to_save"), file=sys.stderr)
            return 1
        steps = candidates[0].params.get("chain")
        if not steps:
            raise RecipeError("that result has no chain of steps to save")
        from ctfc.core.codegen import Step

        pipeline.dump(
            Path(args.recipe).stem,
            [Step(entry["name"], entry.get("params", {})) for entry in steps],
            args.recipe,
        )
        console.print(f"[green]saved[/] {escape_path(args.recipe)}: {candidates[0].label}")
        return 0

    if not args.input:
        raise RecipeError("recipe run needs an input: ctfc recipe run r.json <input>")
    inp = parse_input(args.input, decode_bare=False)
    result = pipeline.run_file(inp.data, args.recipe, flagset_from(config))
    remember(args, config, inp.data, args.input, [recipe_candidate(result)], result.notes)
    url = ""
    if args.cyberchef and result.cyberchef:
        base, note = toolbox.cyberchef_target(config.cyberchef_url, config.offline, for_web=False)
        if note:
            result.notes.append("CyberChef: " + note)
        if base:
            url = deep_link(result.cyberchef, inp.data[: toolbox.CYBERCHEF_DATA_LIMIT], base)
    if args.json:
        print(json.dumps({**result.to_dict(), "cyberchef_url": url}, indent=2))
        return 0 if result.ok else 1
    render.print_recipe(console, result, show_code=args.show_code)
    if url:
        # On its own line and never wrapped, so it stays clickable / copyable.
        console.print("CyberChef link:")
        console.print(url, soft_wrap=True, markup=False, highlight=False)
    return 0 if result.ok else 1


def escape_path(path: str) -> str:
    from rich.markup import escape

    return escape(str(path))


def cmd_tools(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Suggest the external tools that fit this input, and run one on request."""
    if args.list:
        render.print_tool_list(console, toolbox.installed_tools())
        return 0

    inp = parse_input(args.input)
    # The tools read files: a pasted hex:/text: input has no path to give them.
    path = args.input if Path(args.input).is_file() else None
    signals, values = toolbox.gather(inp.data, path, flagset_from(config))
    if args.wordlist:
        values["wordlist"] = args.wordlist
    if args.password:
        values["password"] = args.password
    values["cyberchef_url"] = toolbox.cyberchef_base(config.cyberchef_url, for_web=False)

    suggestions = toolbox.suggest(
        signals,
        values=values,
        offline=config.offline,
        threshold=config.suggest_threshold,
        limit=config.max_suggestions,
    )

    if args.run:
        tool = toolbox.tool_by_id(args.run)
        if not tool.offline_safe and config.offline:
            print(t("tool_offline_refused", name=tool.name), file=sys.stderr)
            return 2
        if path is None:
            # Write the pasted data to a temporary file for the tool, then clean up.
            with tempfile.TemporaryDirectory(prefix="ctfc-") as folder:
                values["input"] = str(toolbox.write_input(inp.data, Path(folder)))
                result = toolbox.run_tool(tool, values)
        else:
            result = toolbox.run_tool(tool, values)
        output = (result.stdout or result.stderr or result.error).splitlines()[:10]
        remember(
            args, config, inp.data, args.input, summary=["$ " + " ".join(result.command), *output]
        )
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
            return 0 if result.returncode == 0 else 1
        render.print_tool_run(console, tool, result)
        return 0 if result.returncode == 0 else 1

    if args.json:
        print(json.dumps({"suggestions": [item.to_dict() for item in suggestions]}, indent=2))
        return 0 if suggestions else 1
    render.print_tools(console, suggestions, public_url=PUBLIC_URL, offline=config.offline)
    return 0 if suggestions else 1


def cmd_serve(args: argparse.Namespace, config: Config) -> int:
    """Start the Flask web UI (bound to 127.0.0.1 unless --host says otherwise)."""
    from ctfc.web.app import create_app  # imported here so the CLI starts fast

    host = args.host or config.web_host
    port = args.port or config.web_port
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"{t('warning_prefix')}: {t('serve_exposed', host=host)}", file=sys.stderr)
    print(t("serve_start", host=host, port=port))
    create_app(config).run(host=host, port=port, debug=False)
    return 0


def main(argv: list[str] | None = None) -> int:
    """Entry point for the `ctfc` command. Returns the process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"{t('error_prefix')}: {exc}", file=sys.stderr)
        return 2
    for warning in config.warnings:
        print(f"{t('warning_prefix')}: {warning}", file=sys.stderr)
    if args.offline:
        config.offline = True
    if args.top:
        config.top_n = args.top

    if args.command == "serve":
        return cmd_serve(args, config)

    console = Console(highlight=False)
    commands = {
        "detect": cmd_detect,
        "auto": cmd_auto,
        "xor": cmd_xor,
        "sym": cmd_sym,
        "blob": cmd_blob,
        "lens": cmd_lens,
        "classical": cmd_classical,
        "keys": cmd_keys,
        "session": cmd_session,
        "report": cmd_report,
        "cheatsheet": cmd_cheatsheet,
        "repair": cmd_repair,
        "rsa": cmd_rsa,
        "hash": cmd_hash,
        "scan": cmd_scan,
        "office": cmd_office,
        "pdf": cmd_pdf,
        "stego": cmd_stego,
        "git": cmd_git,
        "sqlite": cmd_sqlite,
        "jwt": cmd_jwt,
        "pcap": cmd_pcap,
        "radius": cmd_radius,
        "recipe": cmd_recipe,
        "tools": cmd_tools,
    }
    if args.command in commands:
        try:
            return commands[args.command](args, config, console)
        # SessionError and ClassicalError are ValueErrors too.
        except (InputError, CryptoError, RsaError, PcapError, RecipeError, ValueError) as exc:
            print(f"{t('error_prefix')}: {exc}", file=sys.stderr)
            return 2
        except KeyboardInterrupt:
            print(t("interrupted"), file=sys.stderr)
            return 130

    milestone = PLANNED.get(args.command, "?")
    print(t("not_yet", command=args.command, milestone=milestone), file=sys.stderr)
    return 1
