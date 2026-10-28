"""Command line interface. Only parses arguments, calls `ctfc.core`, and displays results.

Each command is one small `cmd_<name>(args, config)` function returning an exit code.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from rich.console import Console

from ctfc import __version__, render
from ctfc.config import Config, ConfigError, load_config
from ctfc.core import pipeline
from ctfc.core import tools as toolbox
from ctfc.core.auto import auto_decode
from ctfc.core.budget import Budget
from ctfc.core.cyberchef import PUBLIC_URL, deep_link
from ctfc.core.detect import detect
from ctfc.core.flags import FlagSet, build_flagset
from ctfc.core.hashes import identify as identify_hash
from ctfc.core.inputs import InputError, parse_input
from ctfc.core.lens import analyse as analyse_script
from ctfc.core.pcap import PcapError
from ctfc.core.pcap import solve as solve_pcap
from ctfc.core.pipeline import RecipeError
from ctfc.core.rsa import RsaError, build_key, keys_match, parse_key, solve_rsa
from ctfc.core.scan import scan as scan_folder
from ctfc.core.symmetric import CryptoError, SolveReport, solve_symmetric
from ctfc.core.types import Input
from ctfc.core.xor import guess_key_lengths, solve_xor, xor_inputs
from ctfc.strings import t

# Commands that exist in the interface but are built in a later milestone.
PLANNED = {
    "keys": "M7",
}


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser with one sub-command per feature."""
    # Options shared by every sub-command, so they can be written after the command name.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help=t("opt_json"))
    common.add_argument("--show-code", action="store_true", help=t("opt_show_code"))
    common.add_argument("--offline", action="store_true", help=t("opt_offline"))
    common.add_argument("--config", type=Path, default=None, help=t("opt_config"))
    common.add_argument("--top", type=int, default=None, help=t("opt_top"))

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

    p = add("lens")
    p.add_argument("script", help=t("arg_script"))

    p = add("keys")
    p.add_argument("dump", help="memory dump / binary / strings output")
    p.add_argument("--against", help="ciphertext to test the candidate keys against")

    p = add("recipe")
    p.add_argument("action", choices=["run", "save", "show"], help=t("arg_recipe_action"))
    p.add_argument("recipe", help=t("arg_recipe"))
    p.add_argument("input", nargs="?", help=t("arg_input"))
    p.add_argument("--cyberchef", action="store_true", help=t("opt_recipe_cyberchef"))

    p = add("pcap")
    p.add_argument("input", help=t("arg_input"))
    p.add_argument("--extract", help=t("opt_pcap_extract"))
    p.add_argument("--seconds", type=float, default=30.0, help=t("opt_seconds"))

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

    p = add("serve")
    p.add_argument("--port", type=int, default=None, help=t("opt_port"))
    p.add_argument("--host", default=None, help=t("opt_host"))

    return parser


def flagset_from(config: Config) -> FlagSet:
    return build_flagset(config.flag_regexes, config.flag_prefixes)


def input_to_dict(inp: Input) -> dict:
    return {"source": inp.source, "length": len(inp.data), "notes": inp.notes}


def cmd_detect(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Fingerprint the input and print ranked guesses."""
    inp = parse_input(args.input, decode_bare=False)
    report = detect(inp.data, flagset_from(config))
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


def _material(spec: str | None) -> bytes | None:
    """Read a --key / --iv / --blob option.

    Bare text is *not* decoded here: the solver tries the raw bytes and their hex
    or base64 readings itself, and says which one worked.
    """
    if not spec:
        return None
    return parse_input(spec, decode_bare=False).data


def print_sym_report(
    args: argparse.Namespace, inp: Input, report: SolveReport, console: Console, title: str
) -> int:
    """Shared output for `sym` and `blob`."""
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
    return print_sym_report(args, inp, report, console, "symmetric")


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
    return print_sym_report(args, ciphertext, report, console, "blob splits")


def cmd_lens(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Static analysis of a script: what it does to the data, and how to undo it."""
    inp = parse_input(args.script, decode_bare=False)
    report = analyse_script(inp.data, filename=args.script, flagset=flagset_from(config))
    if args.json:
        print(json.dumps({"input": input_to_dict(inp), **report.to_dict()}, indent=2))
        return 0 if report.operations else 1
    render.print_input_notes(console, inp)
    render.print_lens(console, report, show_code=args.show_code)
    return 0 if report.operations else 1


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
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
        return 0 if report.candidates else 1
    render.print_rsa(console, report, show_code=args.show_code)
    return 0 if report.candidates or not ciphertext else 1


def cmd_hash(args: argparse.Namespace, config: Config, console: Console) -> int:
    """Identify a hash and print the hashcat / john command for it."""
    report = identify_hash(args.hash, try_passwords=not args.no_passwords)
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
    if args.cyberchef and result.cyberchef:
        base, note = toolbox.cyberchef_target(config.cyberchef_url, config.offline, for_web=False)
        if note:
            result.notes.append("CyberChef: " + note)
        if base:
            data = inp.data[: toolbox.CYBERCHEF_DATA_LIMIT]
            result.notes.append("CyberChef: " + deep_link(result.cyberchef, data, base))
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return 0 if result.ok else 1
    render.print_recipe(console, result, show_code=args.show_code)
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
        "rsa": cmd_rsa,
        "hash": cmd_hash,
        "scan": cmd_scan,
        "pcap": cmd_pcap,
        "recipe": cmd_recipe,
        "tools": cmd_tools,
    }
    if args.command in commands:
        try:
            return commands[args.command](args, config, console)
        except (InputError, CryptoError, RsaError, PcapError, RecipeError, ValueError) as exc:
            print(f"{t('error_prefix')}: {exc}", file=sys.stderr)
            return 2
        except KeyboardInterrupt:
            print(t("interrupted"), file=sys.stderr)
            return 130

    milestone = PLANNED.get(args.command, "?")
    print(t("not_yet", command=args.command, milestone=milestone), file=sys.stderr)
    return 1
