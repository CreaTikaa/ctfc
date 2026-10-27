"""Command line interface. Only parses arguments, calls `ctfc.core`, and displays results.

Each command is one small `cmd_<name>(args, config)` function returning an exit code.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console

from ctfc import __version__, render
from ctfc.config import Config, ConfigError, load_config
from ctfc.core.auto import auto_decode
from ctfc.core.budget import Budget
from ctfc.core.detect import detect
from ctfc.core.flags import FlagSet, build_flagset
from ctfc.core.inputs import InputError, parse_input
from ctfc.core.types import Input
from ctfc.strings import t

# Commands that exist in the interface but are built in a later milestone.
PLANNED = {
    "xor": "M2",
    "sym": "M3",
    "blob": "M3",
    "lens": "M4",
    "rsa": "M5",
    "hash": "M5",
    "recipe": "M6",
    "tools": "M6",
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
    p.add_argument("--key", help="key as hex:..., text:... or a file")
    p.add_argument("--keylen", type=int, help="force this key length")
    p.add_argument("--crib", help="known plaintext, e.g. 'CYBN{'")

    p = add("sym")
    p.add_argument("input", help=t("arg_input"))
    p.add_argument("--cipher", help="aes, des, 3des, blowfish, chacha20, salsa20, rc4, tea, xtea")
    p.add_argument("--mode", help="ecb, cbc, ctr, cfb, ofb, gcm, cts")
    p.add_argument("--key", help="key (hex:, b64:, text: or file)")
    p.add_argument("--iv", help="IV / nonce (hex:, b64:, text: or file)")
    p.add_argument("--blob", help="unknown blob that may contain key and/or iv")
    p.add_argument("--pass", dest="passphrase", help="passphrase (KDFs are tried)")

    p = add("blob")
    p.add_argument("input", help=t("arg_input"))
    p.add_argument("--against", help="ciphertext to test the splits against")

    p = add("rsa")
    p.add_argument("--key", help="PEM/DER key file")
    p.add_argument("--decrypt", help="ciphertext to decrypt")

    p = add("hash")
    p.add_argument("hash", help="the hash string")

    p = add("lens")
    p.add_argument("script", help="script file to analyse (never executed)")

    p = add("keys")
    p.add_argument("dump", help="memory dump / binary / strings output")
    p.add_argument("--against", help="ciphertext to test the candidate keys against")

    p = add("recipe")
    p.add_argument("action", choices=["run"])
    p.add_argument("recipe", help="recipe.json")
    p.add_argument("input", nargs="?", help=t("arg_input"))

    p = add("tools")
    p.add_argument("input", help=t("arg_input"))

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
    commands = {"detect": cmd_detect, "auto": cmd_auto}
    if args.command in commands:
        try:
            return commands[args.command](args, config, console)
        except InputError as exc:
            print(f"{t('error_prefix')}: {exc}", file=sys.stderr)
            return 2

    milestone = PLANNED.get(args.command, "?")
    print(t("not_yet", command=args.command, milestone=milestone), file=sys.stderr)
    return 1
