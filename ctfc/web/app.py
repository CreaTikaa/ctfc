"""Flask application: serves the static UI and a small JSON API.

Security notes (CLAUDE.md hard rules):
- binds to 127.0.0.1 by default (see `ctfc serve`),
- upload size is capped (MAX_CONTENT_LENGTH),
- static files are served by Flask's `send_from_directory`, which refuses `..` paths,
- the browser can never make the server read a local file (parse_input allow_files=False).

API (all POST bodies are JSON):
    {"input": "<text>", "format": "auto|text|hex|b64"}   pasted input
    {"data_b64": "<base64 of the file>", "name": "x.bin"}  uploaded file
    + "options": {...} for tools that take options (xor: key, keylen, crib, other)

Recipes (POST /api/recipe), external tool suggestions (POST /api/tools) and
running one of them (POST /api/tools/run) answer directly.

Long searches (auto, xor) exist twice: POST /api/<kind> answers when finished,
POST /api/jobs/<kind> runs in the background (progress + cancel, see jobs.py).
"""

from __future__ import annotations

import base64
import binascii
import json
import tempfile
from collections.abc import Callable
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory

from ctfc import __version__
from ctfc.config import Config
from ctfc.core import keyhunt, pipeline
from ctfc.core import session as sessions
from ctfc.core import tools as toolbox
from ctfc.core.auto import auto_decode
from ctfc.core.budget import Budget
from ctfc.core.cyberchef import deep_link
from ctfc.core.detect import detect
from ctfc.core.flags import build_flagset
from ctfc.core.hashes import identify as identify_hash
from ctfc.core.inputs import InputError, decode_base64, decode_hex, parse_input
from ctfc.core.lens import analyse as analyse_script
from ctfc.core.lens_against import mirror_against
from ctfc.core.pipeline import RecipeError
from ctfc.core.report import build_report
from ctfc.core.rsa import RsaError, build_key, parse_key, solve_rsa
from ctfc.core.symmetric import solve_symmetric
from ctfc.core.types import Candidate, Input
from ctfc.core.xor import guess_key_lengths, solve_xor, xor_inputs
from ctfc.strings import EN, t
from ctfc.web.jobs import JobManager

STATIC_DIR = Path(__file__).parent / "static"
PREVIEW_BYTES = 4096  # how much of the input is sent back for the hexdump view


def input_from_payload(payload: dict, decode_bare: bool = True) -> Input:
    """Build an `Input` from the JSON body sent by the browser."""
    if "data_b64" in payload:
        try:
            data = base64.b64decode(payload["data_b64"], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise InputError(f"uploaded file is not valid base64 ({exc})") from exc
        name = str(payload.get("name", "upload"))[:100]
        return Input(data=data, source=f"upload:{name}")

    text = str(payload.get("input", ""))
    if not text:
        raise InputError(t("web_empty_input"))
    fmt = payload.get("format", "auto")
    if fmt == "text":
        return Input(data=text.encode("utf-8"), source="text")
    if fmt == "hex":
        return Input(data=decode_hex(text), source="hex")
    if fmt == "b64":
        return Input(data=decode_base64(text), source="b64")
    return parse_input(text, allow_files=False, decode_bare=decode_bare)


def _number(value: object) -> int | None:
    """Read a big integer from the browser: decimal, or 0x hex."""
    text = str(value or "").strip().replace("_", "").replace(" ", "")
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError as exc:
        raise InputError(f"{text[:40]!r} is not a number (decimal, or 0x for hex)") from exc


def candidate_from_dict(raw: dict) -> Candidate:
    """Back from the JSON a tool returned to a Candidate (to record it in a session)."""
    return Candidate(
        label=str(raw.get("label", "")),
        data=bytes.fromhex(raw.get("data_hex", "")),
        score=float(raw.get("score", 0)),
        reasons=list(raw.get("reasons", [])),
        python=raw.get("python") or "",
        cyberchef=raw.get("cyberchef"),
    )


def radius_snippet(encrypted: bytes, authenticator: bytes, secret: bytes) -> str:
    """A tiny standalone script that redoes one RADIUS PAP recovery (teaching layer)."""
    return (
        "import hashlib\n"
        f"enc = bytes.fromhex({encrypted.hex()!r})\n"
        f"auth = bytes.fromhex({authenticator.hex()!r})\n"
        f"secret = {secret!r}\n"
        "out, prev = bytearray(), auth\n"
        "for i in range(0, len(enc), 16):\n"
        "    block = enc[i : i + 16]\n"
        "    stream = hashlib.md5(secret + prev).digest()  # RFC 2865 section 5.2\n"
        "    out += bytes(c ^ s for c, s in zip(block, stream))\n"
        "    prev = block\n"
        "print(bytes(out).rstrip(b'\\x00'))\n"
    )


# The CLI command a web run corresponds to: the write-up shows commands that can
# be typed again. Options are added when they were filled in.
WEB_OPTIONS = {
    "xor": (("key", "--key"), ("keylen", "--keylen"), ("crib", "--crib")),
    "sym": (
        ("cipher", "--cipher"),
        ("mode", "--mode"),
        ("key", "--key"),
        ("iv", "--iv"),
        ("blob", "--blob"),
        ("passphrase", "--pass"),
    ),
    "keys": (("cipher", "--cipher"), ("mode", "--mode")),
    "radius": (("authenticator", "--authenticator"), ("secret", "--secret")),
}


def web_command(tool: str, payload: dict) -> str:
    import shlex

    name = str(payload.get("name") or "")
    if not name:
        text = str(payload.get("input") or "")
        name = "text:" + (text[:40] + "..." if len(text) > 40 else text)
    words = ["ctfc", tool, name]
    options = payload.get("options") or {}
    for option, flag in WEB_OPTIONS.get(tool, ()):
        value = str(options.get(option) or "").strip()
        if value:
            words += [flag, value[:60]]
    if tool in ("keys", "lens") and options.get("against"):
        words += ["--against", "<the encrypted file>"]
    return " ".join(shlex.quote(word) for word in words) + "   # (web UI)"


def recipe_from_option(value: object) -> tuple[str, list]:
    """The recipe sent by the browser: JSON text, or an already-parsed object/list."""
    if isinstance(value, str):
        if not value.strip():
            raise RecipeError("the recipe is empty: add a step first")
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise RecipeError(f"the recipe is not valid JSON: {exc}") from exc
    if isinstance(value, list):
        value = {"steps": value}
    if not isinstance(value, dict) or not isinstance(value.get("steps"), list):
        raise RecipeError('expected {"name": ..., "steps": [...]} or a list of steps')
    return str(value.get("name") or "recipe"), pipeline.parse_steps(value["steps"])


def input_summary(inp: Input) -> dict:
    return {
        "source": inp.source,
        "length": len(inp.data),
        "notes": inp.notes,
        "preview_hex": inp.data[:PREVIEW_BYTES].hex(),
    }


def create_app(config: Config | None = None) -> Flask:
    """Build the Flask app. `config` defaults to the built-in settings."""
    config = config or Config()
    flagset = build_flagset(config.flag_regexes, config.flag_prefixes)
    app = Flask(__name__, static_folder=None)  # we serve static files ourselves
    app.config["MAX_CONTENT_LENGTH"] = config.max_upload_mb * 1024 * 1024
    app.config["CTFC"] = config

    jobs = JobManager()
    sessions_base = (
        Path(config.sessions_dir).expanduser() if config.sessions_dir else sessions.DEFAULT_DIR
    )

    def record(payload: dict, tool: str, inp: Input | None, answer: dict) -> None:
        """Add this run to the session the page chose (payload "session"), if any."""
        name = str(payload.get("session") or "").strip()
        if not name:
            return
        found = answer.get("candidates") or answer.get("results") or answer.get("against") or []
        candidates = [candidate_from_dict(raw) for raw in found[:1]]
        summary = list(answer.get("summary") or [])
        if tool == "detect":
            summary = [
                f"{g['label']} ({g['confidence']:.2f})" for g in answer["report"]["guesses"][:6]
            ]
        summary += [str(note) for note in (answer.get("notes") or [])[:3]]
        if tool == "recipe" and answer.get("steps"):
            candidates = [
                Candidate(
                    label=f"recipe {answer.get('name', '')}",
                    data=bytes.fromhex(answer.get("output_hex", "")),
                    score=max((step["score"] for step in answer["steps"]), default=0),
                    reasons=[step["label"] for step in answer["steps"]],
                    python=answer.get("python") or "",
                    cyberchef=answer.get("cyberchef"),
                )
            ]
        sessions.Session.open(name, sessions_base).add_step(
            tool=tool,
            command=web_command(tool, payload),
            data=inp.data if inp is not None else None,
            input_name=str(payload.get("name") or ""),
            candidates=candidates,
            summary=summary,
            flagset=flagset,
        )

    def read_payload() -> dict:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            raise InputError("expected a JSON object body")
        return payload

    def read_input(decode_bare: bool = True) -> Input:
        return input_from_payload(read_payload(), decode_bare)

    def option_bytes(options: dict, name: str, decode_bare: bool = True) -> bytes | None:
        """An option given like an input (hex:, b64:, text: or bare text), or None."""
        value = str(options.get(name) or "").strip()
        if not value:
            return None
        return parse_input(value, allow_files=False, decode_bare=decode_bare).data

    def prepare(kind: str) -> tuple[Callable[[Budget], dict], Budget]:
        """The work of a long tool, recorded in the page's session when it finishes."""
        payload = read_payload()
        work, budget = prepare_work(kind, payload)

        def recorded(budget: Budget) -> dict:
            answer = work(budget)
            record(payload, kind, None, answer)
            return answer

        return recorded, budget

    def prepare_work(kind: str, payload: dict) -> tuple[Callable[[Budget], dict], Budget]:
        """Read the request now; return the work to run (maybe in a thread) and its budget."""
        options = payload.get("options") or {}
        if kind == "auto":
            inp = input_from_payload(payload, decode_bare=False)
            budget = Budget(max_attempts=config.auto_budget, max_seconds=30)

            def work_auto(budget: Budget) -> dict:
                candidates = auto_decode(
                    inp.data,
                    flagset=flagset,
                    max_depth=config.auto_max_depth,
                    budget=budget,
                    top_n=config.top_n,
                )
                return {
                    "input": input_summary(inp),
                    "budget": budget.summary(),
                    "candidates": [candidate.to_dict() for candidate in candidates],
                }

            return work_auto, budget

        if kind == "xor":
            inp = input_from_payload(payload)
            key = option_bytes(options, "key")
            crib = option_bytes(options, "crib", decode_bare=False)
            other = option_bytes(options, "other")
            try:
                keylen = int(options.get("keylen") or 0) or None
            except ValueError as exc:
                raise InputError("key length must be a number") from exc
            budget = Budget(max_attempts=2000, max_seconds=60)

            def work_xor(budget: Budget) -> dict:
                lengths = []
                if other is not None:
                    candidates = xor_inputs(inp.data, other, flagset, crib, top_n=config.top_n)
                else:
                    cribs = [prefix.encode() for prefix in config.flag_prefixes]
                    if crib:
                        cribs.insert(0, crib)
                    if not key and not keylen:
                        lengths = guess_key_lengths(inp.data)[:5]
                    candidates = solve_xor(
                        inp.data,
                        flagset,
                        key,
                        keylen,
                        cribs,
                        budget,
                        top_n=config.top_n,
                        try_hashed=True if options.get("hashed") else None,
                    )
                return {
                    "input": input_summary(inp),
                    "budget": budget.summary(),
                    "key_lengths": [vars(guess) for guess in lengths],
                    "candidates": [candidate.to_dict() for candidate in candidates],
                }

            return work_xor, budget

        if kind in ("sym", "blob"):
            inp = input_from_payload(payload)
            # The solver tries the raw bytes and their hex/base64 readings itself,
            # so key material is taken literally here (decode_bare=False).
            if kind == "blob":
                blob = option_bytes(options, "blob", decode_bare=False) or inp.data
                ciphertext = option_bytes(options, "against") or b""
                if not ciphertext:
                    raise InputError(t("web_blob_needs_ct"))
                data, blob_bytes = ciphertext, blob
                key = iv = passphrase = None
                cipher = mode = None
                try_passwords = False
            else:
                data = inp.data
                key = option_bytes(options, "key", decode_bare=False)
                iv = option_bytes(options, "iv", decode_bare=False)
                blob_bytes = option_bytes(options, "blob", decode_bare=False)
                passphrase = str(options.get("passphrase") or "").encode() or None
                cipher = str(options.get("cipher") or "").strip() or None
                mode = str(options.get("mode") or "").strip() or None
                try_passwords = bool(options.get("passwords"))
            seconds = min(float(options.get("seconds") or 30), 120)
            budget = Budget(max_attempts=1_000_000, max_seconds=seconds)

            def work_sym(budget: Budget) -> dict:
                report = solve_symmetric(
                    data,
                    flagset=flagset,
                    cipher=cipher,
                    mode=mode,
                    key=key,
                    iv=iv,
                    blob=blob_bytes,
                    passphrase=passphrase,
                    try_passwords=try_passwords,
                    budget=budget,
                    top_n=config.top_n,
                )
                return {"input": input_summary(inp), **report.to_dict()}

            return work_sym, budget

        if kind == "rsa":
            # The input panel holds the ciphertext; the key goes in the options.
            inp = input_from_payload(payload)
            key_text = str(options.get("key") or "").strip()
            if key_text:
                key = parse_key(key_text.encode())
            else:
                key = build_key(
                    n=_number(options.get("n")),
                    e=_number(options.get("e")),
                    d=_number(options.get("d")),
                    p=_number(options.get("p")),
                    q=_number(options.get("q")),
                )
            others = []
            for line in str(options.get("other") or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                others.append(parse_key(line.encode()).n if "-----" in line else int(line))
            attack = bool(options.get("attack"))
            seconds = min(float(options.get("seconds") or 20), 120)
            budget = Budget(max_attempts=50_000_000, max_seconds=seconds)

            def work_rsa(budget: Budget) -> dict:
                report = solve_rsa(
                    key,
                    ciphertext=inp.data or None,
                    flagset=flagset,
                    attack=attack,
                    other_moduli=others,
                    budget=budget,
                    top_n=config.top_n,
                )
                return {"input": input_summary(inp), **report.to_dict()}

            return work_rsa, budget

        if kind == "keys":
            # The input panel holds the dump; the ciphertext is an option.
            dump = input_from_payload(payload, decode_bare=False)
            ciphertext = option_bytes(options, "against")
            cipher = str(options.get("cipher") or "").strip() or None
            mode = str(options.get("mode") or "").strip() or None
            seconds = min(float(options.get("seconds") or 60), 300)
            budget = Budget(max_attempts=1_000_000, max_seconds=seconds)

            def work_keys(budget: Budget) -> dict:
                report = keyhunt.hunt(
                    dump.data,
                    ciphertext,
                    flagset,
                    cipher=cipher,
                    mode=mode,
                    budget=budget,
                    top_n=config.top_n,
                )
                return {"input": input_summary(dump), **report.to_dict()}

            return work_keys, budget

        raise InputError(f"unknown tool '{kind}'")

    @app.get("/")
    def index():
        return send_from_directory(STATIC_DIR, "index.html")

    @app.get("/<path:filename>")
    def static_file(filename: str):
        return send_from_directory(STATIC_DIR, filename)

    @app.get("/api/health")
    def health():
        return jsonify({"ok": True, "version": __version__, "offline": config.offline})

    @app.get("/api/strings")
    def strings():
        """UI labels for the browser (every key starting with 'web_')."""
        return jsonify({key: value for key, value in EN.items() if key.startswith("web_")})

    @app.post("/api/parse")
    def parse():
        return jsonify({"input": input_summary(read_input())})

    @app.post("/api/detect")
    def api_detect():
        inp = read_input(decode_bare=False)
        report = detect(inp.data, flagset)
        answer = {"input": input_summary(inp), "report": report.to_dict()}
        record(request.get_json(silent=True) or {}, "detect", inp, answer)
        return jsonify(answer)

    @app.post("/api/auto")
    def api_auto():
        work, budget = prepare("auto")
        return jsonify(work(budget))

    @app.post("/api/xor")
    def api_xor():
        work, budget = prepare("xor")
        return jsonify(work(budget))

    @app.post("/api/sym")
    def api_sym():
        work, budget = prepare("sym")
        return jsonify(work(budget))

    @app.post("/api/rsa")
    def api_rsa():
        work, budget = prepare("rsa")
        return jsonify(work(budget))

    @app.post("/api/keys")
    def api_keys():
        work, budget = prepare("keys")
        return jsonify(work(budget))

    @app.post("/api/hash")
    def api_hash():
        """Hash identification: instant, except the optional password-list try."""
        payload = read_payload()
        value = str(payload.get("input", "")).strip()
        if not value:
            raise InputError(t("web_empty_input"))
        options = payload.get("options") or {}
        report = identify_hash(value, try_passwords=not options.get("no_passwords"))
        return jsonify(report.to_dict())

    @app.post("/api/radius")
    def api_radius():
        """RADIUS PAP recovery: instant (undo RFC 2865, guess the shared secret)."""
        from ctfc.core import radius as radius_mod

        payload = read_payload()
        inp = input_from_payload(payload, decode_bare=False)  # the encrypted User-Password
        options = payload.get("options") or {}
        authenticator = option_bytes(options, "authenticator", decode_bare=False) or b""
        if len(authenticator) != 16:
            raise InputError(t("web_radius_bad_auth"))
        secret = str(options.get("secret") or "").strip()
        secrets = [secret.encode()] if secret else None
        found = radius_mod.recover(inp.data, authenticator, secrets, flagset=flagset)
        candidates = []
        for item in found[: config.top_n]:
            name = item.secret.decode("utf-8", "replace")
            candidates.append(
                Candidate(
                    label=f"shared secret {name!r}",
                    data=item.password,
                    score=1.0 if item.is_flag else min(1.0, item.score),
                    reasons=[
                        "matches a flag pattern" if item.is_flag else "fully printable password",
                        "RFC 2865 section 5.2: password XOR MD5(secret + authenticator)",
                    ],
                    params={"secret": name, "authenticator": authenticator.hex()},
                    python=radius_snippet(inp.data, authenticator, item.secret),
                ).to_dict()
            )
        notes = []
        if not found:
            notes = [t("web_radius_none_secret") if secret else t("web_radius_none")]
        answer = {"input": input_summary(inp), "candidates": candidates, "notes": notes}
        record(payload, "radius", inp, answer)
        return jsonify(answer)

    @app.post("/api/lens")
    def api_lens():
        """Code Lens: static analysis only, so it is fast enough to answer directly."""
        payload = read_payload()
        # A script stays text: never auto-decode it as hex/base64.
        inp = input_from_payload(payload, decode_bare=False)
        name = str(payload.get("name", ""))[:100]
        report = analyse_script(inp.data, filename=name, flagset=flagset)
        options = payload.get("options") or {}
        encrypted = option_bytes(options, "against", decode_bare=False)
        mirrored = []
        if encrypted:
            budget = Budget(max_attempts=200_000, max_seconds=30)
            mirrored = mirror_against(inp.data, report, encrypted, flagset, budget, config.top_n)
        answer = {"input": input_summary(inp), **report.to_dict()}
        answer["against"] = [candidate.to_dict() for candidate in mirrored]
        if not mirrored and report.peeled and report.recovery:
            best = report.peeled[0]
            answer["candidates"] = [
                Candidate(
                    best.label, best.data, best.score, best.reasons, python=report.recovery.python
                ).to_dict()
            ]
        record(payload, "lens", inp, answer)
        return jsonify(answer)

    def cyberchef_link(recipe: str | None, data: bytes) -> dict | None:
        """The "Open in CyberChef" link for a recipe, or why there is none."""
        if not recipe:
            return None
        base, note = toolbox.cyberchef_target(config.cyberchef_url, config.offline, for_web=True)
        limit = toolbox.CYBERCHEF_DATA_LIMIT
        return {
            "url": deep_link(recipe, data[:limit], base) if base else "",
            "public": bool(note) and bool(base),
            "note": note,
            "truncated": len(data) > limit,
        }

    @app.post("/api/recipe")
    def api_recipe():
        """Run a recipe step by step (fast: no search, only the given operations)."""
        payload = read_payload()
        # The recipe says which decodings to do: do not decode bare hex/base64 first.
        inp = input_from_payload(payload, decode_bare=False)
        options = payload.get("options") or {}
        name, steps = recipe_from_option(options.get("recipe"))
        result = pipeline.run(inp.data, steps, name, flagset)
        answer = {"input": input_summary(inp), **result.to_dict()}
        answer["recipe_json"] = pipeline.dump(name, steps)
        answer["cyberchef_link"] = cyberchef_link(result.cyberchef, inp.data)
        record(payload, "recipe", inp, answer)
        return jsonify(answer)

    @app.post("/api/cyberchef")
    def api_cyberchef():
        """Deep link for a result card's CyberChef recipe and the current input."""
        payload = read_payload()
        inp = input_from_payload(payload, decode_bare=False)
        recipe = str((payload.get("options") or {}).get("recipe") or "")
        link = cyberchef_link(recipe, inp.data)
        if link is None:
            raise InputError("no CyberChef recipe for this result")
        return jsonify(link)

    @app.post("/api/tools")
    def api_tools():
        """External tools worth trying here (empty list when nothing is confident)."""
        inp = read_input(decode_bare=False)
        signals, values = toolbox.gather(inp.data, None, flagset)
        values["cyberchef_url"] = toolbox.cyberchef_base(config.cyberchef_url, for_web=True)
        suggestions = toolbox.suggest(
            signals,
            values=values,
            offline=config.offline,
            threshold=config.suggest_threshold,
            limit=config.max_suggestions,
        )
        return jsonify({"suggestions": [item.to_dict() for item in suggestions]})

    @app.post("/api/tools/run")
    def api_tools_run():
        """Run one local tool from tools.toml on the input (argument list, no shell)."""
        payload = read_payload()
        inp = input_from_payload(payload, decode_bare=False)
        options = payload.get("options") or {}
        try:
            tool = toolbox.tool_by_id(str(options.get("tool") or ""))
        except ValueError as exc:
            raise InputError(str(exc)) from exc
        if tool.kind != "local":
            raise InputError(f"{tool.name} is not a local program: open it instead")
        _signals, values = toolbox.gather(inp.data, None, flagset)
        wordlist = str(options.get("wordlist") or "").strip()
        if wordlist:
            if not Path(wordlist).expanduser().is_file():
                raise InputError(f"wordlist not found: {wordlist}")
            values["wordlist"] = str(Path(wordlist).expanduser())
        if options.get("password"):
            values["password"] = str(options["password"])
        # Tools read files: give it a private copy of the input, removed afterwards.
        with tempfile.TemporaryDirectory(prefix="ctfc-") as folder:
            values["input"] = str(toolbox.write_input(inp.data, Path(folder)))
            result = toolbox.run_tool(tool, values)
        return jsonify(result.to_dict())

    @app.get("/api/cheatsheet")
    def cheatsheet():
        from ctfc.core.datafiles import load_cheatsheet

        return jsonify({"markdown": load_cheatsheet()})

    @app.get("/api/sessions")
    def list_sessions():
        current = sessions.current_session(sessions_base)
        return jsonify(
            {
                "current": current,
                "sessions": [
                    {"name": item.name, "title": item.meta().display_title()}
                    for item in sessions.list_sessions(sessions_base)
                ],
            }
        )

    @app.post("/api/sessions")
    def new_session():
        payload = read_payload()
        session = sessions.Session.open(str(payload.get("name") or ""), sessions_base)
        meta = session.update_meta(
            **{
                key: str(payload[key])
                for key in ("title", "ctf", "category", "description")
                if payload.get(key)
            }
        )
        return jsonify({"name": session.name, "title": meta.display_title()})

    @app.post("/api/sessions/<name>/note")
    def session_note(name: str):
        text = str(read_payload().get("text") or "").strip()
        if not text:
            raise InputError("the note is empty")
        sessions.Session.open(name, sessions_base, create=False).add_note(text)
        return jsonify({"ok": True})

    @app.post("/api/sessions/<name>/flag")
    def session_flag(name: str):
        flag = str(read_payload().get("flag") or "").strip()
        sessions.Session.open(name, sessions_base, create=False).update_meta(flag=flag)
        return jsonify({"ok": True})

    @app.get("/api/sessions/<name>/report")
    def session_report(name: str):
        session = sessions.Session.open(name, sessions_base, create=False)
        lang = request.args.get("lang", "en")
        text = build_report(session, lang=lang if lang in ("en", "fr") else "en")
        return Response(
            text,
            mimetype="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="{session.name}.md"'},
        )

    @app.post("/api/jobs/<kind>")
    def start_job(kind: str):
        work, budget = prepare(kind)
        return jsonify({"job": jobs.start(kind, work, budget).id})

    @app.get("/api/jobs/<job_id>")
    def job_status(job_id: str):
        job = jobs.get(job_id)
        if job is None:
            return jsonify({"error": "unknown job"}), 404
        return jsonify(job.to_dict())

    @app.post("/api/jobs/<job_id>/cancel")
    def cancel_job(job_id: str):
        return jsonify({"ok": jobs.cancel(job_id)})

    @app.errorhandler(RsaError)
    def bad_key(error: RsaError):
        return jsonify({"error": str(error)}), 400

    @app.errorhandler(sessions.SessionError)
    def bad_session(error: sessions.SessionError):
        return jsonify({"error": str(error)}), 400

    @app.errorhandler(RecipeError)
    def bad_recipe(error: RecipeError):
        return jsonify({"error": str(error)}), 400

    @app.errorhandler(InputError)
    def bad_input(error: InputError):
        return jsonify({"error": str(error)}), 400

    @app.errorhandler(413)
    def too_big(_error):
        return jsonify({"error": t("upload_too_big", limit=config.max_upload_mb)}), 413

    return app
