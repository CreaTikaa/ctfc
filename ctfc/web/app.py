"""Flask application: serves the static UI and a small JSON API.

Security notes (CLAUDE.md hard rules):
- binds to 127.0.0.1 by default (see `ctfc serve`),
- upload size is capped (MAX_CONTENT_LENGTH),
- static files are served by Flask's `send_from_directory`, which refuses `..` paths,
- the browser can never make the server read a local file (parse_input allow_files=False).

API (all POST bodies are JSON):
    {"input": "<text>", "format": "auto|text|hex|b64"}   pasted input
    {"data_b64": "<base64 of the file>", "name": "x.bin"}  uploaded file
"""

from __future__ import annotations

import base64
import binascii
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from ctfc import __version__
from ctfc.config import Config
from ctfc.core.auto import auto_decode
from ctfc.core.budget import Budget
from ctfc.core.detect import detect
from ctfc.core.flags import build_flagset
from ctfc.core.inputs import InputError, decode_base64, decode_hex, parse_input
from ctfc.core.types import Input
from ctfc.strings import EN, t

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

    def read_input(decode_bare: bool = True) -> Input:
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            raise InputError("expected a JSON object body")
        return input_from_payload(payload, decode_bare)

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
        return jsonify({"input": input_summary(inp), "report": report.to_dict()})

    @app.post("/api/auto")
    def api_auto():
        inp = read_input(decode_bare=False)
        budget = Budget(max_attempts=config.auto_budget, max_seconds=30)
        candidates = auto_decode(
            inp.data,
            flagset=flagset,
            max_depth=config.auto_max_depth,
            budget=budget,
            top_n=config.top_n,
        )
        return jsonify(
            {
                "input": input_summary(inp),
                "budget": budget.summary(),
                "candidates": [candidate.to_dict() for candidate in candidates],
            }
        )

    @app.errorhandler(InputError)
    def bad_input(error: InputError):
        return jsonify({"error": str(error)}), 400

    @app.errorhandler(413)
    def too_big(_error):
        return jsonify({"error": t("upload_too_big", limit=config.max_upload_mb)}), 413

    return app
