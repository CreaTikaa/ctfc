"""Flask application: serves the static UI and a small JSON API.

Security notes (CLAUDE.md hard rules):
- binds to 127.0.0.1 by default (see `ctfc serve`),
- upload size is capped (MAX_CONTENT_LENGTH),
- static files are served by Flask's `send_from_directory`, which refuses `..` paths.
"""

from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify, send_from_directory

from ctfc import __version__
from ctfc.config import Config
from ctfc.strings import t

STATIC_DIR = Path(__file__).parent / "static"


def create_app(config: Config | None = None) -> Flask:
    """Build the Flask app. `config` defaults to the built-in settings."""
    config = config or Config()
    app = Flask(__name__, static_folder=None)  # we serve static files ourselves
    app.config["MAX_CONTENT_LENGTH"] = config.max_upload_mb * 1024 * 1024
    app.config["CTFC"] = config

    @app.get("/")
    def index():
        return send_from_directory(STATIC_DIR, "index.html")

    @app.get("/<path:filename>")
    def static_file(filename: str):
        return send_from_directory(STATIC_DIR, filename)

    @app.get("/api/health")
    def health():
        return jsonify({"ok": True, "version": __version__, "offline": config.offline})

    @app.errorhandler(413)
    def too_big(_error):
        return jsonify({"error": t("upload_too_big", limit=config.max_upload_mb)}), 413

    return app
