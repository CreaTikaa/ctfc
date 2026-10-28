#!/usr/bin/env bash
# Build an offline bundle: a folder that installs ctfc on a machine with NO internet.
#
#     make bundle            # or: scripts/make_bundle.sh
#
# Run it at home, with internet, BEFORE the CTF. It produces dist/ctfc-bundle/:
#
#     wheels/              ctfc + pycryptodome + flask + rich and their dependencies
#     install.sh           creates .venv and installs from wheels/ only (--no-index)
#     README-OFFLINE.md    the "day of the CTF" quick start
#
# Copy the folder (USB stick, shared drive) and on the CTF machine run
# `./install.sh`. Nothing is downloaded there.
#
# The embedded CyberChef goes INSIDE the ctfc wheel when it has been fetched
# (`make vendor`): run that first, or "Open in CyberChef" will fall back to the
# public instance (refused in offline mode).
#
# The wheels match THIS machine (OS, CPU, Python version): pycryptodome has
# compiled code. For another platform, add for example
#     BUNDLE_PLATFORM=win_amd64 BUNDLE_PYTHON=3.11 scripts/make_bundle.sh
# which also downloads the binary wheels for that platform.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PYTHON:-$REPO/.venv/bin/python}"
OUT="$REPO/dist/ctfc-bundle"

if [[ ! -x "$PY" ]]; then
    echo "error: $PY not found (create the virtualenv with: make venv)" >&2
    exit 1
fi
if [[ ! -f "$REPO/ctfc/web/static/vendor/cyberchef/index.html" ]]; then
    echo "warning: the embedded CyberChef is missing: run 'make vendor' first to include it" >&2
fi

rm -rf "$OUT"
mkdir -p "$OUT/wheels"

echo "Building the ctfc wheel and collecting its dependencies..."
"$PY" -m pip wheel --quiet --wheel-dir "$OUT/wheels" "$REPO"

if [[ -n "${BUNDLE_PLATFORM:-}" ]]; then
    echo "Adding binary wheels for ${BUNDLE_PLATFORM} (Python ${BUNDLE_PYTHON:-3.11})..."
    "$PY" -m pip download --quiet --only-binary=:all: --dest "$OUT/wheels" \
        --platform "$BUNDLE_PLATFORM" --python-version "${BUNDLE_PYTHON:-3.11}" \
        pycryptodome flask rich
fi

cat > "$OUT/install.sh" << 'EOF'
#!/usr/bin/env bash
# Install ctfc from the wheels next to this script, without internet.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"
"$PYTHON" -m venv "$HERE/.venv"
"$HERE/.venv/bin/pip" install --quiet --no-index --find-links "$HERE/wheels" ctfc
echo "ctfc installed: $HERE/.venv/bin/ctfc"
echo "Try: $HERE/.venv/bin/ctfc cheatsheet"
EOF
chmod +x "$OUT/install.sh"

cp "$REPO/docs/day-of-the-ctf.md" "$OUT/README-OFFLINE.md"

echo "Done: $OUT"
ls -1 "$OUT/wheels"
du -sh "$OUT"
