#!/usr/bin/env bash
# Download the official CyberChef release and install it as ctfc's embedded copy.
#
# Run this ONCE, at build time, on a machine with internet access:
#
#     scripts/fetch_vendor.sh            # install (skipped if already there)
#     scripts/fetch_vendor.sh --force    # reinstall
#
# Afterwards CyberChef is served by `ctfc serve` at /vendor/cyberchef/index.html
# and opened from file:// by the CLI: nothing is sent to gchq.github.io any more,
# and "Open in CyberChef" works offline.
#
# Why a script and not a commit: the release is ~80 MB. The folder is in
# .gitignore. ctfc never downloads anything by itself at run time (offline-first).
#
# Safety: the version, the URL and the SHA-256 of the zip are pinned below. The
# download is checked against that hash BEFORE it is unzipped; a mismatch stops
# everything. To upgrade, change the three values together (the hash is shown by
# `gh release view <tag> -R gchq/CyberChef --json assets`), then re-run the
# CyberChef tests: the recipe argument lists were checked against this version.
#
# CyberChef is (c) Crown Copyright, licensed under the Apache License 2.0. The
# licence and an attribution file are kept next to it.

set -euo pipefail

VERSION="v11.5.0"
ZIP_NAME="CyberChef_8cd426dd4f40f1423912d5fad91b578a86a65112.zip"
ZIP_URL="https://github.com/gchq/CyberChef/releases/download/${VERSION}/${ZIP_NAME}"
ZIP_SHA256="f6478925d3eaa16ec08626a85f5b85eed10d531a5e18700615fed7ecb024cccf"
LICENSE_URL="https://raw.githubusercontent.com/gchq/CyberChef/${VERSION}/LICENSE"

# Paths are relative to the repository, wherever the script is called from.
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${REPO}/ctfc/web/static/vendor/cyberchef"
STAMP="${TARGET}/VERSION"

FORCE=0
if [[ "${1:-}" == "--force" ]]; then
    FORCE=1
elif [[ -n "${1:-}" ]]; then
    echo "usage: $0 [--force]" >&2
    exit 2
fi

if [[ $FORCE -eq 0 && -f "$STAMP" && "$(cat "$STAMP")" == "$VERSION" && -f "$TARGET/index.html" ]]; then
    echo "CyberChef ${VERSION} is already installed in ${TARGET} (use --force to reinstall)."
    exit 0
fi

for program in curl unzip sha256sum; do
    if ! command -v "$program" > /dev/null; then
        echo "error: '$program' is needed (apt install $program)" >&2
        exit 1
    fi
done

# Work in a private temporary folder, removed whatever happens.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "Downloading CyberChef ${VERSION} (~80 MB) from GitHub..."
curl --fail --location --proto '=https' --tlsv1.2 --progress-bar \
    --output "$WORK/cyberchef.zip" "$ZIP_URL"

echo "Checking the SHA-256 of the download..."
ACTUAL="$(sha256sum "$WORK/cyberchef.zip" | cut -d' ' -f1)"
if [[ "$ACTUAL" != "$ZIP_SHA256" ]]; then
    echo "error: SHA-256 mismatch, the file is NOT the expected release." >&2
    echo "  expected: $ZIP_SHA256" >&2
    echo "  got:      $ACTUAL" >&2
    exit 1
fi

echo "Unpacking..."
unzip -q "$WORK/cyberchef.zip" -d "$WORK/unpacked"

# ctfc links to index.html. The release ships one (identical to the page named
# after the version, CyberChef_v11.5.0.html); older releases only had the latter.
ADDED="nothing"
if [[ ! -f "$WORK/unpacked/index.html" ]]; then
    PAGE="$(find "$WORK/unpacked" -maxdepth 1 -name 'CyberChef_*.html' | head -n 1)"
    if [[ -z "$PAGE" ]]; then
        echo "error: no index.html nor CyberChef_*.html in the zip: the release layout changed." >&2
        exit 1
    fi
    cp "$PAGE" "$WORK/unpacked/index.html"
    ADDED="index.html, a copy of $(basename "$PAGE")"
fi

# Keep the licence. The zip normally ships it; if not, fetch the one of this tag.
if ! ls "$WORK/unpacked" | grep -qi '^license'; then
    curl --fail --silent --location --proto '=https' --output "$WORK/unpacked/LICENSE" "$LICENSE_URL"
fi

cat > "$WORK/unpacked/ATTRIBUTION.txt" << EOF
CyberChef ${VERSION} - https://github.com/gchq/CyberChef
(c) Crown Copyright, licensed under the Apache License, Version 2.0 (see LICENSE).

This is an unmodified copy of the official release
${ZIP_URL}
sha256 ${ZIP_SHA256}
installed by ctfc's scripts/fetch_vendor.sh on $(date -u +%Y-%m-%d).
Added by ctfc: ${ADDED} (plus this file and VERSION).
EOF
echo "$VERSION" > "$WORK/unpacked/VERSION"

# Replace the old copy only now that the new one is complete.
rm -rf "$TARGET"
mkdir -p "$(dirname "$TARGET")"
mv "$WORK/unpacked" "$TARGET"

echo "Done: CyberChef ${VERSION} installed in ${TARGET}"
echo "Try it: ctfc serve, then 'Open in CyberChef' on a result (works offline)."
