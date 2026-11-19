#!/usr/bin/env bash
# Install the external tools ctfc names or runs that are not on this machine yet.
#
#     sudo scripts/install_tools.sh               # everything (about 2 GB, 10-20 min)
#     sudo scripts/install_tools.sh --no-ghidra   # everything but Ghidra + its JDK (~800 MB)
#     sudo scripts/install_tools.sh --no-gui      # no Ghidra, Audacity, Sonic Visualiser
#     scripts/install_tools.sh --help
#
# Written for Debian 12 (bookworm), checked on 2026-11-19. Afterwards run
# `ctfc doctor` and `ctfc tools --list`: every tool below should say installed.
#
# What, and where from:
#   apt (Debian's own packages)  outguess, stegsnow, hcxtools (hcxpcapngtool),
#                                audacity, sonic-visualiser, + build/runtime deps
#   John the Ripper "jumbo"      built from source (openwall/john, pinned commit).
#                                Debian's `john` package is the *core* build: no
#                                zip2john/pdf2john/rar2john and few formats, so
#                                it is NOT installed. Gives john, zip2john,
#                                rar2john, keepass2john, 7z2john.pl, pdf2john.pl,
#                                office2john.py and every other *2john.
#   bkcrack 1.8.1                ZipCrypto known-plaintext attack (GitHub release)
#   jadx 1.5.6                   Android DEX/APK decompiler (GitHub release)
#   sstv (colaclanth)            SSTV audio -> image, in its own venv (pinned commit;
#                                the "sstv" on PyPI is a different project)
#   Temurin JDK 25 + Ghidra 12.2 Ghidra 12 needs JDK 25, Debian 12 stops at 17:
#                                the JDK goes next to Ghidra, used only by it.
#
# Where: everything under $PREFIX (default /opt/ctfc-tools), with a launcher per
# command in $BIN (default /usr/local/bin). Nothing else is touched; to remove
# it all: sudo rm -rf /opt/ctfc-tools and the launchers this script lists at
# the end (each one says "ctfc install_tools" inside).
#
# Safety: every download has its version, URL and SHA-256 pinned below and is
# checked BEFORE it is unpacked; a mismatch stops the script. git sources are
# checked out at a pinned commit. Re-running the script skips what is there.
# To upgrade a tool, change its values together (GitHub shows each asset's
# digest: `gh api repos/<owner>/<repo>/releases/latest --jq '.assets[]|[.name,.digest]'`).

set -euo pipefail

# ---------------------------------------------------------------------------
# Pinned versions
# ---------------------------------------------------------------------------

JOHN_REPO="https://github.com/openwall/john.git"
JOHN_COMMIT="5184bc0b8c105f8c5978b112e723d65b2de3e63e"   # bleeding-jumbo, 2026-10-11

BKCRACK_VERSION="1.8.1"
BKCRACK_URL="https://github.com/kimci86/bkcrack/releases/download/v${BKCRACK_VERSION}/bkcrack-${BKCRACK_VERSION}-Linux-x86_64.tar.gz"
BKCRACK_SHA256="45dc7d81adbaaad5c0aa2d8615ea920fd08b732fda1ea945504e0a3e8dc1d2ab"

JADX_VERSION="1.5.6"
JADX_URL="https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip"
JADX_SHA256="545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974"

SSTV_REPO="https://github.com/colaclanth/sstv"
SSTV_COMMIT="3e556eee8ad4c4425799cb652bac26ee58f8e113"   # 2019-11-04, the last one

JDK_NAME="jdk-25.0.5+8"
JDK_URL="https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.5%2B8/OpenJDK25U-jdk_x64_linux_hotspot_25.0.5_8.tar.gz"
JDK_SHA256="68982529869257d0ee6b824ec5aa270ff8b118bb438670da0b97ebdab178d7fb"

GHIDRA_NAME="ghidra_12.2_PUBLIC"
GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.2_build/ghidra_12.2_PUBLIC_20261016.zip"
GHIDRA_SHA256="2c2cd776db3c1f6a097ba418922378ac3649cadd5e844a6f5f088ae628a7be67"

APT_TOOLS=(outguess stegsnow hcxtools)
APT_GUI=(audacity sonic-visualiser)
APT_DEPS=(
    ca-certificates curl git unzip tar coreutils
    build-essential pkg-config libssl-dev zlib1g-dev yasm libgmp-dev libpcap-dev libbz2-dev
    libcompress-raw-lzma-perl     # 7z2john.pl
    python3 python3-venv          # the sstv venv, the *2john.py scripts
    libsndfile1                   # sstv reads audio through it
    openjdk-17-jre                # jadx (Java 11+)
)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

PREFIX="${CTFC_TOOLS_PREFIX:-/opt/ctfc-tools}"
BIN="${CTFC_TOOLS_BIN:-/usr/local/bin}"
WITH_GHIDRA=1
WITH_GUI=1
WITH_APT=1

usage() {
    sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    cat <<'EOF'
Options:
  --no-ghidra   skip Ghidra and its JDK (the two biggest downloads)
  --no-gui      skip every program with a window (Ghidra, Audacity, Sonic Visualiser)
  --no-apt      do not call apt (the dependencies must already be there)
  --help        this text
Environment (for a test install without root, with --no-apt):
  CTFC_TOOLS_PREFIX (default /opt/ctfc-tools), CTFC_TOOLS_BIN (default /usr/local/bin)
EOF
}

for arg in "$@"; do
    case "$arg" in
        --no-ghidra) WITH_GHIDRA=0 ;;
        --no-gui) WITH_GUI=0; WITH_GHIDRA=0 ;;
        --no-apt) WITH_APT=0 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $arg (see --help)" >&2; exit 2 ;;
    esac
done

if [[ $WITH_APT -eq 1 && $(id -u) -ne 0 ]]; then
    echo "run it with sudo: sudo $0 $*   (or --no-apt for a test install)" >&2
    exit 1
fi

# The person who ran sudo: John's run/ folder is given to them, because john
# writes its john.pot (the cracked passwords) next to itself.
OWNER="${SUDO_USER:-$(id -un)}"

say() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok() { printf '    \033[32mok\033[0m %s\n' "$*"; }

mkdir -p "$PREFIX" "$BIN"
DOWNLOADS="$PREFIX/.downloads"
mkdir -p "$DOWNLOADS"

# fetch URL SHA256 FILE: download once, then refuse anything with another hash.
fetch() {
    local url="$1" sha="$2" file="$DOWNLOADS/$3"
    if [[ ! -f "$file" ]]; then
        curl -fL --retry 3 --proto '=https' -o "$file.part" "$url"
        mv "$file.part" "$file"
    fi
    if ! echo "$sha  $file" | sha256sum -c --quiet -; then
        echo "SHA-256 mismatch for $file: deleted, nothing installed from it" >&2
        rm -f "$file"
        exit 1
    fi
}

# launcher NAME TARGET [ENV...]: a tiny script in $BIN that runs TARGET by its
# real path (John and Ghidra find their own files from their path, which a
# symlink would hide).
launcher() {
    local name="$1" target="$2"
    shift 2
    {
        echo '#!/bin/sh'
        echo "# ctfc install_tools launcher for $target"
        for assignment in "$@"; do echo "export $assignment"; done
        echo "exec \"$target\" \"\$@\""
    } > "$BIN/$name"
    chmod 755 "$BIN/$name"
    LAUNCHERS+=("$BIN/$name")
}
LAUNCHERS=()

# ---------------------------------------------------------------------------
# 1. Debian packages
# ---------------------------------------------------------------------------

if [[ $WITH_APT -eq 1 ]]; then
    say "Debian packages"
    packages=("${APT_DEPS[@]}" "${APT_TOOLS[@]}")
    if [[ $WITH_GUI -eq 1 ]]; then
        packages+=("${APT_GUI[@]}")
    fi
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
    ok "${packages[*]}"
fi

# ---------------------------------------------------------------------------
# 2. John the Ripper, jumbo (from source)
# ---------------------------------------------------------------------------

say "John the Ripper jumbo (commit ${JOHN_COMMIT:0:10}) - the build takes a few minutes"
JOHN_DIR="$PREFIX/john"
if [[ -x "$JOHN_DIR/run/john" ]] && [[ "$(git -C "$JOHN_DIR" rev-parse HEAD 2>/dev/null)" == "$JOHN_COMMIT" ]]; then
    ok "already built"
else
    rm -rf "$JOHN_DIR"
    git clone --quiet --filter=blob:none --no-checkout "$JOHN_REPO" "$JOHN_DIR"
    git -C "$JOHN_DIR" checkout --quiet "$JOHN_COMMIT"
    (
        cd "$JOHN_DIR/src"
        ./configure > configure.log 2>&1 || { tail -30 configure.log; exit 1; }
        make -s clean > /dev/null
        make -s -j"$(nproc)" > make.log 2>&1 || { tail -30 make.log; exit 1; }
    )
    ok "built in $JOHN_DIR/run"
fi
chown -R "$OWNER" "$JOHN_DIR/run"
# john itself, the *2john programs it builds (zip2john, rar2john...: the same
# binary under another name), and every *2john script of run/.
launcher john "$JOHN_DIR/run/john"
chmod a+x "$JOHN_DIR"/run/*2john*   # the .py/.pl scripts start with a #! line
for tool in "$JOHN_DIR"/run/*2john*; do
    [[ -x "$tool" && -f "$tool" ]] || continue
    launcher "$(basename "$tool")" "$tool"
done
ok "john + $(ls "$JOHN_DIR"/run/*2john* | wc -l) *2john tools"

# ---------------------------------------------------------------------------
# 3. bkcrack
# ---------------------------------------------------------------------------

say "bkcrack $BKCRACK_VERSION"
fetch "$BKCRACK_URL" "$BKCRACK_SHA256" "bkcrack-$BKCRACK_VERSION.tar.gz"
rm -rf "$PREFIX/bkcrack-$BKCRACK_VERSION"
mkdir -p "$PREFIX/bkcrack-$BKCRACK_VERSION"
tar -xzf "$DOWNLOADS/bkcrack-$BKCRACK_VERSION.tar.gz" -C "$PREFIX/bkcrack-$BKCRACK_VERSION" --strip-components=1
launcher bkcrack "$PREFIX/bkcrack-$BKCRACK_VERSION/bkcrack"
ok "$("$BIN/bkcrack" --help 2>&1 | head -1)"

# ---------------------------------------------------------------------------
# 4. jadx
# ---------------------------------------------------------------------------

say "jadx $JADX_VERSION"
fetch "$JADX_URL" "$JADX_SHA256" "jadx-$JADX_VERSION.zip"
rm -rf "$PREFIX/jadx-$JADX_VERSION"
unzip -q "$DOWNLOADS/jadx-$JADX_VERSION.zip" -d "$PREFIX/jadx-$JADX_VERSION"
chmod 755 "$PREFIX/jadx-$JADX_VERSION/bin/"*
launcher jadx "$PREFIX/jadx-$JADX_VERSION/bin/jadx"
launcher jadx-gui "$PREFIX/jadx-$JADX_VERSION/bin/jadx-gui"
ok "jadx $("$BIN/jadx" --version 2>/dev/null | tail -1)"

# ---------------------------------------------------------------------------
# 5. sstv (colaclanth), in its own virtualenv
# ---------------------------------------------------------------------------

say "sstv (colaclanth, commit ${SSTV_COMMIT:0:10})"
SSTV_VENV="$PREFIX/sstv-venv"
if [[ ! -x "$SSTV_VENV/bin/sstv" ]]; then
    rm -rf "$SSTV_VENV"
    python3 -m venv "$SSTV_VENV"
    "$SSTV_VENV/bin/pip" install --quiet --upgrade pip
    "$SSTV_VENV/bin/pip" install --quiet "git+${SSTV_REPO}@${SSTV_COMMIT}"
fi
launcher sstv "$SSTV_VENV/bin/sstv"
ok "$("$BIN/sstv" --help 2>&1 | head -1)"

# ---------------------------------------------------------------------------
# 6. Temurin JDK 25 + Ghidra 12.2
# ---------------------------------------------------------------------------

if [[ $WITH_GHIDRA -eq 1 ]]; then
    say "Temurin $JDK_NAME (for Ghidra only)"
    fetch "$JDK_URL" "$JDK_SHA256" "$JDK_NAME.tar.gz"
    if [[ ! -x "$PREFIX/$JDK_NAME/bin/java" ]]; then
        tar -xzf "$DOWNLOADS/$JDK_NAME.tar.gz" -C "$PREFIX"
    fi
    ok "$("$PREFIX/$JDK_NAME/bin/java" -version 2>&1 | head -1)"

    say "Ghidra 12.2 (a 570 MB download)"
    fetch "$GHIDRA_URL" "$GHIDRA_SHA256" "$GHIDRA_NAME.zip"
    if [[ ! -x "$PREFIX/$GHIDRA_NAME/ghidraRun" ]]; then
        unzip -q "$DOWNLOADS/$GHIDRA_NAME.zip" -d "$PREFIX"
    fi
    # Ghidra looks for its JDK itself; point it at the one above, not Debian's 17.
    properties="$PREFIX/$GHIDRA_NAME/support/launch.properties"
    sed -i '/^JAVA_HOME_OVERRIDE=/d' "$properties"
    echo "JAVA_HOME_OVERRIDE=$PREFIX/$JDK_NAME" >> "$properties"
    launcher ghidraRun "$PREFIX/$GHIDRA_NAME/ghidraRun"
    launcher analyzeHeadless "$PREFIX/$GHIDRA_NAME/support/analyzeHeadless"
    ok "ghidraRun, analyzeHeadless (JDK: $PREFIX/$JDK_NAME)"
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

say "Installed. Launchers written (remove them with rm to uninstall):"
printf '    %s\n' "${LAUNCHERS[@]}"
cat <<EOF

The downloads are kept in $DOWNLOADS (delete it to free the space).
Check with:   ctfc doctor   and   ctfc tools --list
EOF
