#!/usr/bin/env bash
# ============================================================
# scripts/record_demo.sh — Record, convert, and optimise the
# rai-guard terminal demo for embedding in README / docs.
#
# Dependencies (auto-checked below):
#   asciinema     brew install asciinema
#   svg-term-cli  npm i -g svg-term-cli
#   agg           cargo install agg   (optional, for GIF)
#
# Usage:
#   chmod +x scripts/record_demo.sh
#   ./scripts/record_demo.sh
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DOCS_DIR="$REPO_ROOT/docs"
CAST_FILE="$DOCS_DIR/demo.cast"
SVG_FILE="$DOCS_DIR/demo.svg"
GIF_FILE="$DOCS_DIR/demo.gif"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[record]${NC} $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC}  $*"; }
error() { echo -e "${RED}[error]${NC} $*" >&2; }

# ── Dependency checks ─────────────────────────────────────────────────────────
check_dep() {
  if ! command -v "$1" &>/dev/null; then
    error "$1 not found.  Install with: $2"
    exit 1
  fi
}

check_dep asciinema "brew install asciinema"
check_dep python3   "brew install python"

# ── Make sure raiguard is importable ─────────────────────────────────────────
if ! python3 -c "import raiguard" &>/dev/null; then
  warn "raiguard not installed in current env — installing in editable mode..."
  pip install -e "$REPO_ROOT[evidence,server]" --quiet
fi

# ── Create docs dir ───────────────────────────────────────────────────────────
mkdir -p "$DOCS_DIR"

# ── Record ────────────────────────────────────────────────────────────────────
info "Recording demo → $CAST_FILE"
info "The demo will play automatically. Press Ctrl-C to abort."
sleep 1

asciinema rec "$CAST_FILE" \
  --cols 100 \
  --rows 32 \
  --command "python3 $SCRIPT_DIR/demo_script.py" \
  --title "rai-guard — Runtime AI Compliance Guard" \
  --overwrite

info "Cast saved: $CAST_FILE"

# ── Convert to SVG ────────────────────────────────────────────────────────────
if command -v svg-term &>/dev/null; then
  info "Converting cast → SVG ($SVG_FILE)"
  svg-term \
    --in  "$CAST_FILE" \
    --out "$SVG_FILE" \
    --window \
    --no-cursor \
    --term iterm2 \
    --profile Dracula \
    --width 100 \
    --height 32
  info "SVG saved: $SVG_FILE"
  echo ""
  info "Add to README.md:"
  echo "  ![rai-guard demo](docs/demo.svg)"
else
  warn "svg-term not found — skipping SVG conversion."
  warn "Install: npm i -g svg-term-cli"
fi

# ── Convert to GIF (optional) ─────────────────────────────────────────────────
if command -v agg &>/dev/null; then
  info "Converting cast → GIF ($GIF_FILE)"
  agg "$CAST_FILE" "$GIF_FILE" --cols 100 --rows 32
  info "GIF saved: $GIF_FILE"
  echo ""
  info "Add to README.md (for GitHub — SVG doesn't animate in all renderers):"
  echo "  ![rai-guard demo](docs/demo.gif)"
else
  warn "agg not found — skipping GIF conversion (optional)."
  warn "Install: cargo install agg  (requires Rust)"
fi

echo ""
info "Done! Files in $DOCS_DIR:"
ls -lh "$DOCS_DIR"
