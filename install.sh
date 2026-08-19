#!/usr/bin/env bash
# =============================================================================
# hiddify-toolkit installer
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/Alighaemi9731/hiddify-toolkit/main/install.sh)
#
# Installs to /opt/hiddify-toolkit, links `hiddify-toolkit` into PATH, and opens
# the menu. Re-running upgrades in place: /var/lib/hiddify-toolkit (which modules
# are enabled, their config and their backups) is never touched.
#
# Flags:  --no-menu   install/upgrade only, do not open the menu
#         --ref REF   install a specific branch or tag (default: main)
# =============================================================================
set -uo pipefail

REPO="Alighaemi9731/hiddify-toolkit"
REF="main"
OPEN_MENU=1
DEST=/opt/hiddify-toolkit
LINK=/usr/local/bin/hiddify-toolkit

while [ $# -gt 0 ]; do
  case "$1" in
    --no-menu) OPEN_MENU=0 ;;
    --ref) REF="${2:-main}"; shift ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || { echo "must run as root (use sudo)" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1; }
if ! need curl || ! need tar; then
  echo "installing prerequisites (curl, tar)..."
  apt-get update -qq >/dev/null 2>&1
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl tar >/dev/null 2>&1
fi

TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

echo "downloading $REPO@$REF ..."
if ! curl -fsSL "https://codeload.github.com/$REPO/tar.gz/refs/heads/$REF" -o "$TMP/src.tgz" &&
   ! curl -fsSL "https://codeload.github.com/$REPO/tar.gz/refs/tags/$REF"  -o "$TMP/src.tgz"; then
  echo "download failed — check the repo name, the ref, and this server's connectivity" >&2
  exit 1
fi

mkdir -p "$TMP/x"
tar xzf "$TMP/src.tgz" -C "$TMP/x" --strip-components=1 || { echo "extract failed" >&2; exit 1; }
[ -f "$TMP/x/bin/hiddify-toolkit" ] || { echo "archive looks wrong (no bin/hiddify-toolkit)" >&2; exit 1; }

# Replace the CODE only. State lives in /var/lib/hiddify-toolkit and is deliberately
# untouched, so an upgrade never forgets which modules are enabled.
rm -rf "$DEST.old"
[ -d "$DEST" ] && mv "$DEST" "$DEST.old"
mkdir -p "$DEST"
cp -a "$TMP/x/." "$DEST/"
rm -rf "$DEST.old"

chmod +x "$DEST/bin/hiddify-toolkit" 2>/dev/null
chmod +x "$DEST"/modules/*.sh 2>/dev/null
ln -sf "$DEST/bin/hiddify-toolkit" "$LINK"
mkdir -p /var/lib/hiddify-toolkit/{enabled,conf,backup}

# An upgrade must re-point the guard unit at the new tree and re-assert immediately,
# otherwise a module stays "enabled" while nothing is actually re-applying it.
# Adopt anything already applied on this box (by the old standalone scripts, or by a
# previous install) so it gets a marker and therefore guard protection, then re-assert.
"$LINK" adopt >/dev/null 2>&1 || true
if [ -f /etc/systemd/system/hiddify-toolkit-guard.timer ]; then
  "$LINK" reassert >/dev/null 2>&1
fi

echo
echo "  installed: hiddify-toolkit v$(cat "$DEST/VERSION" 2>/dev/null || echo '?')  ->  $DEST"
echo "  run it any time with:  hiddify-toolkit"
echo

# `curl ... | bash` leaves stdin consumed by the pipe, so an interactive menu would
# read garbage and spin. Only open it when stdin is a real terminal.
if [ "$OPEN_MENU" = "1" ]; then
  if [ -t 0 ]; then
    exec "$LINK"
  else
    echo "  (non-interactive shell detected — start the menu with: hiddify-toolkit)"
    echo
  fi
fi
