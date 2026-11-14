#!/usr/bin/env bash
# Toolkit 2 supports the Hiddify 14.2 layout. For Hiddify 12 use tag v1.8.2.
set -euo pipefail
REF=main
OPEN_MENU=1
ARCHIVE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF="${2:?missing ref}"; shift ;;
    --no-menu) OPEN_MENU=0 ;;
    --archive) ARCHIVE="${2:?missing local release archive}"; shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
[ "$(id -u)" = 0 ] || { echo 'Run as root'; exit 1; }
VERSION="$(cat /opt/hiddify-manager/VERSION)"
[[ "$VERSION" =~ ^14\.2\.[0-9]+$ ]] || { echo "Toolkit 2 requires Hiddify 14.2.x. Hiddify 12: install tag v1.8.2."; exit 1; }
for cmd in curl tar python3 nft ip ss systemctl; do
  command -v "$cmd" >/dev/null || { echo "Missing prerequisite: $cmd"; exit 1; }
done
TMP="$(mktemp -d)"
trap 'rm -r -- "$TMP"' EXIT
if [ -n "$ARCHIVE" ]; then
  cp -- "$ARCHIVE" "$TMP/source.tgz"
  mkdir "$TMP/source"
  tar xzf "$TMP/source.tgz" -C "$TMP/source"
else
  curl -fsSL --max-time 90 "https://codeload.github.com/Alighaemi9731/hiddify-toolkit/tar.gz/$REF" -o "$TMP/source.tgz"
  mkdir "$TMP/source"
  tar xzf "$TMP/source.tgz" -C "$TMP/source" --strip-components=1
fi
python3 "$TMP/source/lib/toolkit.py" preflight
if [ -d /var/lib/hiddify-toolkit/enabled ] && find /var/lib/hiddify-toolkit/enabled -type f -print -quit | grep -q .; then
  echo 'Legacy Toolkit 1 modules are enabled. Revert/uninstall Toolkit 1 first.' >&2; exit 1
fi
# Prevent concurrent installers. The guard's file lock is separate from this lock.
exec 9>/run/hiddify-toolkit-installer.lock
flock -n 9 || { echo 'Another toolkit installer is running'; exit 1; }
DEST=/opt/hiddify-toolkit
[ ! -e "$DEST.previous" ] || { echo "$DEST.previous already exists; inspect the previous installation"; exit 1; }
if [ -d "$DEST" ]; then mv "$DEST" "$DEST.previous"; fi
cp -a "$TMP/source" "$DEST"
chmod +x "$DEST/bin/hiddify-toolkit"
ln -sf "$DEST/bin/hiddify-toolkit" /usr/local/bin/hiddify-toolkit
if ! "$DEST/bin/hiddify-toolkit" bootstrap; then
  # bootstrap restores prior feature settings before returning an error.
  rm -r -- "$DEST"
  if [ -d "$DEST.previous" ]; then
    mv "$DEST.previous" "$DEST"
  else
    rm -- /usr/local/bin/hiddify-toolkit
  fi
  echo 'Installation failed; prior code restored.' >&2; exit 1
fi
if [ -d "$DEST.previous" ]; then rm -r -- "$DEST.previous"; fi
echo "Installed Hiddify Toolkit $(cat "$DEST/VERSION")"
if [ "$OPEN_MENU" = 1 ] && [ -t 0 ]; then exec "$DEST/bin/hiddify-toolkit"; fi
