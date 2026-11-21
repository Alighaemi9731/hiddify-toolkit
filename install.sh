#!/usr/bin/env bash
# Toolkit 2 supports the Hiddify 14.2 layout. For Hiddify 12 use tag v1.8.2.
set -euo pipefail
REF=""
OPEN_MENU=1
ARCHIVE=""
SKIP_PERFORMANCE_DEFAULTS=0
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF="${2:?missing ref}"; shift ;;
    --no-menu) OPEN_MENU=0 ;;
    --archive) ARCHIVE="${2:?missing local release archive}"; shift ;;
    --no-performance-defaults) SKIP_PERFORMANCE_DEFAULTS=1 ;;
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
  if [ -z "$REF" ]; then
# >>> release resolver
    REF="$(python3 - <<'PYRESOLVE'
import json
import re
import sys
import urllib.request


def select_release(records):
    candidates = []
    for release in records:
        tag = release.get('tag_name', '')
        match = re.fullmatch(r'v2\.(\d+)\.(\d+)', tag)
        if match and not release.get('draft') and not release.get('prerelease') and release.get('published_at'):
            candidates.append(((int(match[1]), int(match[2])), tag))
    return max(candidates)[1] if candidates else None


def latest_release(fetch):
    releases = []
    page = 1
    while True:
        records = fetch(page)
        if not isinstance(records, list):
            raise ValueError('GitHub returned an invalid release list')
        releases.extend(records)
        if len(records) < 100:
            break
        page += 1
    tag = select_release(releases)
    if not tag:
        raise ValueError('No published stable Toolkit 2 release for Hiddify 14 was found')
    return tag


def fetch_page(page):
    url = f'https://api.github.com/repos/Alighaemi9731/hiddify-toolkit/releases?per_page=100&page={page}'
    request = urllib.request.Request(url, headers={'User-Agent': 'hiddify-toolkit-installer', 'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)


if __name__ == '__main__':
    try:
        print(latest_release(fetch_page))
    except Exception as exc:
        sys.exit(f'Cannot resolve the latest Toolkit 2 release: {exc}')
PYRESOLVE
)"
# <<< release resolver
  fi
  echo "Installing release/ref: $REF"
  curl -fsSL --max-time 90 "https://codeload.github.com/Alighaemi9731/hiddify-toolkit/tar.gz/$REF" -o "$TMP/source.tgz"
  mkdir "$TMP/source"
  tar xzf "$TMP/source.tgz" -C "$TMP/source" --strip-components=1
fi
SOURCE_VERSION="$(cat "$TMP/source/VERSION")"
[[ "$SOURCE_VERSION" =~ ^2\.[0-9]+\.[0-9]+$ ]] || { echo 'Refusing a release outside the Toolkit 2 / Hiddify 14 channel'; exit 1; }
if [[ "$REF" =~ ^v2\.[0-9]+\.[0-9]+$ ]] && [ "$SOURCE_VERSION" != "${REF#v}" ]; then
  echo 'Downloaded version does not match the selected release'; exit 1
fi
# Older Toolkit versions cannot remove the new kernel/service controls.
# >>> downgrade guard
python3 - "$SOURCE_VERSION" <<'PYDOWNGRADE'
import json
import os
from pathlib import Path
import sys


def check_downgrade(source_version, enabled, managed=False):
    performance = {'tcp-memory', 'tcp-timewait', 'rpxy-nodelay'}
    if tuple(map(int, source_version.split('.'))) < (2, 1, 0) and (managed or performance.intersection(enabled)):
        raise ValueError('Revert tcp-memory, tcp-timewait and rpxy-nodelay using Toolkit 2.1 before downgrading to 2.0.x')


if __name__ == '__main__':
    try:
        state = Path(os.environ.get('HT_STATE', '/var/lib/hiddify-toolkit'))
        settings = state/'settings.json'
        receipt = state/'performance.json'
        enabled = json.loads(settings.read_text()).get('enabled', []) if settings.exists() else []
        active = json.loads(receipt.read_text()) if receipt.exists() else {}
        check_downgrade(sys.argv[1], enabled, bool(active.get('parameters') or active.get('nodelay')))
    except Exception as exc:
        sys.exit(f'Cannot prove safe downgrade: {exc}')
PYDOWNGRADE
# <<< downgrade guard
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
if ! HT_SKIP_PERFORMANCE_DEFAULTS="$SKIP_PERFORMANCE_DEFAULTS" "$DEST/bin/hiddify-toolkit" bootstrap; then
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
