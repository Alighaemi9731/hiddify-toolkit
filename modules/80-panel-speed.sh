# shellcheck shell=bash
# =============================================================================
# hiddify-toolkit module: panel-speed
#
# Stop the admin dashboard from starving the panel of its single request slot.
#
# The panel is served by bjoern (/opt/hiddify-manager/hiddify-panel/app.py is five
# lines: `bjoern.run(...)` on 127.0.0.1:9000). bjoern is ONE process with ONE
# thread — the panel answers exactly one request at a time, fleet-wide, for every
# admin at once. There is no worker pool to absorb a slow handler.
#
# hutils/system.py's system_stats() contains three calls that are far too slow to
# sit in a request on that server:
#
#   psutil.cpu_percent(interval=1)            a 1.0 s sleep INSIDE the request
#   psutil.net_connections()                  walks every socket of every process
#                                             (measured 0.60 s at ~37k sockets)
#   get_folder_size('/opt/hiddify-manager/')  os.walk over ~17k files
#
# ~1.7 s per call, measured. It is reached from TWO places: Dashboard.index calls
# it on every /admin/ page load, and panel/admin/templates/index.html polls
# /api/v2/admin/server_status/ with `setInterval(..., refresh_s * 1000)` where
# refresh_s = 4 — unconditionally, without waiting for the previous response.
#
# So ONE open dashboard tab consumes ~1.7/4 = ~40% of the entire panel, and about
# three tabs saturate it permanently. Past that the accept queue on 127.0.0.1:9000
# grows without bound (Recv-Q climbs to the 1024 backlog, then the kernel drops
# SYNs), and the panel stops loading in a browser with NO error at all — just a
# spinner. HAProxy's `timeout client/server 50s` then resets those connections and
# bjoern logs `Client N hit errno 32/104`; s3 had 110,587 such lines in one day.
# Every abandoned request still burns its full 1.7 s slot, so the queue never
# recovers on its own. A reinstall only appears to fix it: the restart empties the
# queue, and it refills as soon as the tabs come back.
#
# Two changes, both inside the panel's venv, both undone by a Hiddify update and
# therefore re-asserted by the guard timer:
#
#   (a) an override block appended to hutils/system.py, which REBINDS the three
#       slow names in that module's namespace. Upstream's function body is not
#       rewritten and its output keys are not reproduced here, so a panel upgrade
#       that changes either keeps working.
#   (b) refresh_s in the dashboard template, 4 -> PANEL_REFRESH_S (default 20).
#
# Deliberately NOT done: caching system_stats() itself. It computes bytes_sent /
# bytes_recv as a delta against its own previous call, and the template divides
# that delta by refresh_s to draw Mb/s. Serving a cached snapshot would silently
# scale every bandwidth reading by (age / refresh_s).
# =============================================================================

# shellcheck disable=SC2034  # the core reads these after sourcing the module
{
MOD_ID="panel-speed"
MOD_TITLE="Panel dashboard speed"
MOD_DESC="The admin dashboard polls a ~1.7s system-stats call every 4s, and the panel serves one request at a time — so a few open tabs wedge it and the panel stops loading with no error. Makes that call ~10x cheaper and slows the poll."
MOD_GUARD=yes
}

_PS_BEGIN="# >>> hiddify-toolkit:panel-speed >>>"
_PS_END="# <<< hiddify-toolkit:panel-speed <<<"
_PS_JSTAG="// hiddify-toolkit:panel-speed"
_PS_UNIT="hiddify-panel"
_PS_DEFAULT_REFRESH=20

# --------------------------------------------------------------- locating ----

# The interpreter the RUNNING service uses, not whichever python is on $PATH.
_ps_python() {
  local py
  py="$(awk -F= '/^ExecStart=/ { print $2; exit }' \
        "/etc/systemd/system/${_PS_UNIT}.service" 2>/dev/null | awk '{print $1}')"
  [ -n "$py" ] && [ -x "$py" ] && { printf '%s\n' "$py"; return 0; }
  for py in /opt/hiddify-manager/.venv*/bin/python; do
    [ -x "$py" ] && { printf '%s\n' "$py"; return 0; }
  done
  return 1
}

# find_spec() does not execute a top-level package, so this cannot trip over a
# panel that is mid-upgrade or otherwise unimportable.
_ps_pkg() {
  local py; py="$(_ps_python)" || return 1
  "$py" - <<'PY' 2>/dev/null
import importlib.util, os
try:
    s = importlib.util.find_spec("hiddifypanel")
    print(os.path.dirname(s.origin) if s and s.origin else "")
except Exception:
    print("")
PY
}

_ps_sysfile()  { local p; p="$(_ps_pkg)" || return 1; [ -n "$p" ] || return 1; printf '%s/hutils/system.py\n' "$p"; }
_ps_tplfile()  { local p; p="$(_ps_pkg)" || return 1; [ -n "$p" ] || return 1; printf '%s/panel/admin/templates/index.html\n' "$p"; }

_ps_refresh()  { ht_conf_get refresh_s "$_PS_DEFAULT_REFRESH"; }

# ------------------------------------------------------------- the payload ---

# Written to stdout so apply and reassert compare and install the SAME text.
_ps_override() {
cat <<'PYEOF'
# >>> hiddify-toolkit:panel-speed >>>
# Appended by hiddify-toolkit (module: panel-speed). Do not edit by hand;
# `hiddify-toolkit revert panel-speed` removes this block.
#
# The panel runs on bjoern: one process, one thread, one request at a time. The
# three names rebound below are the slow parts of system_stats(), which the admin
# dashboard polls every few seconds. Upstream's functions are left exactly as they
# are -- only what they look up at call time changes -- so a panel upgrade that
# rewrites system_stats() or its output keys still works.

import socket as _ht_socket
import time as _ht_time
from collections import namedtuple as _ht_namedtuple

_HT_CONN_TTL = 5.0        # seconds a socket census is reused
_HT_WALK_TTL = 600.0      # seconds a directory size is reused

_HTAddr = _ht_namedtuple("_HTAddr", "ip port")
_HTConn = _ht_namedtuple("_HTConn", "status raddr")

# /proc/net/tcp state codes, in psutil's spelling.
_HT_TCP_STATE = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}
_HT_IP_CACHE = {}


def _ht_ip(hexs):
    """'0100007F' / 32 hex chars -> dotted or colonned address. Memoised: a busy
    panel has ~20k sockets across only a few thousand distinct peers."""
    got = _HT_IP_CACHE.get(hexs)
    if got is not None:
        return got
    try:
        if len(hexs) == 8:
            n = int(hexs, 16)
            got = "%d.%d.%d.%d" % (n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF, (n >> 24) & 0xFF)
        else:
            raw = b"".join(int(hexs[i:i + 8], 16).to_bytes(4, "little") for i in range(0, 32, 8))
            got = _ht_socket.inet_ntop(_ht_socket.AF_INET6, raw)
    except Exception:
        got = "0.0.0.0"
    if len(_HT_IP_CACHE) < 200000:
        _HT_IP_CACHE[hexs] = got
    return got


def _ht_read_connections():
    """The socket census psutil.net_connections(kind='inet') returns, read straight
    out of /proc/net instead. psutil's cost is not the parsing -- it is resolving
    every socket back to a pid by walking /proc/*/fd, which nothing here needs.

    raddr is materialised only for ESTABLISHED rows. That is the only state the
    panel reads an address from, and building 20k namedtuples nobody looks at is
    most of what makes the honest version slow."""
    out = []
    add = out.append
    for path, is_tcp in (("/proc/net/tcp", True), ("/proc/net/tcp6", True),
                         ("/proc/net/udp", False), ("/proc/net/udp6", False)):
        try:
            with open(path) as fh:
                fh.readline()
                for line in fh:
                    col = line.split(None, 5)
                    if len(col) < 4:
                        continue
                    if not is_tcp:
                        add(_HTConn("NONE", None))
                        continue
                    st = col[3]
                    if st == "01":
                        rem = col[2]
                        cut = rem.rfind(":")
                        try:
                            port = int(rem[cut + 1:], 16)
                        except Exception:
                            port = 0
                        add(_HTConn("ESTABLISHED", _HTAddr(_ht_ip(rem[:cut]), port)))
                    else:
                        add(_HTConn(_HT_TCP_STATE.get(st, "NONE"), None))
        except OSError:
            pass
    return out


class _HTPsutil:
    """psutil, with the two calls that must never block a request replaced. Every
    other attribute (virtual_memory, disk_usage, net_io_counters, process_iter,
    cpu_count, ...) is the real module's."""

    def __init__(self, real):
        self._real = real
        self._conn = []
        self._conn_at = 0.0
        try:
            real.cpu_percent(interval=None)   # prime the delta so the first read is real
        except Exception:
            pass

    def __getattr__(self, name):
        return getattr(self._real, name)

    def cpu_percent(self, interval=None, percpu=False):
        # interval=None measures since the PREVIOUS call, which for a dashboard
        # that polls on a timer is the window we actually want -- and it returns
        # immediately instead of sleeping a full second inside the request.
        try:
            return self._real.cpu_percent(interval=None, percpu=percpu)
        except Exception:
            return 0.0

    def net_connections(self, kind="inet"):
        now = _ht_time.monotonic()
        if self._conn and (now - self._conn_at) < _HT_CONN_TTL:
            return self._conn
        self._conn = _ht_read_connections()
        self._conn_at = now
        return self._conn


_ht_walk_cache = {}
_ht_real_get_folder_size = get_folder_size


def get_folder_size(folder_path: str) -> int:
    """/opt/hiddify-manager is ~17k files and its size is a number on a dashboard.
    Walking it per request is the wrong trade at any poll interval."""
    now = _ht_time.monotonic()
    got = _ht_walk_cache.get(folder_path)
    if got is not None and (now - got[0]) < _HT_WALK_TTL:
        return got[1]
    val = _ht_real_get_folder_size(folder_path)
    _ht_walk_cache[folder_path] = (now, val)
    return val


if not isinstance(psutil, _HTPsutil):       # re-import must not double-wrap
    psutil = _HTPsutil(psutil)
# <<< hiddify-toolkit:panel-speed <<<
PYEOF
}

# ----------------------------------------------------------------- probing ---

_ps_has_block() {                         # <file>
  [ -f "$1" ] && grep -qF "$_PS_BEGIN" "$1"
}

# The installed block, byte for byte, so a toolkit update that changes the payload
# is detected and re-installed instead of being reported as already applied.
_ps_block_matches() {                     # <file>
  local f="$1" live
  _ps_has_block "$f" || return 1
  live="$(sed -n "/^$(printf '%s' "$_PS_BEGIN" | sed 's/[][\.*^$/]/\\&/g')$/,/^$(printf '%s' "$_PS_END" | sed 's/[][\.*^$/]/\\&/g')$/p" "$f")"
  [ "$live" = "$(_ps_override)" ]
}

_ps_strip_block() {                       # <file>  -- remove block + the blank line before it
  local f="$1" tmp
  _ps_has_block "$f" || return 0
  tmp="$(mktemp)" || return 1
  awk -v b="$_PS_BEGIN" -v e="$_PS_END" '
    $0 == b { skip = 1 }
    !skip   { print }
    $0 == e { skip = 0 }
  ' "$f" > "$tmp" || { rm -f "$tmp"; return 1; }
  # drop trailing blank lines the block left behind
  awk 'BEGIN{n=0} { lines[NR]=$0 } END { last=NR; while (last>0 && lines[last] ~ /^[[:space:]]*$/) last--; for (i=1;i<=last;i++) print lines[i] }' "$tmp" > "$tmp.2" \
    && mv "$tmp.2" "$tmp"
  cat "$tmp" > "$f" && rm -f "$tmp"
}

_ps_tpl_value() {                         # <file> -> the live refresh_s, or ""
  [ -f "$1" ] || return 1
  sed -n 's/^[[:space:]]*var[[:space:]][[:space:]]*refresh_s[[:space:]]*=[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$1" | head -1
}

_ps_backlog() {                           # pending connections bjoern has not accepted
  ss -Hltn "sport = :9000" 2>/dev/null | awk '{print $2; exit}'
}

_ps_errno_lines() {
  local f=/opt/hiddify-manager/log/system/hiddify_panel.err.log
  [ -f "$f" ] && grep -c "hit errno" "$f" 2>/dev/null || echo 0
}

# Cost of one system_stats()+top_processes() as the panel pays it, in seconds.
_ps_measure() {
  local py; py="$(_ps_python)" || return 1
  "$py" - <<'PY' 2>/dev/null
import time
try:
    from hiddifypanel.hutils import system
    system.system_stats(); system.top_processes()          # warm
    t = time.time(); system.system_stats(); system.top_processes()
    print("%.3f" % (time.time() - t))
except Exception:
    print("")
PY
}

# ------------------------------------------------------------------ status ---

mod_status() {
  local sf tf want live blocked tplok=0 blockok=0 q errs

  if ! ht_is_hiddify; then echo "ABSENT  no /opt/hiddify-manager on this box"; return 0; fi
  sf="$(_ps_sysfile)" || { echo "UNKNOWN  cannot locate the hiddifypanel package"; return 0; }
  tf="$(_ps_tplfile)"
  want="$(_ps_refresh)"

  printf 'package         : %s\n' "$(dirname "$(dirname "$sf")")"
  if _ps_block_matches "$sf"; then
    blockok=1; printf 'system.py       : patched (current payload)\n'
  elif _ps_has_block "$sf"; then
    printf 'system.py       : patched, but with an OLDER payload — reassert will replace it\n'
  else
    printf 'system.py       : stock — cpu_percent(interval=1) sleeps 1s in every request\n'
  fi

  live="$(_ps_tpl_value "$tf")"
  if [ -z "$live" ]; then
    printf 'dashboard poll  : refresh_s not found in %s\n' "${tf:-?}"
  elif [ "$live" = "$want" ]; then
    tplok=1; printf 'dashboard poll  : every %ss\n' "$live"
  else
    printf 'dashboard poll  : every %ss (want %ss)\n' "$live" "$want"
  fi

  q="$(_ps_backlog)"; errs="$(_ps_errno_lines)"
  printf 'accept queue    : %s waiting on 127.0.0.1:9000%s\n' "${q:-?}" \
    "$([ -n "$q" ] && [ "$q" -gt 0 ] 2>/dev/null && printf '   <-- requests are QUEUING right now' || true)"
  printf 'reset clients   : %s "hit errno" lines in the panel error log\n' "$errs"
  blocked="$(_ps_measure)"
  [ -n "$blocked" ] && printf 'one stats call  : %ss of the panel'"'"'s single thread\n' "$blocked"

  if [ "$blockok" = "1" ] && [ "$tplok" = "1" ]; then
    echo "APPLIED  stats call is cheap, dashboard polls every ${want}s"
  elif [ "$blockok" = "1" ] || [ "$tplok" = "1" ]; then
    echo "PARTIAL  only half of the fix is in place"
  else
    echo "ABSENT  dashboard can still wedge the panel"
  fi
}

# ------------------------------------------------------------------- apply ---

# Install both halves. Prints nothing; returns 0 and sets _PS_CHANGED=1 if it wrote.
_ps_converge() {
  local sf tf want live tmp
  _PS_CHANGED=0
  sf="$(_ps_sysfile)" || { err "cannot locate the hiddifypanel package"; return 1; }
  [ -f "$sf" ] || { err "$sf does not exist"; return 1; }
  tf="$(_ps_tplfile)"
  want="$(_ps_refresh)"

  if ! _ps_block_matches "$sf"; then
    ht_backup "$sf"
    _ps_strip_block "$sf" || { err "could not clean the old block out of $sf"; return 1; }
    tmp="$(mktemp)" || return 1
    { cat "$sf"; printf '\n\n'; _ps_override; } > "$tmp" || { rm -f "$tmp"; return 1; }
    # Reject a payload the panel's own interpreter cannot even parse, BEFORE it
    # replaces a working file — a syntax error here takes the whole panel down.
    if ! "$(_ps_python)" -c "import py_compile,sys; py_compile.compile(sys.argv[1], doraise=True)" "$tmp" >/dev/null 2>&1; then
      err "the patched $sf does not compile — leaving the original in place"
      rm -f "$tmp"; return 1
    fi
    cat "$tmp" > "$sf" && rm -f "$tmp" || { rm -f "$tmp"; return 1; }
    _PS_CHANGED=1
  fi

  if [ -n "$tf" ] && [ -f "$tf" ]; then
    live="$(_ps_tpl_value "$tf")"
    if [ -n "$live" ] && [ "$live" != "$want" ]; then
      ht_backup "$tf"
      sed -i "s|^\([[:space:]]*\)var[[:space:]][[:space:]]*refresh_s[[:space:]]*=[[:space:]]*[0-9][0-9]*;.*|\1var refresh_s = ${want};  ${_PS_JSTAG}|" "$tf" || return 1
      [ "$(_ps_tpl_value "$tf")" = "$want" ] || { err "could not set refresh_s in $tf"; return 1; }
      _PS_CHANGED=1
    elif [ -z "$live" ]; then
      warn "refresh_s not found in $tf — the poll interval is unchanged"
    fi
  fi
  return 0
}

# Jinja compiles templates once and bjoern holds the patched module in memory, so
# neither half takes effect until the panel restarts. Only ever on a real change:
# the guard runs every two minutes.
_ps_restart() {
  systemctl restart "$_PS_UNIT" >/dev/null 2>&1 || return 1
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    ss -Hltn "sport = :9000" 2>/dev/null | grep -q . && return 0
    sleep 1
  done
  return 1
}

mod_apply() {
  local _PS_CHANGED before after
  ht_is_hiddify || { err "no /opt/hiddify-manager on this box"; return 1; }
  [ -n "${PANEL_REFRESH_S:-}" ] && ht_conf_set refresh_s "$PANEL_REFRESH_S"

  before="$(_ps_measure)"
  _ps_converge || return 1
  if [ "$_PS_CHANGED" = "1" ]; then
    _ps_restart || { err "panel did not come back up after the restart"; return 1; }
    ok "panel restarted"
  else
    ok "already in place"
  fi
  after="$(_ps_measure)"
  [ -n "$before" ] && [ -n "$after" ] && ok "one stats call: ${before}s -> ${after}s"
  ok "dashboard polls every $(_ps_refresh)s"
}

mod_verify() {
  local sf tf cost fail=0
  sf="$(_ps_sysfile)" || { err "cannot locate the hiddifypanel package"; return 1; }
  _ps_block_matches "$sf" || { err "the override block is not in $sf"; fail=1; }
  tf="$(_ps_tplfile)"
  if [ -n "$tf" ] && [ -f "$tf" ]; then
    [ "$(_ps_tpl_value "$tf")" = "$(_ps_refresh)" ] || { err "refresh_s in $tf is not $(_ps_refresh)"; fail=1; }
  fi
  # The point of the module is a number, so verify the number.
  cost="$(_ps_measure)"
  if [ -n "$cost" ] && awk -v c="$cost" 'BEGIN{exit !(c > 0.9)}'; then
    err "a stats call still costs ${cost}s — the override is not being used by the running code"
    fail=1
  fi
  systemctl is-active --quiet "$_PS_UNIT" || { err "$_PS_UNIT is not running"; fail=1; }
  return $fail
}

mod_revert() {
  local sf tf
  sf="$(_ps_sysfile)" || { err "cannot locate the hiddifypanel package"; return 1; }
  _ps_strip_block "$sf" || { err "could not remove the block from $sf"; return 1; }
  tf="$(_ps_tplfile)"
  if [ -n "$tf" ] && [ -f "$tf" ] && grep -qF "$_PS_JSTAG" "$tf"; then
    sed -i "s|^\([[:space:]]*\)var[[:space:]][[:space:]]*refresh_s[[:space:]]*=[[:space:]]*[0-9][0-9]*;.*${_PS_JSTAG}.*|\1var refresh_s = 4;|" "$tf"
  fi
  _ps_restart || { err "panel did not come back up after the restart"; return 1; }
  ok "stock system_stats() and a 4s poll are back"
}

mod_reassert() {
  local _PS_CHANGED
  _ps_converge || return 1
  [ "$_PS_CHANGED" = "1" ] && _ps_restart
  return 0
}
