# shellcheck shell=bash
# =============================================================================
# hiddify-toolkit module: ech-param — one fixed `ech` value on every TLS config
# =============================================================================
# What the panel does on its own, and why it is useless here: with the TLS ECH
# switch on, hutils/proxy/shared.py calls get_ech_info(sni), which resolves the
# SNI's HTTPS RR against 1.1.1.1, pulls the ECHConfigList out of it and
# base64-encodes it into the link. For a CDN/fake SNI that record is either
# absent (so no ech param at all) or Cloudflare's own public ECH keys, which are
# not the keys of the tunnel the client is about to open — so the client either
# ignores it or fails the handshake. It also costs a DNS lookup per domain while
# a subscription is being rendered.
#
# What a client actually wants is to be told WHERE to fetch ECH keys at run time:
# `ech=udp://1.1.1.1` is that instruction, and xray-core / sing-box resolve it
# themselves at connect time. That value cannot be typed into the panel — the ECH
# field is not an operator input, it is computed — hence this module.
#
# THE EDIT IS ONE LINE, AND DELIBERATELY NOT THE OBVIOUS ONE. The obvious site is
#   if proxy.get('ech'): q['ech'] = proxy['ech']
# in to_link(), but writing through `q` means urlencode() renders the value as
# ech=udp%3A%2F%2F1.1.1.1. That decodes correctly and every client accepts it, yet
# it is not what an operator comparing links expects to see. ":" and "/" are legal
# in a query value (RFC 3986 §3.4), so we append the param AFTER urlencode and the
# link reads exactly `ech=udp://1.1.1.1`. The same edit pops any value the panel's
# own ECH path may have put in `q`, so the two can never both emit an `ech` param.
#
# SCOPE IS `q['security'] == 'tls'`, which is the file's own classification, set a
# few lines above the patch: 'reality' for reality, 'none' for plain http, 'tls'
# for tls and quic. So TLS-bearing configs get the param and nothing else does —
# which is the whole request — and it holds without this module having to re-derive
# what counts as TLS.
#
# WHAT THIS DOES NOT TOUCH, on purpose:
#   - vmess links (xray.py builds those as base64 JSON, a different field), and
#   - sing-box / xray-json subscriptions, where `ech` is an object whose `config`
#     must be a real ECHConfigList — `udp://1.1.1.1` there would be invalid, not
#     merely useless. Those paths keep the panel's own behaviour.
#
# WHAT UNDOES IT: not apply-config — the venv is not rebuilt by it. A Hiddify
# UPDATE is, because update_panel() runs `uv pip install -U --force-reinstall
# hiddifypanel`. mod_reassert watches for exactly that, with the two rules the
# other code-patching modules learned the hard way: never restart when the patch
# is already in place, and restart only if the panel was up before we touched it.
# =============================================================================

# shellcheck disable=SC2034  # the core reads these after sourcing the module
{
MOD_ID="ech-param"
MOD_TITLE="Fixed ech value on TLS configs"
MOD_DESC="Puts one fixed ech value (default udp://1.1.1.1) on every TLS config in the subscription links, instead of the useless base64 the panel resolves from DNS. Patches panel code, so a Hiddify update wipes it — the guard re-applies it."
MOD_GUARD=yes
}

_EC_TAG="hiddify-toolkit:ech-param"
_EC_UNIT="hiddify-panel"
_EC_PROBE="http://127.0.0.1:9000/"
_EC_REL="lib/python*/site-packages/hiddifypanel/hutils/proxy/xray.py"
_EC_DEFAULT="udp://1.1.1.1"

# The pristine line, matched as a fixed string. Verified unique on 12.0.0.
_EC_OLD='    return f"{baseurl}?{urlencode(q, quote_via=quote)}#{name_link}"'

# --------------------------------------------------------------- the value ---
# Baked into a single-quoted Python string, so the charset is a safety gate, not
# cosmetics: a quote or a backslash in here would end the string and let the rest
# of the value run as code inside the panel. Length-capped for the same reason.
_ec_value_ok() {                          # <value>
  case "$1" in
    *[!A-Za-z0-9._:/%+-]*) return 1 ;;
  esac
  [ -n "$1" ] && [ "${#1}" -le 120 ]
}

_ec_value() {
  local v
  v="$(ht_conf_get ech_value "$_EC_DEFAULT")"
  _ec_value_ok "$v" || v="$_EC_DEFAULT"
  printf '%s\n' "$v"
}

# The replacement block, built around the configured value.
_ec_new_block() {                         # <value>
  cat <<PYBLOCK
    # $_EC_TAG — one fixed ech value on TLS configs; see the module for why
    if q.get('security') == 'tls':
        q.pop('ech', None)
        _ht_ech = '$1'
    else:
        _ht_ech = None
    _ht_qs = urlencode(q, quote_via=quote)
    if _ht_ech:
        _ht_qs = _ht_qs + '&ech=' + _ht_ech
    return f"{baseurl}?{_ht_qs}#{name_link}"
PYBLOCK
}

# --------------------------------------------------------------- discovery ---
_ec_targets() {
  (
    shopt -s nullglob
    # shellcheck disable=SC2206
    local -a m=( /opt/hiddify-manager/.venv*/$_EC_REL )
    [ "${#m[@]}" -gt 0 ] && printf '%s\n' "${m[@]}"
    return 0
  )
}

_ec_target_count() {
  local -a m=()
  mapfile -t m < <(_ec_targets)
  printf '%s\n' "${#m[@]}"
}

# Exactly one or nothing — two venvs left by an upgrade means we cannot know which
# tree the running panel imports from, and patching the wrong one looks applied.
_ec_target() {
  local -a m=()
  mapfile -t m < <(_ec_targets)
  [ "${#m[@]}" -eq 1 ] || return 1
  printf '%s\n' "${m[0]}"
}

# Occurrences, not matching lines.
_ec_count() {                             # <file> <fixed-string> -> integer
  local n
  [ -f "$1" ] || { printf '0\n'; return 0; }
  n="$(grep -oF -e "$2" -- "$1" 2>/dev/null | wc -l | tr -dc '0-9')" || n=""
  printf '%s\n' "${n:-0}"
}

_ec_python() {
  local p
  for p in /opt/hiddify-manager/.venv*/bin/python3 /opt/hiddify-manager/.venv*/bin/python; do
    [ -x "$p" ] && { printf '%s\n' "$p"; return 0; }
  done
  p="$(command -v python3 2>/dev/null)" || return 1
  [ -n "$p" ] || return 1
  printf '%s\n' "$p"
}

_ec_unit_exists() { systemctl cat "$_EC_UNIT" >/dev/null 2>&1; }

_ec_panel_state() {
  local s
  s="$(systemctl is-active "$_EC_UNIT" 2>/dev/null)" || true
  printf '%s\n' "${s:-unknown}"
}

# A Type=simple unit reads "active" the moment exec() returns, before the
# interpreter has imported xray.py — so a panel that dies on import passes a bare
# is-active check. Re-check after a settle, which is the window that failure needs.
_ec_wait_panel() {                        # <max-seconds>
  local deadline=$(( SECONDS + ${1:-20} ))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if [ "$(_ec_panel_state)" = "active" ]; then
      sleep 3
      [ "$(_ec_panel_state)" = "active" ] && return 0
    fi
    sleep 1
  done
  [ "$(_ec_panel_state)" = "active" ]
}

_ec_restart_panel() {
  _ec_unit_exists || return 1
  systemctl restart "$_EC_UNIT" >/dev/null 2>&1 || true
  _ec_wait_panel 25
}

# 400 is the HEALTHY answer on 9000 — the panel only serves under its secret path.
_ec_http_probe() {
  local code
  command -v curl >/dev/null 2>&1 || { printf 'n/a\n'; return 0; }
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "$_EC_PROBE" 2>/dev/null)" || code=""
  printf '%s\n' "${code:-none}"
}

# ------------------------------------------------------- end-to-end probe ----
# The point of this module is what the SUBSCRIPTION says, so verification fetches
# one and reads it. Everything needed is on the box: the client proxy path from
# current.json, any user's uuid from the panel DB, and a servable domain. Resolved
# to 127.0.0.1 so the check never leaves the host and never depends on public DNS.
#
# Exit codes are three-valued on purpose. 2 ("could not look") must not be
# reported as 0 ("looked, and it is right") — that is how a probe that silently
# stopped working becomes a green light forever.
_EC_PROBE_MSG=""
_ec_live_probe() {                        # <value> -> 0 ok / 1 wrong / 2 unknown
  local want="$1" path uuid dom body tls_lines hit bad
  _EC_PROBE_MSG=""
  command -v curl >/dev/null 2>&1 || { _EC_PROBE_MSG="curl not installed"; return 2; }

  path="$(python3 - <<'PY' 2>/dev/null
import json
try:
    c = json.load(open("/opt/hiddify-manager/current.json"))
    h = c.get("chconfigs", {}).get("0") or c.get("hconfigs") or {}
    print(h.get("proxy_path_client") or "")
except Exception:
    print("")
PY
)" || path=""
  [ -n "$path" ] || { _EC_PROBE_MSG="no proxy_path_client in current.json"; return 2; }

  uuid="$(mysql -N -B -e 'select uuid from hiddifypanel.user limit 1' 2>/dev/null | head -1 | tr -dc 'a-f0-9-')"
  [ -n "$uuid" ] || { _EC_PROBE_MSG="no user in the panel DB to build a sub link with"; return 2; }

  dom="$(mysql -N -B -e "select domain from hiddifypanel.domain where mode in ('cdn','direct') limit 1" 2>/dev/null | head -1 | tr -dc 'A-Za-z0-9.-')"
  [ -n "$dom" ] || { _EC_PROBE_MSG="no cdn/direct domain in the panel DB"; return 2; }

  # A non-Hiddify UA, because the Hiddify app is served sing-box JSON and this
  # module deliberately does not touch that format.
  body="$(curl -ks --max-time 20 --resolve "$dom:443:127.0.0.1" \
            -A 'v2rayNG/1.8.0' "https://$dom/$path/$uuid/sub/" 2>/dev/null)" || body=""
  [ -n "$body" ] || { _EC_PROBE_MSG="could not fetch a subscription from $dom"; return 2; }

  tls_lines="$(printf '%s\n' "$body" | grep -c 'security=tls')" || tls_lines=0
  [ "$tls_lines" != "0" ] || { _EC_PROBE_MSG="the subscription carries no security=tls config to check"; return 2; }

  hit="$(printf '%s\n' "$body" | grep -c "ech=$want")" || hit=0
  # Any ech= that is NOT ours means two writers of the same param, which is the
  # bug this module exists to end — report it rather than pass on the count above.
  bad="$(printf '%s\n' "$body" | grep -o 'ech=[^&#]*' | grep -vcF "ech=$want")" || bad=0

  if [ "$hit" = "0" ]; then
    _EC_PROBE_MSG="$tls_lines TLS config(s) in the live subscription, none carrying ech=$want"
    return 1
  fi
  if [ "$bad" != "0" ]; then
    _EC_PROBE_MSG="$bad ech= param(s) in the live subscription with a value that is not ours"
    return 1
  fi
  _EC_PROBE_MSG="$hit of $tls_lines TLS config(s) carry ech=$want"
  return 0
}

# ---------------------------------------------------------------- baseline ---
# Refreshed from a file that does not already carry our tag, so the baseline can
# never become a modified copy. Refreshing matters because the event that reverts
# us is an UPDATE: a kept-forever .bak would be the previous release's code, and
# restoring that over the current package is version skew that compiles and then
# fails at runtime. ht_backup keeps the first version forever as an archive.
# 0 = baseline now pristine, 1 = hard failure, 2 = already patched so none taken.
_ec_snapshot_baseline() {                 # <xray.py>
  local f="$1" bak="$1.bak"
  [ -f "$f" ] || return 1
  [ "$(_ec_count "$f" "$_EC_TAG")" = "0" ] || return 2
  if [ ! -f "$bak" ] || ! cmp -s "$f" "$bak"; then
    cp -a "$f" "$bak" || return 1
  fi
  ht_backup "$f"
  return 0
}

_ec_bak_is_pristine() {                   # <xray.py.bak>
  [ -f "$1" ] || return 1
  [ "$(_ec_count "$1" "$_EC_TAG")" = "0" ] || return 1
  [ "$(_ec_count "$1" "$_EC_OLD")" != "0" ]
}

# ------------------------------------------------------------------- patch ---
# Rewrite a copy, prove the copy compiles, then move it over the live file, so the
# panel never has a broken xray.py on disk for even a moment.
_ec_patch_file() {                        # <file> <value> -> 0 patched
  local f="$1" val="$2" py new
  py="$(_ec_python)" || return 1
  new="$(_ec_new_block "$val")"

  "$py" - "$f" "$_EC_OLD" "$new" "$_EC_TAG" <<'PYEOF'
import os, py_compile, shutil, sys, tempfile

path, frm, to, tag = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
try:
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
except OSError as exc:
    print(f"cannot read {path}: {exc}", file=sys.stderr)
    sys.exit(1)

if tag in src:
    print("file already carries our tag", file=sys.stderr)
    sys.exit(3)

# Exactly one, always. Zero means upstream rewrote the return; more than one means
# the marker stopped being unique and a blanket replace would edit code nobody
# looked at.
n = src.count(frm)
if n != 1:
    print(f"marker occurs {n} times (expected 1)", file=sys.stderr)
    sys.exit(4)

# Temp file in the SAME directory: os.replace is atomic only within a filesystem.
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".ht")
try:
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(src.replace(frm, to))
    try:
        py_compile.compile(tmp, cfile=tmp + ".pyc", doraise=True)
    except Exception as exc:
        print(f"patched file does not compile: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        if os.path.exists(tmp + ".pyc"):
            os.unlink(tmp + ".pyc")
    shutil.copystat(path, tmp)
    os.replace(tmp, path)
except BaseException:
    if os.path.exists(tmp):
        os.unlink(tmp)
    raise

# Python keys its cache on (mtime, size) and both changed, so this is
# belt-and-braces — but a stale xray.cpython-3XX.pyc is the one way a correct edit
# on disk can still leave the old code running.
cache = os.path.join(os.path.dirname(path), "__pycache__")
if os.path.isdir(cache):
    for name in os.listdir(cache):
        if name.startswith("xray."):
            try:
                os.unlink(os.path.join(cache, name))
            except OSError:
                pass
PYEOF
  local rc=$?
  [ "$rc" = "0" ] || return 1

  # Assert the POSITIVE outcome: an empty or truncated file also satisfies
  # "the old line is gone", and this is the last gate before a panel restart.
  [ "$(_ec_count "$f" "$_EC_TAG")" = "1" ] || return 1
  [ "$(_ec_count "$f" "q.pop('ech', None)")" = "1" ] || return 1
  [ "$(_ec_count "$f" "_ht_ech = '$val'")" = "1" ] || return 1
  [ "$(_ec_count "$f" "$_EC_OLD")" = "0" ] || return 1
  return 0
}

# Restore from the pristine sibling .bak. Used by revert and by the halt path.
_ec_restore_file() {                      # <file> -> 0 restored
  local f="$1" bak="$1.bak"
  _ec_bak_is_pristine "$bak" || return 1
  cp -a "$bak" "$f" || return 1
  local py; py="$(_ec_python)" || py=""
  [ -n "$py" ] && "$py" -c 'import sys,py_compile; py_compile.compile(sys.argv[1], cfile=sys.argv[1]+".chk.pyc", doraise=True)' "$f" >/dev/null 2>&1
  rm -f "$f.chk.pyc"
  rm -f "$(dirname "$f")/__pycache__/xray."*.pyc 2>/dev/null
  [ "$(_ec_count "$f" "$_EC_TAG")" = "0" ]
}

# ----------------------------------------------------------------- halting ---
# If a re-patch ever leaves the panel dead, restore and STOP trying: the guard
# fires every 2 minutes and a patch/fail/restore/restart cycle on that clock is
# worse than the bug it chases. Cleared only by an explicit mod_apply.
_ec_halted() { [ "$(ht_conf_get halted 0)" = "1" ]; }
_ec_halt()   { ht_conf_set halted 1; }
_ec_unhalt() { [ "$(ht_conf_get halted 0)" = "1" ] && ht_conf_set halted 0; return 0; }

# The guard is silent by design, so findings go to the toolkit log — but only when
# they CHANGE, or a permanent condition writes 720 identical lines a day.
_ec_note() {                              # <message>
  local msg="$1" nf prev
  nf="$(ht_state_dir)/${MOD_ID}.note"
  prev="$(cat "$nf" 2>/dev/null)" || prev=""
  [ "$prev" = "$msg" ] && return 0
  mkdir -p "$(ht_state_dir)" 2>/dev/null || true
  printf '%s\n' "$msg" > "$nf" 2>/dev/null || true
  ht_log "[$MOD_ID] $msg"
  return 0
}

_ec_note_clear() { rm -f "$(ht_state_dir)/${MOD_ID}.note" 2>/dev/null || true; return 0; }

# ====================================================================== API ===
mod_status() {
  local n f tag old panel bak hal cnt last val pr

  if ! ht_is_hiddify; then
    printf '  %-10s %s\n' "panel" "/opt/hiddify-manager not present"
    printf 'ABSENT  hiddify-manager is not installed on this host\n'
    return 0
  fi

  n="$(_ec_target_count)"
  if [ "$n" = "0" ]; then
    printf '  %-10s %s\n' "file" "hiddifypanel/hutils/proxy/xray.py not found"
    printf 'ABSENT  panel python package not found — nothing to patch\n'
    return 0
  fi
  if [ "$n" != "1" ]; then
    _ec_targets | sed 's/^/  file       /'
    printf 'PARTIAL  %s candidate xray.py files — cannot tell which venv the panel imports\n' "$n"
    return 0
  fi

  f="$(_ec_target)" || return 1
  val="$(_ec_value)"
  tag="$(_ec_count "$f" "$_EC_TAG")"
  old="$(_ec_count "$f" "$_EC_OLD")"
  panel="$(_ec_panel_state)"
  if _ec_bak_is_pristine "$f.bak"; then bak="present"
  elif [ -f "$f.bak" ]; then bak="present (not a clean baseline)"
  else bak="absent"; fi
  hal="no"; _ec_halted && hal="yes"
  cnt="$(ht_conf_get repatch_count 0)"
  last="$(ht_conf_get repatch_last "")"

  printf '  %-10s %s\n' "file" "$f"
  printf '  %-10s %s\n' "value" "ech=$val"
  printf '  %-10s %s patched / %s pristine return line\n' "patch" "$tag" "$old"
  printf '  %-10s %s\n' "backup" "$bak"
  printf '  %-10s %s\n' "panel" "$panel"

  if [ "$tag" = "1" ]; then
    _ec_live_probe "$val"; pr=$?
    case "$pr" in
      0) printf '  %-10s ok — %s\n' "live sub" "$_EC_PROBE_MSG" ;;
      1) printf '  %-10s WRONG — %s\n' "live sub" "$_EC_PROBE_MSG" ;;
      *) printf '  %-10s not checked — %s\n' "live sub" "$_EC_PROBE_MSG" ;;
    esac
  fi

  [ "$cnt" != "0" ] && printf '  %-10s %s (last %s) — Hiddify updates keep reverting it\n' \
                              "re-applied" "$cnt" "${last:-unknown}"
  [ "$hal" = "yes" ] && printf '  %-10s %s\n' "guard" "HALTED — a re-patch took the panel down; re-apply by hand"

  if [ "$hal" = "yes" ]; then
    printf 'PARTIAL  guard HALTED after a failed re-patch — enabled but no longer asserting\n'
  elif [ "$tag" = "1" ] && [ "$old" = "0" ]; then
    if [ "${pr:-2}" = "1" ]; then
      printf 'PARTIAL  patched, but the live subscription does not show ech=%s\n' "$val"
    else
      printf 'APPLIED  TLS configs carry ech=%s\n' "$val"
    fi
  elif [ "$tag" = "0" ] && [ "$old" = "1" ]; then
    printf 'ABSENT   the panel decides the ech value itself (DNS lookup, or nothing)\n'
  else
    printf 'PARTIAL  the link builder is not where it was (tag=%s pristine=%s) — panel code changed upstream\n' "$tag" "$old"
  fi
  return 0
}

mod_apply() {
  local n f val tag old code rc

  ht_is_hiddify || { err "hiddify-manager is not installed here"; return 1; }

  n="$(_ec_target_count)"
  if [ "$n" = "0" ]; then
    err "hiddifypanel hutils/proxy/xray.py not found — aborting, nothing changed"
    return 1
  fi
  if [ "$n" != "1" ]; then
    err "glob matched $n xray.py files — aborting, nothing changed"
    _ec_targets | sed 's/^/    /'
    return 1
  fi
  f="$(_ec_target)" || return 1

  # An operator-supplied value that cannot be safely embedded must stop the apply,
  # not be silently swapped for the default: shipping a different value than the
  # one in conf is worse than refusing.
  val="$(ht_conf_get ech_value "$_EC_DEFAULT")"
  if ! _ec_value_ok "$val"; then
    err "ech_value '$val' is not usable — letters, digits and . _ : / % + - only, max 120 chars"
    err "fix it in $(ht_state_dir)/conf/${MOD_ID}.conf, or remove the line to use $_EC_DEFAULT"
    return 1
  fi

  tag="$(_ec_count "$f" "$_EC_TAG")"
  old="$(_ec_count "$f" "$_EC_OLD")"

  # Recorded on EVERY path before any branch can return: mod_verify gates on this
  # and a failed verify triggers revert + disable, so a value left from an earlier
  # apply would let a panel that is down for its own reasons rip out a good patch.
  ht_conf_set panel_pre_state "$(_ec_panel_state)"

  # Already carrying OUR tag but a different value (operator changed ech_value):
  # restore the baseline first so the re-patch starts from pristine code.
  if [ "$tag" != "0" ] && [ "$(_ec_count "$f" "_ht_ech = '$val'")" = "0" ]; then
    if _ec_restore_file "$f"; then
      warn "value changed — restored pristine xray.py before re-patching"
      tag=0; old="$(_ec_count "$f" "$_EC_OLD")"
    else
      err "xray.py carries a different ech value and no pristine baseline to restore — aborting"
      return 1
    fi
  fi

  if [ "$tag" = "1" ] && [ "$old" = "0" ]; then
    _ec_snapshot_baseline "$f" >/dev/null 2>&1 || true
    _ec_unhalt; _ec_note_clear
    ok "already patched with ech=$val — panel NOT restarted"
    return 0
  fi
  if [ "$old" != "1" ]; then
    err "the link builder's return line is not where it was (found $old) — aborting, nothing changed"
    return 1
  fi

  _ec_snapshot_baseline "$f"
  rc=$?
  if [ "$rc" = "1" ]; then
    err "could not write the pristine baseline $f.bak — aborting, nothing changed"
    return 1
  elif [ "$rc" = "2" ]; then
    warn "$f already carries the patch — no pristine $f.bak taken"
  fi

  if ! _ec_patch_file "$f" "$val"; then
    err "patch did not apply cleanly (edit rejected or failed to compile) — file left untouched"
    return 1
  fi
  ok "patched the link builder: TLS configs now carry ech=$val"

  if ! _ec_unit_exists; then
    warn "no ${_EC_UNIT}.service on this host — file patched, nothing restarted"
    _ec_unhalt; _ec_note_clear
    return 0
  fi
  if _ec_restart_panel; then
    code="$(_ec_http_probe)"
    ok "${_EC_UNIT} active (http=${code}; 400 is the normal answer on 9000)"
  else
    warn "${_EC_UNIT} did not come back active — verification will roll this back"
  fi

  _ec_unhalt
  _ec_note_clear
  ht_conf_set ech_value "$val"
  ht_conf_set applied_at "$(date -Is)"
  return 0
}

mod_verify() {
  local f val tag old py pre pr

  f="$(_ec_target)" || { err "expected exactly one xray.py, found $(_ec_target_count)"; return 1; }
  val="$(_ec_value)"

  tag="$(_ec_count "$f" "$_EC_TAG")"
  old="$(_ec_count "$f" "$_EC_OLD")"
  [ "$tag" = "1" ] || { err "expected our tag once in $f, found $tag"; return 1; }
  [ "$old" = "0" ] || { err "the pristine return line is still present $old time(s)"; return 1; }
  [ "$(_ec_count "$f" "_ht_ech = '$val'")" = "1" ] \
    || { err "the patched file does not carry the configured value ($val)"; return 1; }

  py="$(_ec_python)" || py=""
  if [ -n "$py" ]; then
    if ! "$py" -c 'import py_compile,sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)' \
         "$f" "$f.verify.pyc" >/dev/null 2>&1; then
      rm -f "$f.verify.pyc"
      err "patched file does not compile"
      return 1
    fi
    rm -f "$f.verify.pyc"
    ok "file compiles and carries ech=$val"
  else
    warn "no python interpreter found — compile check skipped"
  fi

  pre="$(ht_conf_get panel_pre_state unknown)"
  if [ "$pre" = "active" ]; then
    if ! _ec_wait_panel 20; then
      err "${_EC_UNIT} was active before and is $(_ec_panel_state) now"
      return 1
    fi
  else
    warn "${_EC_UNIT} was '${pre}' before this change — liveness not used as a gate"
  fi

  # The claim this module makes is about the SUBSCRIPTION, so read one. A probe
  # that could not look (code 2) is reported and not treated as proof either way;
  # a probe that looked and found the wrong thing fails the apply.
  _ec_live_probe "$val"; pr=$?
  case "$pr" in
    0) ok "live subscription: $_EC_PROBE_MSG" ;;
    1) err "live subscription: $_EC_PROBE_MSG"; return 1 ;;
    *) warn "live subscription not checked — $_EC_PROBE_MSG" ;;
  esac

  return 0
}

mod_revert() {
  local n f tag

  n="$(_ec_target_count)"
  if [ "$n" = "0" ]; then
    ok "panel python package not present — nothing to restore"
    _ec_unhalt; _ec_note_clear
    return 0
  fi
  if [ "$n" != "1" ]; then
    err "glob matched $n xray.py files — refusing to guess which one to restore"
    return 1
  fi
  f="$(_ec_target)" || return 1
  tag="$(_ec_count "$f" "$_EC_TAG")"

  if [ "$tag" = "0" ]; then
    ok "xray.py does not carry our patch — nothing to undo"
    _ec_unhalt; _ec_note_clear
    return 0
  fi

  if ! _ec_restore_file "$f"; then
    err "could not restore a pristine xray.py — $f still carries the patch"
    err "the archived original is in $(ht_backup_dir)"
    return 1
  fi
  ok "restored the panel's own ech behaviour in xray.py"

  if _ec_unit_exists && [ "$(_ec_panel_state)" = "active" ]; then
    if _ec_restart_panel; then
      ok "${_EC_UNIT} restarted and active"
    else
      warn "${_EC_UNIT} did not come back active after the restore"
    fi
  fi

  _ec_unhalt
  _ec_note_clear
  return 0
}

mod_reassert() {
  local f val tag old pre

  _ec_halted && return 0
  ht_is_hiddify || return 0
  [ "$(_ec_target_count)" = "1" ] || return 0
  f="$(_ec_target)" || return 0
  val="$(_ec_value)"

  tag="$(_ec_count "$f" "$_EC_TAG")"
  # RULE ONE: already patched means restart NOTHING. The guard runs every 2
  # minutes; a restart per tick would keep the admin UI and the subscription
  # endpoint down forever while every check still said the patch was in place.
  if [ "$tag" != "0" ] && [ "$(_ec_count "$f" "_ht_ech = '$val'")" = "1" ]; then
    _ec_note_clear
    return 0
  fi

  old="$(_ec_count "$f" "$_EC_OLD")"
  if [ "$tag" = "0" ] && [ "$old" != "1" ]; then
    # Neither our patch nor the line we know how to patch: a panel release that
    # moved this code. Say so once and change nothing.
    _ec_note "xray.py return line not found (pristine=$old) — upstream changed it; patch NOT re-applied"
    return 0
  fi

  # RULE TWO: the event that wiped the patch is a Hiddify UPDATE, and that update
  # is driving hiddify-panel at this very moment. Treat "panel not active" as
  # somebody else mid-apply, never as evidence against our own patch — and restart
  # only if the panel was up before we touched anything.
  pre="$(_ec_panel_state)"

  if [ "$tag" != "0" ]; then
    _ec_restore_file "$f" || { _ec_note "could not restore before re-patch — left as is"; return 1; }
  fi

  if ! _ec_patch_file "$f" "$val"; then
    _ec_note "re-patch of xray.py FAILED — panel code left as upstream shipped it"
    return 1
  fi

  ht_conf_set repatch_count "$(( $(ht_conf_get repatch_count 0) + 1 ))"
  ht_conf_set repatch_last "$(date -Is)"
  ht_log "[$MOD_ID] panel code was reverted (Hiddify update) — re-applied ech=$val"

  if [ "$pre" = "active" ]; then
    if ! _ec_restart_panel; then
      # A re-patch that kills the panel is the one failure worth giving up over.
      _ec_restore_file "$f" >/dev/null 2>&1
      systemctl restart "$_EC_UNIT" >/dev/null 2>&1 || true
      _ec_halt
      _ec_note "re-patch left ${_EC_UNIT} down — restored upstream code and HALTED"
      return 1
    fi
  fi

  _ec_note_clear
  return 0
}
