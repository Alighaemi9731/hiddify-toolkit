# shellcheck shell=bash
# =============================================================================
# module: fakedomain-dot — Trailing dot in domain names
# =============================================================================
# The panel's Domain form validates the name with one wtforms Regexp whose first
# alternative must END at the TLD:
#
#   ^(\*\.)?([A-Za-z0-9\-\.]+\.[a-zA-Z]{2,})$|^$|<ipv4>|<ipv6>
#
# so "fast.com." is refused with "Should be a valid domain". A trailing dot is a
# perfectly legal FQDN (the root label), and it is worth having because Xray and
# sing-box put the domain into the HTTP Host header VERBATIM — a Host-matching
# proxy sees "fast.com." while the connection still works. Appending an optional
# "\.?" to that one alternative is the whole fix; nothing else in the panel or in
# hiddify-manager objects:
#
#   on_model_change      .lower().strip() only strips whitespace — the dot lives
#   _validate_domain_ips returns True immediately for DomainType.fake — no DNS
#   _update_cloudflare   skips fake mode entirely
#   shared.py            sni = host = domain verbatim; only `server` is swapped
#   need_valid_ssl       False for fake, so the config carries allow_insecure
#   replace_variables.sh basename "fast.com..crt" .crt == "fast.com." — the cert
#                        matches the domain list, so apply-config does not churn it
#
# WHAT UNDOES IT, precisely — the two events are NOT the same:
#   apply-config  runs hiddify-panel/install.sh, which only pip-installs when
#                 HIDDIFY_PANLE_SOURCE_DIR is set (it is not), then run.sh
#                 restarts the panel. Our patch SURVIVES; only the unit bounces.
#   update        update_panel() runs `uv pip install -U --force-reinstall
#                 hiddifypanel`, which replaces the whole package. Patch GONE.
#
# That asymmetry is the reason mod_reassert below never treats "panel is not
# active" as evidence against itself: the guard fires every 2 minutes, so it lands
# inside an apply-config's restart window as a matter of course, and an
# apply-config is exactly when nothing is wrong with the patch at all.
#
# WHY PYTHON AND NOT SED, unlike reality-alpn: both markers here ARE regexes —
# ^ ( ) * . [ ] + { } $ \ — and every one of them is also a sed metacharacter. A
# fixed-string str.replace() in the interpreter we already need for the compile
# check has no escaping surface at all, and the two markers provably cannot be
# mistaken for each other (neither is a substring of the other, and the pristine
# file contains the old one exactly once).
# =============================================================================

# The core reads this metadata by sourcing the file, so shellcheck cannot see
# the use of any of it.
# shellcheck disable=SC2034
MOD_ID="fakedomain-dot"
MOD_TITLE="Trailing dot in domain names"
MOD_DESC="Lets the panel accept a domain written with a trailing dot (fast.com.), so Fake-Site and CDN configs carry that dot in their Host header. Patches panel code, so a Hiddify update wipes it — the guard re-applies it."
MOD_GUARD=yes

# Matched with grep -F / str.replace on purpose — see the header.
_FD_OLD='^(\*\.)?([A-Za-z0-9\-\.]+\.[a-zA-Z]{2,})$'
_FD_NEW='^(\*\.)?([A-Za-z0-9\-\.]+\.[a-zA-Z]{2,}\.?)$'
_FD_UNIT="hiddify-panel"
_FD_PROBE="http://127.0.0.1:9000/"
_FD_REL="lib/python*/site-packages/hiddifypanel/panel/admin/DomainAdmin.py"

# --------------------------------------------------------------- discovery ---
# nullglob in a subshell: an unmatched glob otherwise expands to its own literal
# text, which then sails through `[ -f ... ]` looking like a plausible path.
_fd_targets() {
  (
    shopt -s nullglob
    # $_FD_REL is deliberately unquoted: it carries a `python*` component that
    # must go through pathname expansion, which quoting would switch off.
    # shellcheck disable=SC2206
    local -a m=( /opt/hiddify-manager/.venv*/$_FD_REL )
    [ "${#m[@]}" -gt 0 ] && printf '%s\n' "${m[@]}"
    return 0
  )
}

_fd_target_count() {
  local -a m=()
  mapfile -t m < <(_fd_targets)
  printf '%s\n' "${#m[@]}"
}

# Exactly one match or nothing: a second venv left behind by an upgrade (.venv
# plus .venv313) means we cannot know which tree the running panel imports from,
# and patching the wrong one is a silent no-op that looks applied.
_fd_target() {
  local -a m=()
  mapfile -t m < <(_fd_targets)
  [ "${#m[@]}" -eq 1 ] || return 1
  printf '%s\n' "${m[0]}"
}

# Occurrences, not matching lines. `grep -c` counts lines, so two markers on one
# physical line would report 1 and a half-applied patch would pass verification.
_fd_count() {                            # <file> <fixed-string> -> integer
  local n
  [ -f "$1" ] || { printf '0\n'; return 0; }
  # tr, because some wc implementations pad the count with spaces and every
  # comparison here is a string comparison — "      0" != "0" would read as
  # "already patched" on exactly the boxes where nothing is patched.
  n="$(grep -oF -e "$2" -- "$1" 2>/dev/null | wc -l | tr -dc '0-9')" || n=""
  printf '%s\n' "${n:-0}"
}

_fd_python() {
  local p
  for p in /opt/hiddify-manager/.venv*/bin/python3 /opt/hiddify-manager/.venv*/bin/python; do
    [ -x "$p" ] && { printf '%s\n' "$p"; return 0; }
  done
  # The system interpreter is an acceptable fallback: we only do a fixed-string
  # replace and a syntax check, neither of which depends on the minor version.
  p="$(command -v python3 2>/dev/null)" || return 1
  [ -n "$p" ] || return 1
  printf '%s\n' "$p"
}

_fd_unit_exists() { systemctl cat "$_FD_UNIT" >/dev/null 2>&1; }

_fd_panel_state() {
  local s
  s="$(systemctl is-active "$_FD_UNIT" 2>/dev/null)" || true
  printf '%s\n' "${s:-unknown}"
}

# systemd calls a Type=simple unit "active" the moment exec() returns — before the
# interpreter has imported DomainAdmin.py. A panel that dies at import time
# therefore passes a bare is-active check and mod_verify signs off on a corpse.
# Re-check after a short settle, which is the window an import-time failure needs.
_fd_wait_panel() {                       # <max-seconds>
  local deadline=$(( SECONDS + ${1:-20} ))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if [ "$(_fd_panel_state)" = "active" ]; then
      sleep 3
      [ "$(_fd_panel_state)" = "active" ] && return 0
    fi
    sleep 1
  done
  [ "$(_fd_panel_state)" = "active" ]
}

_fd_restart_panel() {                    # restart + wait; 0 only if it came back
  _fd_unit_exists || return 1
  systemctl restart "$_FD_UNIT" >/dev/null 2>&1 || true
  _fd_wait_panel 25
}

# 400 here is the HEALTHY answer — Hiddify only serves the panel under its secret
# proxy path, so a bare GET / on 9000 is supposed to be refused. Informational
# only; never gate on it.
_fd_http_probe() {
  local code
  command -v curl >/dev/null 2>&1 || { printf 'n/a\n'; return 0; }
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "$_FD_PROBE" 2>/dev/null)" || code=""
  printf '%s\n' "${code:-none}"
}

# ---------------------------------------------------------------- baseline ---
# The sibling .bak is the restore source, refreshed — but ONLY from a file that
# does not already carry our patch, so the baseline can never become a modified
# copy. Refreshing matters because the event that reverts us is a Hiddify UPDATE:
# a kept-forever .bak would be the PREVIOUS release's code, and restoring that
# over the current package is version skew that compiles and then fails at
# runtime. ht_backup keeps the very first version forever as an archive.
#
# 0 = $bak now holds pristine upstream, 1 = hard failure, 2 = the file already
# carries our patch so no baseline was taken (2 must not be announced as 0 — that
# would claim a baseline that was never written).
_fd_snapshot_baseline() {                # <DomainAdmin.py>
  local f="$1" bak="$1.bak"
  [ -f "$f" ] || return 1
  [ "$(_fd_count "$f" "$_FD_NEW")" = "0" ] || return 2
  if [ ! -f "$bak" ] || ! cmp -s "$f" "$bak"; then
    cp -a "$f" "$bak" || return 1
  fi
  ht_backup "$f"
  return 0
}

_fd_bak_is_pristine() {                  # <DomainAdmin.py.bak>
  [ -f "$1" ] || return 1
  [ "$(_fd_count "$1" "$_FD_NEW")" = "0" ] || return 1
  [ "$(_fd_count "$1" "$_FD_OLD")" != "0" ]
}

# ------------------------------------------------------------------- patch ---
# Rewrite a copy, prove the copy compiles, then move it over the live file, so the
# panel never has a broken DomainAdmin.py on disk for even a moment. `direction`
# is forward|reverse — the reverse substitution is the exact textual inverse and,
# unlike the .bak, it cannot resurrect code from a different panel version.
_fd_rewrite() {                          # <file> <forward|reverse> -> 0 changed
  local f="$1" dir="$2" py from to
  py="$(_fd_python)" || return 1
  if [ "$dir" = "reverse" ]; then from="$_FD_NEW"; to="$_FD_OLD"
  else                            from="$_FD_OLD"; to="$_FD_NEW"; fi

  "$py" - "$f" "$from" "$to" <<'PYEOF'
import os, py_compile, shutil, sys, tempfile

path, frm, to = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
except OSError as exc:
    print(f"cannot read {path}: {exc}", file=sys.stderr)
    sys.exit(1)

# Exactly one, always. Zero means upstream renamed it or we are already in the
# target state; more than one means the marker stopped being unique and a blanket
# replace would edit something nobody looked at.
n = src.count(frm)
if n != 1:
    print(f"marker occurs {n} times (expected 1)", file=sys.stderr)
    sys.exit(4)

# Temp file in the SAME directory: os.replace is only atomic within one
# filesystem, and /tmp is very often a separate one.
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

# Python keys its cache on (mtime, size) and both changed here, so this is
# belt-and-braces — but a stale DomainAdmin.cpython-3XX.pyc is the one way a
# correct edit on disk can still leave the old regex running.
cache = os.path.join(os.path.dirname(path), "__pycache__")
if os.path.isdir(cache):
    for name in os.listdir(cache):
        if name.startswith("DomainAdmin."):
            try:
                os.unlink(os.path.join(cache, name))
            except OSError:
                pass
PYEOF
  local rc=$?
  [ "$rc" = "0" ] || return 1

  # Assert the POSITIVE outcome, not merely "the old marker is gone" — an empty or
  # truncated file also satisfies the negative, and this is the last gate before a
  # panel restart.
  if [ "$(_fd_count "$f" "$to")" = "0" ] || [ "$(_fd_count "$f" "$from")" != "0" ]; then
    return 1
  fi
  return 0
}

_fd_patch_file() {                       # <file> -> 0 patched, 1 untouched
  local f="$1"
  if ! _fd_rewrite "$f" forward; then
    # Contract from the standalone script: if the live file somehow does not carry
    # the patch, put the baseline back rather than leave it unknown. Pristine
    # check, not merely "a file exists there" — a .bak from an earlier panel
    # RELEASE installed over the current package is exactly the version skew that
    # compiles cleanly and then fails at runtime.
    if [ "$(_fd_count "$f" "$_FD_NEW")" = "0" ] && _fd_bak_is_pristine "$f.bak"; then
      cp -a "$f.bak" "$f"
    fi
    return 1
  fi
  return 0
}

# ----------------------------------------------------------------- halting ---
# If a re-patch ever leaves the panel dead, we restore and then STOP trying. The
# guard fires every 2 minutes; a patch/restart/fail/restore/restart cycle on that
# clock is worse than the bug it is chasing. Cleared by an explicit mod_apply.
_fd_halted() { [ "$(ht_conf_get halted 0)" = "1" ]; }
_fd_halt()   { ht_conf_set halted 1; }
_fd_unhalt() { [ "$(ht_conf_get halted 0)" = "1" ] && ht_conf_set halted 0; return 0; }

# The guard is silent by design, so its findings go to the toolkit log — but only
# when they CHANGE, or a permanent condition writes 720 identical lines a day.
_fd_note() {                             # <message>
  local msg="$1" nf prev
  nf="$(ht_state_dir)/${MOD_ID}.note"
  prev="$(cat "$nf" 2>/dev/null)" || prev=""
  [ "$prev" = "$msg" ] && return 0
  mkdir -p "$(ht_state_dir)" 2>/dev/null || true
  printf '%s\n' "$msg" > "$nf" 2>/dev/null || true
  ht_log "[$MOD_ID] $msg"
  return 0
}

_fd_note_clear() {
  rm -f "$(ht_state_dir)/${MOD_ID}.note" 2>/dev/null || true
  return 0
}

# ====================================================================== API ===
mod_status() {
  local n f new old bak panel hal cnt last

  if ! ht_is_hiddify; then
    printf '  %-9s %s\n' "panel" "/opt/hiddify-manager not present"
    printf 'ABSENT  hiddify-manager is not installed on this host\n'
    return 0
  fi

  n="$(_fd_target_count)"
  if [ "$n" = "0" ]; then
    printf '  %-9s %s\n' "file" "hiddifypanel/panel/admin/DomainAdmin.py not found"
    printf 'ABSENT  panel python package not found — nothing to patch\n'
    return 0
  fi
  if [ "$n" != "1" ]; then
    _fd_targets | sed 's/^/  file      /'
    printf 'PARTIAL  %s candidate DomainAdmin.py files — cannot tell which venv the panel imports\n' "$n"
    return 0
  fi

  f="$(_fd_target)" || return 1
  new="$(_fd_count "$f" "$_FD_NEW")"
  old="$(_fd_count "$f" "$_FD_OLD")"
  panel="$(_fd_panel_state)"
  if _fd_bak_is_pristine "$f.bak"; then
    bak="present"
  elif [ -f "$f.bak" ]; then
    bak="present (not a clean baseline)"
  else
    bak="absent"
  fi
  hal="no"; _fd_halted && hal="yes"
  cnt="$(ht_conf_get repatch_count 0)"
  last="$(ht_conf_get repatch_last "")"

  printf '  %-9s %s\n' "file" "$f"
  printf '  %-9s %s patched / %s still reject a trailing dot\n' "regex" "$new" "$old"
  printf '  %-9s %s\n' "backup" "$bak"
  printf '  %-9s %s\n' "panel" "$panel"
  [ "$cnt" != "0" ] && printf '  %-9s %s (last %s) — Hiddify updates keep reverting it\n' \
                              "re-applied" "$cnt" "${last:-unknown}"
  [ "$hal" = "yes" ] && printf '  %-9s %s\n' "guard" "HALTED — a re-patch took the panel down; re-apply by hand"

  # HALTED is checked first, and reports PARTIAL rather than ABSENT: the halt path
  # reverts the patch, so the token would be ABSENT, which the main menu draws as a
  # dim "off" — indistinguishable from a module nobody ever enabled. This one IS
  # enabled and has quietly stopped defending itself; yellow "partial" is the truth.
  if [ "$hal" = "yes" ]; then
    printf 'PARTIAL  guard HALTED after a failed re-patch — enabled but no longer asserting\n'
  elif [ "$new" = "1" ] && [ "$old" = "0" ]; then
    printf 'APPLIED  a trailing dot is accepted (fast.com.)\n'
  elif [ "$new" != "0" ] && [ "$old" != "0" ]; then
    printf 'PARTIAL  %s copy of the regex still rejects a trailing dot\n' "$old"
  elif [ "$old" = "1" ]; then
    printf 'ABSENT   a trailing dot is rejected ("Should be a valid domain")\n'
  else
    printf 'PARTIAL  the domain regex is not where it was (old=%s new=%s) — panel code changed upstream\n' "$old" "$new"
  fi
  return 0
}

mod_apply() {
  local n f new old code rc

  ht_is_hiddify || { err "hiddify-manager is not installed here"; return 1; }

  n="$(_fd_target_count)"
  if [ "$n" = "0" ]; then
    err "hiddifypanel DomainAdmin.py not found — aborting, nothing changed"
    return 1
  fi
  if [ "$n" != "1" ]; then
    err "glob matched $n DomainAdmin.py files — aborting, nothing changed"
    _fd_targets | sed 's/^/    /'
    return 1
  fi
  f="$(_fd_target)" || return 1

  new="$(_fd_count "$f" "$_FD_NEW")"
  old="$(_fd_count "$f" "$_FD_OLD")"

  # Recorded on EVERY path, before any branch below can return. mod_verify gates on
  # this value and do_apply answers a failed verify with mod_revert + disable, so a
  # value left over from an EARLIER apply is lethal: re-running apply on an
  # already-patched box would return early without refreshing it, verify would then
  # compare a panel that is down for its own reasons (update, OOM, admin stopped it)
  # against a stale "active", and the no-op apply would rip out a healthy patch.
  ht_conf_set panel_pre_state "$(_fd_panel_state)"

  if [ "$new" != "0" ] && [ "$old" = "0" ]; then
    _fd_snapshot_baseline "$f" >/dev/null 2>&1 || true
    _fd_unhalt; _fd_note_clear
    ok "already patched — panel NOT restarted"
    return 0
  fi
  if [ "$old" != "1" ]; then
    err "the domain regex is not where it was (found $old copies) — aborting, nothing changed"
    return 1
  fi

  _fd_snapshot_baseline "$f"
  rc=$?
  if [ "$rc" = "1" ]; then
    err "could not write the pristine baseline $f.bak — aborting, nothing changed"
    return 1
  elif [ "$rc" = "2" ]; then
    warn "$f already carries the patch — no pristine $f.bak taken; revert will reverse the edit instead"
  fi

  if ! _fd_patch_file "$f"; then
    err "patch did not apply cleanly (edit rejected or failed to compile) — file left untouched"
    return 1
  fi
  ok "patched the domain regex: a single trailing dot is now accepted"

  if ! _fd_unit_exists; then
    warn "no ${_FD_UNIT}.service on this host — file patched, nothing restarted"
    _fd_unhalt; _fd_note_clear
    return 0
  fi
  if _fd_restart_panel; then
    code="$(_fd_http_probe)"
    ok "${_FD_UNIT} active (http=${code}; 400 is the normal answer on 9000)"
  else
    warn "${_FD_UNIT} did not come back active — verification will roll this back"
  fi

  _fd_unhalt
  _fd_note_clear
  ht_conf_set applied_at "$(date -Is)"
  return 0
}

mod_verify() {
  local f new old py pre

  f="$(_fd_target)" || { err "expected exactly one DomainAdmin.py, found $(_fd_target_count)"; return 1; }

  new="$(_fd_count "$f" "$_FD_NEW")"
  old="$(_fd_count "$f" "$_FD_OLD")"
  [ "$new" = "1" ] || { err "expected 1 patched regex in $f, found $new"; return 1; }
  [ "$old" = "0" ] || { err "$old copy of the regex still rejects a trailing dot"; return 1; }

  py="$(_fd_python)" || py=""
  if [ -n "$py" ]; then
    if ! "$py" -c 'import py_compile,sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)' \
         "$f" "$f.verify.pyc" >/dev/null 2>&1; then
      rm -f "$f.verify.pyc"
      err "patched file does not compile"
      return 1
    fi
    rm -f "$f.verify.pyc"

    # The point of the module is a REGEX, so check what the regex DOES rather than
    # only that some bytes changed. The marker being present proves an edit landed;
    # it does not prove the alternation around it still parses the way it read
    # before. Pull the live pattern out of the file and exercise it — accept the
    # trailing dot, keep accepting everything that already worked, and still refuse
    # a double dot. Failures are reported as one line: a raw Python traceback in
    # the menu tells the operator nothing they can act on.
    local why
    why="$("$py" - "$f" 2>/dev/null <<'PYEOF'
import re, sys

try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        line = next(l for l in fh if "Should be a valid domain" in l)
except (OSError, StopIteration):
    print("the validator line is gone from the file"); sys.exit(1)

m = re.search(r"Regexp\(r'([^']+)'", line)
if not m:
    print("cannot read the pattern out of the validator line"); sys.exit(1)
pat = m.group(1)

for value, want in (("fast.com.", True), ("fast.com", True), ("*.example.com", True),
                    ("1.2.3.4", True), ("", True), ("fast.com..", False)):
    if bool(re.match(pat, value)) is not want:
        verb = "rejects" if want else "accepts"
        print(f"the patched pattern {verb} {value!r}"); sys.exit(1)
PYEOF
)" || { err "${why:-the patched regex does not behave as intended}"; return 1; }
    ok "regex accepts fast.com. and still refuses fast.com.."
  else
    warn "no python interpreter found — compile and regex checks skipped"
  fi

  pre="$(ht_conf_get panel_pre_state unknown)"
  if [ "$pre" = "active" ]; then
    if ! _fd_wait_panel 20; then
      err "${_FD_UNIT} was active before and is $(_fd_panel_state) now"
      return 1
    fi
  else
    warn "${_FD_UNIT} was '${pre}' before this change — liveness not used as a gate"
  fi

  ok "trailing dot accepted, file compiles, panel $(_fd_panel_state)"
  return 0
}

mod_revert() {
  local n f new bak tmp restored=0

  n="$(_fd_target_count)"
  if [ "$n" = "0" ]; then
    ok "panel python package not present — nothing to restore"
    _fd_unhalt; _fd_note_clear
    return 0
  fi
  if [ "$n" != "1" ]; then
    err "glob matched $n DomainAdmin.py files — refusing to guess which one to restore"
    return 1
  fi
  f="$(_fd_target)" || return 1
  bak="$f.bak"
  new="$(_fd_count "$f" "$_FD_NEW")"

  if [ "$new" = "0" ]; then
    rm -f "$bak"
    _fd_unhalt; _fd_note_clear
    ok "already unpatched — panel NOT restarted"
    return 0
  fi

  if _fd_bak_is_pristine "$bak"; then
    # Same temp-in-the-same-directory + mv discipline as _fd_rewrite, and for the
    # same reason: `cp` onto the live file truncates it first, so a cp that dies
    # half way (ENOSPC) leaves a torn DomainAdmin.py behind. A torn file contains
    # no _FD_NEW, which would sail through a naive "the patch is gone" test — and
    # the tail of this function then restarts the panel onto it.
    tmp="$(mktemp "${f}.ht-XXXXXX" 2>/dev/null)" || tmp=""
    if [ -n "$tmp" ] && cp -a "$bak" "$tmp" && mv -f "$tmp" "$f"; then
      restored=1
    else
      [ -n "$tmp" ] && rm -f "$tmp"
      err "could not restore from $bak"
    fi
  fi
  if [ "$restored" = "0" ]; then
    warn "no clean $bak — reverting by reversing the edit instead"
    _fd_rewrite "$f" reverse && restored=1
  fi
  # Assert the POSITIVE, for the same reason as everywhere else in this file.
  if [ "$restored" = "0" ] || [ "$(_fd_count "$f" "$_FD_NEW")" != "0" ] \
                           || [ "$(_fd_count "$f" "$_FD_OLD")" = "0" ]; then
    err "revert failed — $f does not carry the original domain regex"
    return 1
  fi
  rm -f "$bak"
  ok "restored the original domain regex (a trailing dot is rejected again)"

  _fd_unhalt
  _fd_note_clear
  ht_conf_set panel_pre_state ""
  # The re-patch counter belongs to the enablement that just ended; leaving it
  # behind makes a reverted module report update-churn it is no longer watching.
  ht_conf_set repatch_count 0

  if ! _fd_unit_exists; then
    warn "no ${_FD_UNIT}.service on this host — nothing restarted"
    return 0
  fi
  if _fd_restart_panel; then
    ok "${_FD_UNIT} active"
    return 0
  fi
  err "${_FD_UNIT} did not come back active after the restore"
  return 1
}

# Adoption (ht_adopt_applied) marks an already-APPLIED module enabled WITHOUT
# running mod_apply — right, because the box is already in the target state, but
# it also skips everything mod_apply records. What matters here is panel_pre_state:
# left unset, a later mod_verify would gate on a value from some earlier run.
#
# Deliberately NOT taking a baseline: adoption only happens when mod_status says
# APPLIED, which by construction means the live file already carries the patch, so
# there is no pristine copy left to snapshot. Revert therefore uses its reverse-edit
# path, which is the exact textual inverse and restores the file byte-for-byte.
# Bookkeeping only — this hook must never change the box.
mod_adopt() {
  _fd_target >/dev/null || return 0
  ht_conf_set panel_pre_state "$(_fd_panel_state)"
  _fd_unhalt
  return 0
}

mod_reassert() {
  local f new old pre rc

  # Non-zero is reserved for TRANSIENT failures worth retrying. do_reassert turns
  # any non-zero into a "reassert FAILED" line on every 2-minute tick and nothing
  # rotates toolkit.log, so the permanent states below (halted, unresolvable venv,
  # upstream renamed the regex) would write 720 identical failure lines a day about
  # something no retry can fix. The deduped note IS the report for those.
  _fd_halted && return 0
  ht_is_hiddify || return 0

  f="$(_fd_target)" || {
    _fd_note "cannot resolve a single hiddifypanel DomainAdmin.py ($(_fd_target_count) candidates) — not touching anything"
    return 0
  }

  new="$(_fd_count "$f" "$_FD_NEW")"
  old="$(_fd_count "$f" "$_FD_OLD")"

  # THE FAST PATH, and the one that runs 719 times out of 720 — including during
  # every apply-config, which does not touch the package at all. Nothing is
  # written and above all nothing is restarted.
  if [ "$new" != "0" ] && [ "$old" = "0" ]; then
    _fd_note_clear
    return 0
  fi

  if [ "$old" != "1" ]; then
    _fd_note "the domain regex is not where it was in $f (old=$old new=$new) — upstream code changed, leaving it alone"
    return 0
  fi

  # What the panel was doing BEFORE we touched anything. The only thing that puts
  # the strict regex back is a Hiddify update — and a Hiddify update is stopping
  # and starting this very unit. Firing every 2 minutes, the guard lands inside
  # that window as a matter of course, so "not active" here overwhelmingly means
  # "hiddify is still mid-update", not "our one-line edit killed the panel".
  pre="$(_fd_panel_state)"

  # Reaching here means the panel package was replaced under us, so the file on
  # disk right now IS the new pristine upstream copy — snapshot it before editing,
  # or the .bak keeps pointing at the old release. rc=2 is not a reason to refuse
  # the repair; only a hard write failure is.
  _fd_snapshot_baseline "$f"
  rc=$?
  if [ "$rc" = "1" ]; then
    _fd_note "could not refresh $f.bak — skipping re-patch"
    return 1
  fi

  if ! _fd_patch_file "$f"; then
    _fd_note "re-patch of $f failed (edit rejected or would not compile)"
    return 1
  fi

  ht_conf_set repatch_count "$(( $(ht_conf_get repatch_count 0) + 1 ))"
  ht_conf_set repatch_last "$(date -Is)"
  ht_log "[$MOD_ID] panel code was reverted (Hiddify update) — re-applied the trailing-dot patch"

  _fd_unit_exists || { _fd_note_clear; return 0; }

  # The patch is on disk, and whoever is driving this unit will import it when they
  # start it — so a panel that was already down needs nothing from us. Restarting a
  # unit somebody else currently owns is how a GOOD patch gets destroyed: mid-update
  # the restart cannot succeed, the failure path below then restores the baseline
  # and halts the guard for good, leaving the module in exactly the state it exists
  # to prevent. Only restart what was ours to break.
  if [ "$pre" != "active" ]; then
    _fd_note "re-patched $f while ${_FD_UNIT} was '${pre}' — not restarting it, re-checking next tick"
    return 0
  fi

  if _fd_restart_panel; then
    _fd_note_clear
    return 0
  fi

  # The patch is on disk but the panel will not start with it. Put the baseline
  # back, restart once more, and stop the guard from trying again — two minutes
  # from now is not a fix, it is the same failure with the panel down in between.
  if _fd_bak_is_pristine "$f.bak"; then
    cp -a "$f.bak" "$f"
    systemctl restart "$_FD_UNIT" >/dev/null 2>&1 || true
  fi
  _fd_halt
  _fd_note "re-patched $f but ${_FD_UNIT} would not start — baseline restored, guard HALTED"
  return 1
}
