# shellcheck shell=bash
# =============================================================================
# module: reality-alpn — Reality domain ALPN fix
# =============================================================================
# hiddifypanel builds an SSL context with `set_alpn_protocols(["h2"])` and uses
# it to probe a candidate Reality SNI domain. A domain that only speaks http/1.1
# aborts that handshake with "no application protocol", so the panel rejects a
# perfectly usable Reality target. Offering http/1.1 next to h2 fixes it.
#
# THIS MODULE IS THE ODD ONE OUT: every other module writes SYSTEM state, so what
# undoes it is Hiddify's apply-config. This one edits panel CODE inside the venv,
# where the thing that undoes it is a Hiddify UPDATE — pip reinstalls hiddifypanel
# and the h2-only list is silently back, with nothing anywhere reporting it. That
# is what mod_reassert watches for.
#
# Re-applying means restarting hiddify-panel, and mod_reassert runs every 2
# minutes. So the reassert path has exactly one job before anything else: decide
# "already patched" vs "was reverted", and restart NOTHING in the first case. A
# restart on every tick would keep the admin UI and subscription serving down
# forever while every check still said the patch was in place.
#
# The second reassert rule, learned the hard way: re-patch freely, but restart the
# panel ONLY if it was active before we touched it. The event that reverts our
# patch IS a Hiddify update, and that update is driving hiddify-panel at the same
# moment — a restart we issue in that window cannot succeed, and treating it as
# "our patch killed the panel" made the guard revert the good patch and halt
# itself permanently, on the one path the guard exists for.
# =============================================================================

# The core reads this metadata by sourcing the file, so shellcheck cannot see
# the use of any of it.
# shellcheck disable=SC2034
MOD_ID="reality-alpn"
MOD_TITLE="Reality domain ALPN fix"
MOD_DESC="Lets the panel accept Reality SNI domains that only speak http/1.1, by offering http/1.1 alongside h2 in the panel's ALPN list (a Hiddify update wipes this; the guard re-applies it)."
MOD_GUARD=yes

# Fixed strings, matched with grep -F on purpose: the payload is full of regex
# metacharacters ([ ] ( ) . /) and every escaping bug in this area produces a
# false "already patched" rather than a visible error.
_RA_OLD='set_alpn_protocols(["h2"])'
_RA_NEW='set_alpn_protocols(["h2", "http/1.1"])'
_RA_UNIT="hiddify-panel"
_RA_PROBE="http://127.0.0.1:9000/"

# --------------------------------------------------------------- discovery ---
# A glob that matches nothing expands to the literal pattern, which then sails
# through `[ -f ... ]` checks as a plausible-looking path; nullglob in a subshell
# is what keeps "not installed" distinguishable from "found one file".
_ra_targets() {
  (
    shopt -s nullglob
    local p
    for p in /opt/hiddify-manager/.venv*/lib/python*/site-packages/hiddifypanel/hutils/network/net.py; do
      printf '%s\n' "$p"
    done
  )
}

_ra_target_count() {
  local -a m=()
  mapfile -t m < <(_ra_targets)
  printf '%s\n' "${#m[@]}"
}

# Exactly one match or nothing: a second venv left behind by an upgrade (.venv
# plus .venv-old) means we cannot know which tree the running panel imports from,
# and patching the wrong one is a silent no-op that looks applied.
_ra_target() {
  local -a m=()
  mapfile -t m < <(_ra_targets)
  [ "${#m[@]}" -eq 1 ] || return 1
  printf '%s\n' "${m[0]}"
}

# Occurrences, not matching lines. `grep -c` counts lines, so two call sites on
# one physical line report 1 and a half-applied patch passes verification.
_ra_count() {                            # <file> <fixed-string> -> integer
  local n
  [ -f "$1" ] || { printf '0\n'; return 0; }
  # tr, because some wc implementations pad the count with spaces and every
  # comparison here is a string comparison — "      0" != "0" would read as
  # "already patched" on exactly the boxes where nothing is patched.
  n="$(grep -oF -e "$2" -- "$1" 2>/dev/null | wc -l | tr -dc '0-9')" || n=""
  printf '%s\n' "${n:-0}"
}

_ra_python() {
  local p
  for p in /opt/hiddify-manager/.venv*/bin/python3 /opt/hiddify-manager/.venv*/bin/python; do
    [ -x "$p" ] && { printf '%s\n' "$p"; return 0; }
  done
  # The system interpreter is an acceptable fallback: we only need a syntax
  # check, and shipping an unverified edit into a restarted panel is worse than
  # checking it with a python of a slightly different minor version.
  p="$(command -v python3 2>/dev/null)" || return 1
  [ -n "$p" ] || return 1
  printf '%s\n' "$p"
}

_ra_unit_exists() {
  systemctl cat "$_RA_UNIT" >/dev/null 2>&1
}

_ra_panel_state() {
  local s
  s="$(systemctl is-active "$_RA_UNIT" 2>/dev/null)" || true
  printf '%s\n' "${s:-unknown}"
}

# systemd calls a Type=simple unit "active" the moment exec() returns — before
# the interpreter has imported net.py. A panel that dies at import time therefore
# passes a bare is-active check, and mod_verify signs off on a corpse. Re-check
# after a short settle, which is the window an import-time failure needs to show.
_ra_wait_panel() {                       # <max-seconds>
  local deadline=$(( SECONDS + ${1:-20} ))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if [ "$(_ra_panel_state)" = "active" ]; then
      sleep 3
      [ "$(_ra_panel_state)" = "active" ] && return 0
    fi
    sleep 1
  done
  [ "$(_ra_panel_state)" = "active" ]
}

_ra_restart_panel() {                    # restart + wait; 0 only if it came back
  _ra_unit_exists || return 1
  systemctl restart "$_RA_UNIT" >/dev/null 2>&1 || true
  _ra_wait_panel 25
}

# 400 here is the HEALTHY answer — Hiddify only serves the panel under its secret
# proxy path, so a bare GET / on 9000 is supposed to be refused. Informational
# only; never gate on it.
_ra_http_probe() {
  local code
  command -v curl >/dev/null 2>&1 || { printf 'n/a\n'; return 0; }
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "$_RA_PROBE" 2>/dev/null)" || code=""
  printf '%s\n' "${code:-none}"
}

# ---------------------------------------------------------------- baseline ---
# The sibling .bak is the restore source, and it is refreshed — but ONLY from a
# file that does not already contain our patch. The old standalone script never
# overwrote an existing .bak, which was right in spirit and wrong in practice:
# after a Hiddify update replaced net.py, that kept-forever .bak was the previous
# RELEASE's code, so "revert" would have installed stale panel source. Refreshing
# is safe precisely because of the guard below — the baseline can never become a
# modified copy. ht_backup keeps the very first version forever as an archive.
#
# 0 = $bak now holds pristine upstream, 1 = hard failure, 2 = the file already
# carries our patch so no baseline was taken. 2 used to be 0, and the caller then
# announced a baseline that had never been written: harmless for a FULLY patched
# file, a lie for a half-patched one (one call site edited, no .bak anywhere).
_ra_snapshot_baseline() {                # <net.py>
  local f="$1" bak="$1.bak"
  [ -f "$f" ] || return 1
  [ "$(_ra_count "$f" "$_RA_NEW")" = "0" ] || return 2
  if [ ! -f "$bak" ] || ! cmp -s "$f" "$bak"; then
    cp -a "$f" "$bak" || return 1
  fi
  ht_backup "$f"
  return 0
}

_ra_bak_is_pristine() {                  # <net.py.bak>
  [ -f "$1" ] || return 1
  [ "$(_ra_count "$1" "$_RA_NEW")" = "0" ] || return 1
  [ "$(_ra_count "$1" "$_RA_OLD")" != "0" ]
}

# Python caches by (source mtime, source size) and both change here, so this is
# belt-and-braces — but a stale net.cpython-3XX.pyc is the one way a correct edit
# on disk can still leave the old ALPN list running.
_ra_drop_pyc() {                         # <net.py>
  local d; d="$(dirname "$1")"
  rm -f "$d"/__pycache__/net.cpython-*.pyc 2>/dev/null || true
}

# ------------------------------------------------------------------- patch ---
# Edit a copy, prove the copy compiles, then move it over the live file. The
# panel therefore never has a broken net.py on disk for even a moment, and the
# "restore from .bak" path below is a backstop rather than the normal recovery.
_ra_patch_file() {                       # <net.py> -> 0 patched, 1 untouched
  local f="$1" tmp py

  # Temp file in the SAME directory: mv is only atomic within one filesystem and
  # /tmp is very often a separate one.
  tmp="$(mktemp "${f}.ht-XXXXXX" 2>/dev/null)" || return 1
  if ! cp -a "$f" "$tmp"; then rm -f "$tmp"; return 1; fi

  # `|` delimiter so the http/1.1 slash needs no escaping; /g because a second
  # call site on the same line must not survive; no `context.` receiver prefix,
  # so what we detect and what we replace are literally the same text.
  if ! sed -i 's|set_alpn_protocols(\["h2"\])|set_alpn_protocols(["h2", "http/1.1"])|g' "$tmp"; then
    rm -f "$tmp"; return 1
  fi
  if [ "$(_ra_count "$tmp" "$_RA_NEW")" = "0" ] || [ "$(_ra_count "$tmp" "$_RA_OLD")" != "0" ]; then
    rm -f "$tmp"; return 1
  fi

  # `python -m py_compile` would drop a __pycache__ entry named after the TEMP
  # file into the panel's site-packages, where it would sit forever. Compile to
  # an explicit cfile we own and delete instead.
  py="$(_ra_python)" || py=""
  if [ -n "$py" ]; then
    if ! "$py" -c 'import py_compile,sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)' \
         "$tmp" "$tmp.pyc" >/dev/null 2>&1; then
      rm -f "$tmp" "$tmp.pyc"
      return 1
    fi
  fi
  rm -f "$tmp.pyc"

  if ! mv -f "$tmp" "$f"; then rm -f "$tmp"; return 1; fi
  _ra_drop_pyc "$f"

  # Contract from the standalone script: if the live file somehow does not carry
  # the patch after the move, put the baseline back rather than leave it unknown.
  if [ "$(_ra_count "$f" "$_RA_NEW")" = "0" ]; then
    # Pristine check, not merely "a file exists at that path". Every other reader
    # of .bak goes through _ra_bak_is_pristine; this one used to take whatever was
    # there, so a .bak left behind by an earlier panel RELEASE would be installed
    # over the current package — version skew that compiles cleanly and then fails
    # at runtime, which is exactly the class of bug py_compile cannot catch.
    if _ra_bak_is_pristine "$f.bak"; then cp -a "$f.bak" "$f"; fi
    _ra_drop_pyc "$f"
    return 1
  fi
  return 0
}

# ----------------------------------------------------------------- halting ---
# If a re-patch ever leaves the panel dead, we restore and then STOP trying. The
# guard fires every 2 minutes; a patch/restart/fail/restore/restart cycle on that
# clock is worse than the bug it is chasing. Cleared by an explicit mod_apply.
_ra_halted()  { [ "$(ht_conf_get halted 0)" = "1" ]; }
_ra_halt()    { ht_conf_set halted 1; }
_ra_unhalt()  { [ "$(ht_conf_get halted 0)" = "1" ] && ht_conf_set halted 0; return 0; }

# The guard is silent by design, so its findings go to the toolkit log — but only
# when they CHANGE, or a permanent condition writes 720 identical lines a day.
_ra_note() {                             # <message>
  local msg="$1" nf prev
  nf="$(ht_state_dir)/${MOD_ID}.note"
  prev="$(cat "$nf" 2>/dev/null)" || prev=""
  [ "$prev" = "$msg" ] && return 0
  mkdir -p "$(ht_state_dir)" 2>/dev/null || true
  printf '%s\n' "$msg" > "$nf" 2>/dev/null || true
  ht_log "[$MOD_ID] $msg"
  return 0
}

_ra_note_clear() {
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

  n="$(_ra_target_count)"
  if [ "$n" = "0" ]; then
    printf '  %-9s %s\n' "file" "hiddifypanel/hutils/network/net.py not found"
    printf 'ABSENT  panel python package not found — nothing to patch\n'
    return 0
  fi
  if [ "$n" != "1" ]; then
    _ra_targets | sed 's/^/  file      /'
    printf 'PARTIAL  %s candidate net.py files — cannot tell which venv the panel imports\n' "$n"
    return 0
  fi

  f="$(_ra_target)" || return 1
  new="$(_ra_count "$f" "$_RA_NEW")"
  old="$(_ra_count "$f" "$_RA_OLD")"
  panel="$(_ra_panel_state)"
  if _ra_bak_is_pristine "$f.bak"; then
    bak="present"
  elif [ -f "$f.bak" ]; then
    bak="present (not a clean baseline)"
  else
    bak="absent"
  fi
  hal="no"; _ra_halted && hal="yes"
  cnt="$(ht_conf_get repatch_count 0)"
  last="$(ht_conf_get repatch_last "")"

  printf '  %-9s %s\n' "file" "$f"
  printf '  %-9s %s patched / %s still h2-only\n' "alpn" "$new" "$old"
  printf '  %-9s %s\n' "backup" "$bak"
  printf '  %-9s %s\n' "panel" "$panel"
  [ "$cnt" != "0" ] && printf '  %-9s %s (last %s) — Hiddify updates keep reverting it\n' \
                              "re-applied" "$cnt" "${last:-unknown}"
  [ "$hal" = "yes" ] && printf '  %-9s %s\n' "guard" "HALTED — a re-patch took the panel down; re-apply by hand"

  # HALTED is checked first, and reports PARTIAL rather than ABSENT: the halt path
  # reverts the patch, so the token was ABSENT, which the main menu draws as a dim
  # "off" — indistinguishable from a module nobody ever enabled. This one IS
  # enabled and has quietly stopped defending itself; yellow "partial" is the truth.
  if [ "$hal" = "yes" ]; then
    printf 'PARTIAL  guard HALTED after a failed re-patch — enabled but no longer asserting\n'
  elif [ "$new" != "0" ] && [ "$old" = "0" ]; then
    printf 'APPLIED  panel offers h2 + http/1.1\n'
  elif [ "$new" != "0" ] && [ "$old" != "0" ]; then
    printf 'PARTIAL  %s call site(s) still offer h2 only\n' "$old"
  elif [ "$old" != "0" ]; then
    printf 'ABSENT   panel offers h2 only\n'
  else
    printf 'PARTIAL  set_alpn_protocols(["h2"]) not found — panel code changed upstream\n'
  fi
  return 0
}

mod_apply() {
  local n f new old code rc

  ht_is_hiddify || { err "hiddify-manager is not installed here"; return 1; }

  n="$(_ra_target_count)"
  if [ "$n" = "0" ]; then
    err "hiddifypanel net.py not found — aborting, nothing changed"
    return 1
  fi
  if [ "$n" != "1" ]; then
    err "glob matched $n net.py files — aborting, nothing changed"
    _ra_targets | sed 's/^/    /'
    return 1
  fi
  f="$(_ra_target)" || return 1

  new="$(_ra_count "$f" "$_RA_NEW")"
  old="$(_ra_count "$f" "$_RA_OLD")"

  # Recorded on EVERY path, before any branch below can return. mod_verify gates
  # on this value and do_apply answers a failed verify with mod_revert + disable,
  # so a value left over from an EARLIER apply was lethal: re-running apply on an
  # already-patched box returned early without refreshing it, verify then compared
  # a panel that was down for its own reasons (update, OOM, admin stopped it)
  # against a stale "active", and the no-op apply ripped out a healthy patch.
  ht_conf_set panel_pre_state "$(_ra_panel_state)"

  if [ "$new" != "0" ] && [ "$old" = "0" ]; then
    _ra_snapshot_baseline "$f" >/dev/null 2>&1 || true
    _ra_unhalt; _ra_note_clear
    ok "already patched — panel NOT restarted"
    return 0
  fi
  if [ "$old" = "0" ]; then
    err "target pattern set_alpn_protocols([\"h2\"]) not found — aborting, nothing changed"
    return 1
  fi

  _ra_snapshot_baseline "$f"
  rc=$?
  if [ "$rc" = "1" ]; then
    err "could not write the pristine baseline $f.bak — aborting, nothing changed"
    return 1
  elif [ "$rc" = "2" ]; then
    # Half-patched already. Say so instead of implying a baseline exists: the
    # reverse-sed in mod_revert is the only way back from here.
    warn "$f already carries the patch on some call sites — no pristine $f.bak taken; revert will reverse the edit instead"
  fi

  if ! _ra_patch_file "$f"; then
    err "patch did not apply cleanly (edit rejected or failed to compile) — file left untouched"
    return 1
  fi
  ok "patched $(_ra_count "$f" "$_RA_NEW") call site(s): h2 -> h2 + http/1.1"

  if ! _ra_unit_exists; then
    warn "no ${_RA_UNIT}.service on this host — file patched, nothing restarted"
    _ra_unhalt; _ra_note_clear
    return 0
  fi
  if _ra_restart_panel; then
    code="$(_ra_http_probe)"
    ok "${_RA_UNIT} active (http=${code}; 400 is the normal answer on 9000)"
  else
    warn "${_RA_UNIT} did not come back active — verification will roll this back"
  fi

  _ra_unhalt
  _ra_note_clear
  ht_conf_set applied_at "$(date -Is)"
  return 0
}

mod_verify() {
  local f new old py pre

  f="$(_ra_target)" || { err "expected exactly one net.py, found $(_ra_target_count)"; return 1; }

  new="$(_ra_count "$f" "$_RA_NEW")"
  old="$(_ra_count "$f" "$_RA_OLD")"
  [ "$new" != "0" ] || { err "no patched call site in $f"; return 1; }
  [ "$old" = "0" ]  || { err "$old call site(s) still offer h2 only"; return 1; }

  py="$(_ra_python)" || py=""
  if [ -n "$py" ]; then
    if ! "$py" -c 'import py_compile,sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)' \
         "$f" "$f.verify.pyc" >/dev/null 2>&1; then
      rm -f "$f.verify.pyc"
      err "patched file does not compile"
      return 1
    fi
    rm -f "$f.verify.pyc"
  else
    warn "no python interpreter found — compile check skipped"
  fi

  pre="$(ht_conf_get panel_pre_state unknown)"
  if [ "$pre" = "active" ]; then
    if ! _ra_wait_panel 20; then
      err "${_RA_UNIT} was active before and is $(_ra_panel_state) now"
      return 1
    fi
  else
    warn "${_RA_UNIT} was '${pre}' before this change — liveness not used as a gate"
  fi

  ok "h2 + http/1.1 offered, file compiles, panel $(_ra_panel_state)"
  return 0
}

mod_revert() {
  local n f new bak tmp restored=0

  n="$(_ra_target_count)"
  if [ "$n" = "0" ]; then
    ok "panel python package not present — nothing to restore"
    _ra_unhalt; _ra_note_clear
    return 0
  fi
  if [ "$n" != "1" ]; then
    err "glob matched $n net.py files — refusing to guess which one to restore"
    return 1
  fi
  f="$(_ra_target)" || return 1
  bak="$f.bak"
  new="$(_ra_count "$f" "$_RA_NEW")"

  if [ "$new" = "0" ]; then
    rm -f "$bak"
    _ra_unhalt; _ra_note_clear
    ok "already unpatched — panel NOT restarted"
    return 0
  fi

  if _ra_bak_is_pristine "$bak"; then
    # Same temp-in-the-same-directory + mv discipline as _ra_patch_file, and for
    # the same reason: `cp` onto the live file truncates it first, so a cp that
    # dies half way (ENOSPC) leaves a torn net.py behind. That torn file contains
    # no _RA_NEW, which sailed through the old "the patch is gone" test — and the
    # tail of this function then restarts the panel onto it.
    tmp="$(mktemp "${f}.ht-XXXXXX" 2>/dev/null)" || tmp=""
    if [ -n "$tmp" ] && cp -a "$bak" "$tmp" && mv -f "$tmp" "$f"; then
      restored=1
    else
      [ -n "$tmp" ] && rm -f "$tmp"
      err "could not restore from $bak"
    fi
  fi
  if [ "$restored" = "0" ]; then
    # No usable .bak (deleted by hand, or written by an older release). The
    # reverse substitution is an exact textual inverse of the forward one and,
    # unlike the .bak, it cannot resurrect code from a different panel version.
    warn "no clean $bak — reverting by reversing the edit instead"
    if sed -i 's|set_alpn_protocols(\["h2", "http/1.1"\])|set_alpn_protocols(["h2"])|g' "$f"; then
      restored=1
    fi
  fi
  # Assert the POSITIVE. "Our patch is gone" is also true of an empty, truncated
  # or otherwise destroyed file, and this is the last gate before a panel restart.
  if [ "$restored" = "0" ] || [ "$(_ra_count "$f" "$_RA_NEW")" != "0" ] \
                           || [ "$(_ra_count "$f" "$_RA_OLD")" = "0" ]; then
    err "revert failed — $f does not carry the original ALPN list"
    return 1
  fi
  _ra_drop_pyc "$f"
  rm -f "$bak"
  ok "restored the original ALPN list (h2 only)"

  _ra_unhalt
  _ra_note_clear
  ht_conf_set panel_pre_state ""
  # The re-patch counter belongs to the enablement that just ended; leaving it
  # behind makes a reverted module report update-churn it is no longer watching.
  ht_conf_set repatch_count 0

  if ! _ra_unit_exists; then
    warn "no ${_RA_UNIT}.service on this host — nothing restarted"
    return 0
  fi
  if _ra_restart_panel; then
    ok "${_RA_UNIT} active"
    return 0
  fi
  err "${_RA_UNIT} did not come back active after the restore"
  return 1
}

mod_reassert() {
  local f new old pre rc

  # Non-zero is reserved for TRANSIENT failures worth retrying. do_reassert turns
  # any non-zero into a "reassert FAILED" line on every 2-minute tick and nothing
  # rotates toolkit.log, so the permanent states below (halted, unresolvable venv,
  # upstream renamed the call) used to write 720 identical failure lines a day
  # about something no retry can fix. The deduped note IS the report for those.
  _ra_halted && return 0
  ht_is_hiddify || return 0

  f="$(_ra_target)" || {
    _ra_note "cannot resolve a single hiddifypanel net.py ($(_ra_target_count) candidates) — not touching anything"
    return 0
  }

  new="$(_ra_count "$f" "$_RA_NEW")"
  old="$(_ra_count "$f" "$_RA_OLD")"

  # THE FAST PATH, and the one that runs 719 times out of 720. Nothing is
  # written and above all nothing is restarted.
  if [ "$new" != "0" ] && [ "$old" = "0" ]; then
    _ra_note_clear
    return 0
  fi

  if [ "$old" = "0" ]; then
    _ra_note "set_alpn_protocols([\"h2\"]) is gone from $f — upstream code changed, leaving it alone"
    return 0
  fi

  # What the panel was doing BEFORE we touched anything. mod_apply records the
  # same fact for mod_verify; the guard needs it even more, because the ONLY thing
  # that puts h2-only code back is a Hiddify update — and a Hiddify update is
  # stopping and starting this very unit. Firing every 2 minutes, the guard lands
  # inside that window as a matter of course, so "not active" here overwhelmingly
  # means "hiddify is still mid-update", not "our one-line edit killed the panel".
  pre="$(_ra_panel_state)"

  # Reaching here means the panel package was replaced under us (a Hiddify
  # update), so the file on disk right now IS the new pristine upstream copy —
  # snapshot it before editing, or the .bak keeps pointing at the old release.
  # rc=2 (half-patched, no baseline taken) is not a reason to refuse the repair;
  # only a hard write failure is.
  _ra_snapshot_baseline "$f"
  rc=$?
  if [ "$rc" = "1" ]; then
    _ra_note "could not refresh $f.bak — skipping re-patch"
    return 1
  fi

  if ! _ra_patch_file "$f"; then
    _ra_note "re-patch of $f failed (edit rejected or would not compile)"
    return 1
  fi

  ht_conf_set repatch_count "$(( $(ht_conf_get repatch_count 0) + 1 ))"
  ht_conf_set repatch_last "$(date -Is)"
  ht_log "[$MOD_ID] panel code was reverted (Hiddify update) — re-applied the ALPN patch"

  _ra_unit_exists || { _ra_note_clear; return 0; }

  # The patch is on disk, and whoever is driving this unit will import it when
  # they start it — so a panel that was already down needs nothing from us.
  # Restarting a unit somebody else currently owns is how a GOOD patch gets
  # destroyed: mid-update the restart cannot succeed, the failure path below then
  # restores the baseline and halts the guard for good, and the module is left
  # exactly in the state it exists to prevent. Only restart what was ours to break.
  if [ "$pre" != "active" ]; then
    _ra_note "re-patched $f while ${_RA_UNIT} was '${pre}' — not restarting it, re-checking next tick"
    return 0
  fi

  # Only now: something really changed on disk AND the panel was up before we
  # changed it, so a panel that does not come back is genuinely on us.
  if _ra_restart_panel; then
    _ra_note_clear
    return 0
  fi

  # The patch is on disk but the panel will not start with it. Put the baseline
  # back, restart once more, and stop the guard from trying again — two minutes
  # from now is not a fix, it is the same failure with the panel down in between.
  if _ra_bak_is_pristine "$f.bak"; then
    cp -a "$f.bak" "$f" && _ra_drop_pyc "$f"
    systemctl restart "$_RA_UNIT" >/dev/null 2>&1 || true
  fi
  _ra_halt
  _ra_note "re-patched $f but ${_RA_UNIT} would not start — baseline restored, guard HALTED"
  return 1
}
