#!/usr/bin/env bash
# =============================================================================
# hiddify-toolkit — core library
# =============================================================================
# Sourced by bin/hiddify-toolkit and by every module. Provides output helpers,
# state/config/backup storage, module loading, and the guard timer machinery.
#
# THE PERSISTENCE PROBLEM THIS TOOLKIT EXISTS TO SOLVE
#   Hiddify re-runs /opt/hiddify-manager/common/install.sh on every apply-config,
#   every update, and @reboot. That script re-links its own sysctl.conf and runs
#   `sysctl --system`, then imperatively runs `sysctl -w ...disable_ipv6=0`, and
#   rebuilds the iptables ruleset from scratch. So a change written only to a file
#   in /etc/sysctl.d/ can be undone seconds later by an imperative `sysctl -w`, and
#   any iptables rule we add is simply gone after an apply-config.
#
#   Hence every module implements mod_reassert(), and one systemd timer re-runs
#   the reassert of every ENABLED module on a short cycle. Files we own are named
#   with a `zz-` prefix so that when Hiddify does run `sysctl --system`, ours are
#   applied last and win.
# =============================================================================

HT_VERSION_FILE="${HT_ROOT:-/opt/hiddify-toolkit}/VERSION"
# ht_module_run re-sources this file inside a subshell, so these must be written as
# "keep whatever is already set" — otherwise every override is silently reset and a
# test harness ends up writing into the real /var/lib state.
HT_STATE="${HT_STATE:-/var/lib/hiddify-toolkit}"
HT_ENABLED_DIR="${HT_ENABLED_DIR:-$HT_STATE/enabled}"
HT_CONF_DIR="${HT_CONF_DIR:-$HT_STATE/conf}"
HT_BACKUP_ROOT="${HT_BACKUP_ROOT:-$HT_STATE/backup}"
HT_LOG="${HT_LOG:-$HT_STATE/toolkit.log}"

HT_GUARD_SERVICE=/etc/systemd/system/hiddify-toolkit-guard.service
HT_GUARD_TIMER=/etc/systemd/system/hiddify-toolkit-guard.timer

# ------------------------------------------------------------------ output ---
# Colour only when stdout is a terminal, so log files and `| tee` stay readable.
if [ -t 1 ]; then
  _C_HEAD=$'\033[1;36m'; _C_OK=$'\033[1;32m'; _C_WARN=$'\033[1;33m'
  _C_ERR=$'\033[1;31m'; _C_DIM=$'\033[2m'; _C_OFF=$'\033[0m'
else
  _C_HEAD=""; _C_OK=""; _C_WARN=""; _C_ERR=""; _C_DIM=""; _C_OFF=""
fi

say()  { printf '%s%s%s\n' "$_C_HEAD" "$*" "$_C_OFF"; }
ok()   { printf '  %s+%s %s\n' "$_C_OK"   "$_C_OFF" "$*"; }
warn() { printf '  %s!%s %s\n' "$_C_WARN" "$_C_OFF" "$*"; }
err()  { printf '  %sx%s %s\n' "$_C_ERR"  "$_C_OFF" "$*" >&2; }
dim()  { printf '%s%s%s\n' "$_C_DIM" "$*" "$_C_OFF"; }

ht_log() {
  mkdir -p "$HT_STATE" 2>/dev/null
  printf '%s  %s\n' "$(date -Is)" "$*" >> "$HT_LOG" 2>/dev/null || true
}

need_root() {
  [ "$(id -u)" -eq 0 ] || { err "must run as root"; exit 1; }
}

# ------------------------------------------------------------------- state ---
ht_init_state() { mkdir -p "$HT_ENABLED_DIR" "$HT_CONF_DIR" "$HT_BACKUP_ROOT"; }

ht_state_dir()  { printf '%s\n' "$HT_STATE"; }

ht_is_enabled() { [ -e "$HT_ENABLED_DIR/${1:-$MOD_ID}" ]; }
ht_mark_enabled()   { ht_init_state; : > "$HT_ENABLED_DIR/${1:-$MOD_ID}"; }
ht_mark_disabled()  { rm -f "$HT_ENABLED_DIR/${1:-$MOD_ID}"; }

ht_enabled_list() {
  [ -d "$HT_ENABLED_DIR" ] || return 0
  find "$HT_ENABLED_DIR" -maxdepth 1 -type f -printf '%f\n' 2>/dev/null | sort
}

# --- per-module key/value config ---------------------------------------------
_ht_conf_file() { printf '%s/%s.conf\n' "$HT_CONF_DIR" "${MOD_ID:-unknown}"; }

ht_conf_get() {
  local key="$1" def="${2:-}" f; f="$(_ht_conf_file)"
  [ -f "$f" ] || { printf '%s\n' "$def"; return 0; }
  local v; v="$(grep -m1 "^${key}=" "$f" 2>/dev/null | cut -d= -f2-)"
  [ -n "$v" ] && printf '%s\n' "$v" || printf '%s\n' "$def"
}

ht_conf_set() {
  local key="$1" val="$2" f; f="$(_ht_conf_file)"
  ht_init_state
  touch "$f"; chmod 600 "$f"
  if grep -q "^${key}=" "$f" 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${val}|" "$f"
  else
    printf '%s=%s\n' "$key" "$val" >> "$f"
  fi
}

# --- backups ------------------------------------------------------------------
ht_backup_dir() {
  local d="$HT_BACKUP_ROOT/${MOD_ID:-unknown}"
  mkdir -p "$d"; printf '%s\n' "$d"
}

# Copy a file into this module's backup dir exactly ONCE. Re-running apply must
# never overwrite the pristine baseline with an already-modified copy — that is
# how a revert silently starts restoring the broken state instead of the original.
ht_backup() {
  local src="$1" d; d="$(ht_backup_dir)"
  [ -f "$src" ] || return 0
  local dst
  dst="$d/$(printf '%s' "$src" | sed 's|/|_|g')"
  [ -f "$dst" ] || cp -a "$src" "$dst"
}

ht_is_hiddify() { [ -d /opt/hiddify-manager ]; }

# Earlier iterations of these fixes shipped as standalone scripts, each with its own
# systemd timer. A module that supersedes one MUST retire it: two timers enforcing the
# same setting is not merely redundant — on revert, the orphaned one silently puts the
# change back and the revert looks broken.
ht_retire_legacy_unit() {                # <unit-basename>, e.g. hiddify-noipv6
  local u="$1" found=0
  [ -f "/etc/systemd/system/${u}.timer" ]   && found=1
  [ -f "/etc/systemd/system/${u}.service" ] && found=1
  [ "$found" = "1" ] || return 0
  systemctl disable --now "${u}.timer" >/dev/null 2>&1
  systemctl disable --now "${u}.service" >/dev/null 2>&1
  rm -f "/etc/systemd/system/${u}.timer" "/etc/systemd/system/${u}.service"
  systemctl daemon-reload
  warn "retired legacy unit ${u} (superseded by this module)"
}

# ----------------------------------------------------------------- modules ---
ht_module_files() {
  local dir="${HT_ROOT:-/opt/hiddify-toolkit}/modules"
  [ -d "$dir" ] || return 0
  find "$dir" -maxdepth 1 -name '*.sh' -type f 2>/dev/null | sort
}

# Every module defines the SAME function names (mod_apply, mod_revert, ...), so
# only one may ever be sourced into a given shell. Both helpers below therefore
# run in a subshell — that isolation is what lets the menu list ten modules and
# then act on one without their functions colliding.
ht_module_meta() {                       # <file>  ->  id|title|title_fa|guard|desc
  (
    # shellcheck disable=SC1090
    . "$1" 2>/dev/null || exit 1
    printf '%s|%s|%s|%s|%s\n' "${MOD_ID:-}" "${MOD_TITLE:-}" "${MOD_TITLE_FA:-}" \
                              "${MOD_GUARD:-no}" "${MOD_DESC:-}"
  )
}

ht_module_file_by_id() {
  local want="$1" f id
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    id="$(ht_module_meta "$f" | cut -d'|' -f1)"
    [ "$id" = "$want" ] && { printf '%s\n' "$f"; return 0; }
  done < <(ht_module_files)
  return 1
}

# Run one module function in an isolated subshell with the core already loaded.
ht_module_run() {                        # <file> <function> [args...]
  local file="$1" fn="$2"; shift 2
  (
    HT_ROOT="${HT_ROOT:-/opt/hiddify-toolkit}"
    # shellcheck disable=SC1090
    . "$HT_ROOT/lib/core.sh"
    # shellcheck disable=SC1090
    . "$file" || exit 1
    if ! declare -F "$fn" >/dev/null 2>&1; then
      err "module $(basename "$file") does not implement $fn"; exit 3
    fi
    "$fn" "$@"
  )
}

# mod_status contracts to print a machine token as the FIRST word of its LAST
# line. Anything else (missing function, crash, garbage) is reported UNKNOWN
# rather than being allowed to look like a healthy ABSENT.
ht_module_state() {                      # <file> -> APPLIED|ABSENT|PARTIAL|UNKNOWN
  local out tok
  out="$(ht_module_run "$1" mod_status 2>/dev/null)" || { printf 'UNKNOWN\n'; return 0; }
  tok="$(printf '%s\n' "$out" | tail -1 | awk '{print $1}')"
  case "$tok" in
    APPLIED|ABSENT|PARTIAL) printf '%s\n' "$tok" ;;
    *) printf 'UNKNOWN\n' ;;
  esac
}

# ------------------------------------------------------------------- guard ---
ht_guard_install() {
  cat > "$HT_GUARD_SERVICE" <<EOF
[Unit]
Description=hiddify-toolkit: re-assert enabled modules (Hiddify apply-config undoes them)
After=network.target

[Service]
Type=oneshot
# A module whose reassert blocks (a hung network probe, a stuck systemctl) must not
# wedge the timer forever — cap it well under the 2-minute cycle.
TimeoutStartSec=90
ExecStart=${HT_ROOT:-/opt/hiddify-toolkit}/bin/hiddify-toolkit reassert
EOF
  cat > "$HT_GUARD_TIMER" <<'EOF'
[Unit]
Description=hiddify-toolkit: re-assert enabled modules every 2 minutes

[Timer]
OnBootSec=30s
OnUnitActiveSec=2min
AccuracySec=10s

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now hiddify-toolkit-guard.timer >/dev/null 2>&1
}

ht_guard_remove() {
  systemctl disable --now hiddify-toolkit-guard.timer >/dev/null 2>&1
  rm -f "$HT_GUARD_SERVICE" "$HT_GUARD_TIMER"
  systemctl daemon-reload
}

# A module can be APPLIED without the toolkit ever having applied it — the standalone
# scripts that predate this toolkit, a rebuilt box, or a restored state dir. Such a module
# has no enabled marker, so the guard would not re-assert it and `status` would cheerfully
# report "applied" for something nothing is protecting. Adopt it: if it is really applied,
# it gets a marker and therefore a guard.
#
# Adoption deliberately never runs mod_apply — the box is already in the target state and
# re-applying it would be a change nobody asked for. But mod_apply is also where a module
# RECORDS things, above all the baseline its revert replays, and adoption skips all of that.
# An adopted module whose revert then finds no baseline removes its files, reports success,
# and leaves the live values exactly as they were. So every adopted module gets one call to
# the OPTIONAL mod_adopt hook to do that bookkeeping (and nothing else — it must not change
# the box). Modules that do not implement it are unaffected: ht_module_run exits 3 and says
# so on stderr, both discarded here.
ht_adopt_applied() {
  local f id guard
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    IFS='|' read -r id _ _ guard _ < <(ht_module_meta "$f")
    [ "$guard" = "yes" ] || continue
    ht_is_enabled "$id" && continue
    if [ "$(ht_module_state "$f")" = "APPLIED" ]; then
      ht_mark_enabled "$id"
      ht_module_run "$f" mod_adopt >/dev/null 2>&1 || true
      ht_log "adopted pre-existing $id (applied outside the toolkit)"
    fi
  done < <(ht_module_files)
}

# The timer is only worth running while at least one guard-needing module is on.
ht_guard_sync() {
  local f id guard need=0
  ht_adopt_applied
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    IFS='|' read -r id _ _ guard _ < <(ht_module_meta "$f")
    [ "$guard" = "yes" ] && ht_is_enabled "$id" && need=1
  done < <(ht_module_files)
  if [ "$need" = "1" ]; then ht_guard_install; else ht_guard_remove; fi
}
