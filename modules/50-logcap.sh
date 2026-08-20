# shellcheck shell=bash
# =============================================================================
# module: logcap — log disk-space guard
# =============================================================================
# The failure this exists for: /opt/hiddify-manager/log fills the disk, and a
# Hiddify panel with no free space stops opening. The usual cure is to ssh in and
# delete the directory by hand, which is a cure only until the next time.
#
# Measured on a live panel (s7, 2026-08-20): hiddify_panel.err.log.1 was 321 MB,
# 14,639,476 of its 14,639,588 lines the single string "Client <n> hit errno <n>"
# — the panel's EPIPE/ECONNRESET spin loop on a dead client socket, which writes
# at ~4 MB/s while it lasts. Hiddify ships no rotation for these files at all.
#
# WHY logrotate CANNOT BE THE ANSWER, and this module can
#   The tuning module drops /etc/logrotate.d/hiddify-manager with `size 100M`.
#   `size` is a condition logrotate EVALUATES WHEN IT RUNS, and on Ubuntu it runs
#   from logrotate.timer, OnCalendar=daily. At 4 MB/s a day is ~345 GB, so the
#   disk is dead long before logrotate gets a turn — and `rotate 3` never fires.
#   Worse, the rotation that does eventually happen leaves the evidence behind:
#   the 321 MB file above was a ROTATED copy (.log.1), which logrotate's own
#   `size` clause never looks at again and nothing else was watching.
#
#   So the ceiling has to be enforced on a short cycle, over the WHOLE tree, not
#   just the live *.log files. That is the toolkit guard's 2-minute tick.
#
# THE ONE NON-OBVIOUS RULE: SIZE MEANS ALLOCATED BLOCKS, NEVER `stat -c %s`
#   hiddify-panel.service redirects with `StandardError=file:` — systemd's
#   `file:` opens WITHOUT O_APPEND, so the service writes at its own saved
#   offset. Truncate the file and the next write lands at that old offset and
#   punches a hole: the file is now SPARSE. Its APPARENT size is unchanged (and
#   keeps climbing) while its real cost on disk is a few hundred KB.
#
#   Verified on s6: hiddify_panel.err.log reported 2,150,617 bytes with 3,440
#   512-byte blocks allocated — 1.7 MB of actual disk for a 2.1 MB "size".
#
#   Cap on the apparent size and this module would re-truncate the same file on
#   every single tick, forever, reclaiming nothing and reporting hundreds of MB
#   that do not exist. Every measurement below is therefore `%b * 512`. The
#   apparent size resets by itself whenever the unit restarts, which an
#   apply-config does anyway.
#
# WHY TRUNCATE AND NOT DELETE (for live logs)
#   The writer holds the fd. Unlinking frees zero bytes until the service
#   restarts, so `rm` on a live log looks like it worked and changes nothing.
#   Rotated copies have no fd behind them and ARE deleted.
#
# AND THE ONE `find` CAN NEVER SEE
#   Deleting a live log with `rm` — the obvious manual cure, and the one that gets
#   used — does not free a byte. The writer keeps its fd, so the inode lives on
#   with no name: invisible to ls, to du, to find, to logrotate and to the sweep
#   above, and still growing. Measured on s4 while writing this module: 8,282 MB
#   of allocated disk (146 GB apparent) behind hiddify-panel's fd 2, on a box
#   whose whole visible log tree was 16 KB.
#
#   So the sweep also walks /proc/<pid>/fd for links that end in " (deleted)" and
#   point into the log tree, and truncates those through /proc. That reclaims the
#   space with no restart and no outage — proven live on s4: 14 GB used -> 4.5 GB,
#   hiddify-panel never left active.
#
# journald is capped here too, because it is the same disease and it was the
# larger consumer on all seven panels: with no SystemMaxUse, journald takes 10%
# of the filesystem (measured 1.0-2.4 GB per box, uncapped on every one).
# =============================================================================

# shellcheck disable=SC2034
MOD_ID="logcap"
MOD_TITLE="Log disk-space guard"
MOD_DESC="Holds /opt/hiddify-manager/log under a hard ceiling — every file capped, the whole tree on a budget, re-checked every 2 minutes instead of once a day — and caps systemd-journald, which ships uncapped at 10% of the disk. This is the failure that fills a panel's disk and stops the panel opening."
MOD_GUARD=yes

# The tuning module also truncates /opt/hiddify-manager/log/system/*.log at a
# HARDCODED 100 MB on the same guard tick, and it runs first (10- before 50-).
# That is a deliberate safety net for boxes where only tuning is on, and it is
# invisible in the log because tuning discards its reclaim output — so a live
# *.log can vanish from under this module with nothing here reporting it.
# Harmless while file_mb <= 100. Above that, tuning's fixed 100 MB is the real
# limit for that one directory, and mod_status says so rather than letting the
# configured number quietly not be the truth.
LC_TUNING_FIXED_MB=100

LC_LOGROOT=/opt/hiddify-manager/log
LC_JOURNALD_DIR=/etc/systemd/journald.conf.d
LC_JOURNALD_FILE=/etc/systemd/journald.conf.d/zz-hiddify-toolkit.conf

# Defaults. dir_mb is derived from file_mb so that lowering the per-file cap
# lowers the budget with it: tuning's logrotate keeps `rotate 3` plus the live
# file, which is exactly four cap-sized files.
LC_DEF_FILE_MB=100
LC_DEF_JOURNAL_MB=512

# journald cannot vacuum the ACTIVE journal file, whose default ceiling is 1/8 of
# SystemMaxUse. Anything inside this slack is journald behaving correctly, not a
# cap that failed, and re-vacuuming it every tick would be pure noise.
LC_JOURNAL_SLACK_MB=128

# --------------------------------------------------------------- settings ----
# Clamped on read, not only on write: the conf file is a plain text file an admin
# may edit, and a typo there must not turn into `truncate everything` on the next
# guard tick.
_lc_file_mb() {
  local v; v="$(ht_conf_get file_mb "$LC_DEF_FILE_MB")"
  case "$v" in (*[!0-9]*|'') v="$LC_DEF_FILE_MB" ;; esac
  [ "$v" -lt 1 ]     2>/dev/null && v=1
  [ "$v" -gt 100000 ] 2>/dev/null && v=100000
  printf '%s\n' "$v"
}

_lc_dir_mb() {
  local v f; f="$(_lc_file_mb)"
  v="$(ht_conf_get dir_mb "")"
  case "$v" in (*[!0-9]*|'') v=$(( f * 4 )) ;; esac
  # A budget below the per-file cap is unsatisfiable — the sweep would delete
  # every archive and then truncate every live log on every tick and still be
  # "over". Refuse to hold a limit that can only be met by an empty directory.
  [ "$v" -lt "$f" ] 2>/dev/null && v="$f"
  printf '%s\n' "$v"
}

# 0 is a real, supported value: it means "leave journald alone", for a box where
# somebody else already manages /etc/systemd/journald.conf.d.
_lc_journal_mb() {
  local v; v="$(ht_conf_get journal_mb "$LC_DEF_JOURNAL_MB")"
  case "$v" in (*[!0-9]*|'') v="$LC_DEF_JOURNAL_MB" ;; esac
  if [ "$v" != "0" ]; then
    [ "$v" -lt 16 ]     2>/dev/null && v=16
    [ "$v" -gt 100000 ] 2>/dev/null && v=100000
  fi
  printf '%s\n' "$v"
}

_lc_mb() { printf '%s\n' "$(( ${1:-0} / 1048576 ))"; }

# For messages only. Whole MB reads as "0 MB" for anything under a megabyte, and
# a reclaim line that says it freed 0 MB reads as a bug in the sweep.
_lc_human() {
  local b="${1:-0}"
  if [ "$b" -ge 1048576 ]; then printf '%s MB\n' "$(( b / 1048576 ))"
  elif [ "$b" -ge 1024 ]; then printf '%s KB\n' "$(( b / 1024 ))"
  else printf '%s B\n' "$b"; fi
}

# ----------------------------------------------------------- classification --
# Only these two classes are ever touched. Everything else in the tree —
# above all 0-install.lock, whose absence makes Hiddify believe no install is
# running and lets two apply-configs race — is reported and left completely alone.
_lc_class() {                            # <basename> -> live|archive|other
  case "$1" in
    *.lock|*.pid|*.sock)          printf 'other\n'   ;;
    *.log)                        printf 'live\n'    ;;
    *.gz|*.xz|*.bz2|*.zst|*.zip)  printf 'archive\n' ;;
    *.log.[0-9]*|*.[0-9])         printf 'archive\n' ;;
    *.old|*.bak)                  printf 'archive\n' ;;
    *)                            printf 'other\n'   ;;
  esac
}

# One find for the whole tree: blocks, mtime, path. %b is in 512-byte units and
# is the ONLY honest size here (see the header). -xdev so a mount under the log
# directory is somebody else's budget, and NUL records so a space in a filename
# cannot split a record.
_lc_scan() {
  [ -d "$LC_LOGROOT" ] || return 0
  find "$LC_LOGROOT" -xdev -type f -printf '%b\t%T@\t%p\0' 2>/dev/null
}

_lc_total_bytes() {
  local blocks mtime path total=0
  while IFS=$'\t' read -r -d '' blocks mtime path; do
    [ -n "$blocks" ] || continue
    total=$(( total + blocks * 512 ))
  done < <(_lc_scan)
  printf '%s\n' "$total"
}

# ---------------------------------------------------- deleted-but-open files --
# `rm` on a live log frees nothing — the writer holds the fd and the inode lives
# on unnamed. Nothing that walks the FILESYSTEM can see it, which is what makes
# this the most dangerous shape of the bug: the directory looks clean, du agrees,
# and df keeps climbing with nothing to point at.
#
# One find over the fd directories rather than a readlink per fd: a panel has a
# few hundred processes with tens of fds each, and a fork per fd every two
# minutes is not a guard, it is a load generator.
_lc_deleted_fds() {
  local d
  local -a dirs=()
  for d in /proc/[0-9]*/fd; do [ -d "$d" ] && dirs+=("$d"); done
  [ "${#dirs[@]}" -gt 0 ] || return 0
  find "${dirs[@]}" -maxdepth 1 -type l -lname "${LC_LOGROOT}/* (deleted)" -print0 2>/dev/null
}

# Only fds opened for WRITING. A deleted file somebody is still READING is not
# ours to empty, and the whole point of acting through /proc is that we are
# reaching past every normal safety check the filesystem would give us.
_lc_fd_writable() {                      # </proc/PID/fd/N>
  local pid num fl
  pid="${1#/proc/}"; pid="${pid%%/*}"
  num="${1##*/}"
  fl="$(awk '/^flags:/{print $2; exit}' "/proc/$pid/fdinfo/$num" 2>/dev/null)" || return 1
  [ -n "$fl" ] || return 1
  case $(( 8#$fl & 3 )) in (1|2) return 0 ;; esac
  return 1
}

# Prints "<bytes>\t<fdpath>\t<origpath>" per DISTINCT inode. Distinct matters:
# stdout and stderr are routinely two fds on one inode, and a fleet of duplicates
# would report the same 8 GB three times and truncate it three times.
_lc_orphans() {
  local fd tgt key sz base
  local -A seen=()
  while IFS= read -r -d '' fd; do
    tgt="$(readlink "$fd" 2>/dev/null)" || continue
    tgt="${tgt% (deleted)}"
    base="${tgt##*/}"
    # Same classification as the on-disk sweep: a lock or an unrecognised name is
    # left alone here too.
    case "$(_lc_class "$base")" in (live|archive) ;; (*) continue ;; esac
    key="$(stat -Lc '%d:%i' "$fd" 2>/dev/null)" || continue
    [ -n "${seen[$key]:-}" ] && continue
    seen[$key]=1
    sz="$(stat -Lc %b "$fd" 2>/dev/null)" || continue
    case "$sz" in (*[!0-9]*|'') continue ;; esac
    printf '%s\t%s\t%s\n' "$(( sz * 512 ))" "$fd" "$tgt"
  done < <(_lc_deleted_fds)
}

_lc_orphan_bytes() {
  local sz fd tgt t=0
  while IFS=$'\t' read -r sz fd tgt; do
    [ -n "$sz" ] && t=$(( t + sz ))
  done < <(_lc_orphans)
  printf '%s\n' "$t"
}

_lc_orphan_over_cap() {
  local sz fd tgt cap_b n=0
  cap_b=$(( $(_lc_file_mb) * 1048576 ))
  while IFS=$'\t' read -r sz fd tgt; do
    [ -n "$sz" ] && [ "$sz" -gt "$cap_b" ] && n=$(( n + 1 ))
  done < <(_lc_orphans)
  printf '%s\n' "$n"
}

# Truncating through /proc/<pid>/fd/<n> empties the inode the fd points at, with
# no restart and no outage — the alternative is restarting hiddify-panel, which
# is not something a 2-minute timer should be doing. Proven live on s4:
# 14 GB used -> 4.5 GB, hiddify-panel never left active.
_lc_sweep_orphans() {
  local sz fd tgt cap_b
  cap_b=$(( $(_lc_file_mb) * 1048576 ))
  while IFS=$'\t' read -r sz fd tgt; do
    [ -n "$sz" ] || continue
    [ "$sz" -gt "$cap_b" ] || continue
    _lc_fd_writable "$fd" || {
      printf 'SKIPPED %s (%s, deleted and held open READ-ONLY)\n' "$tgt" "$(_lc_human "$sz")"
      continue
    }
    if : > "$fd" 2>/dev/null; then
      printf 'truncated %s (%s, DELETED but still held open — invisible to du/find)\n' \
             "$tgt" "$(_lc_human "$sz")"
    else
      printf 'FAILED to truncate the deleted inode behind %s\n' "$tgt"
    fi
  done < <(_lc_orphans)
  return 0
}

# ------------------------------------------------------------------ sweep ----
# Prints one line per action taken; prints nothing at all on a quiet tick, which
# is what lets the caller decide whether anything is worth logging.
#
# Order matters. Per-file caps first, because they are the runaway case and they
# also shrink the tree; the directory budget afterwards, on what is left.
_lc_sweep() {
  local file_mb dir_mb cap_b budget_b
  file_mb="$(_lc_file_mb)"; dir_mb="$(_lc_dir_mb)"
  cap_b=$(( file_mb * 1048576 )); budget_b=$(( dir_mb * 1048576 ))

  # Before anything on disk: the space that no directory listing can account for.
  # Independent of the tree budget below — a deleted inode is not IN the tree, and
  # deleting an archive would not shrink it.
  _lc_sweep_orphans

  [ -d "$LC_LOGROOT" ] || return 0

  local blocks mtime path base cls sz total=0
  local -a live_p=() live_s=() arch_p=() arch_s=() arch_t=()

  # --- pass 1: per-file cap, and collect what pass 2 may act on ---------------
  while IFS=$'\t' read -r -d '' blocks mtime path; do
    [ -n "$blocks" ] || continue
    [ -f "$path" ] || continue
    sz=$(( blocks * 512 ))
    base="${path##*/}"
    cls="$(_lc_class "$base")"

    case "$cls" in
      live)
        if [ "$sz" -gt "$cap_b" ]; then
          # Truncate, never unlink: hiddify-panel holds this fd and an unlink
          # would free nothing until the unit restarts.
          if : > "$path" 2>/dev/null; then
            printf 'truncated %s (%s)\n' "$path" "$(_lc_human "$sz")"
            continue
          fi
          printf 'FAILED to truncate %s\n' "$path"
        fi
        total=$(( total + sz ))
        live_p+=("$path"); live_s+=("$sz")
        ;;
      archive)
        if [ "$sz" -gt "$cap_b" ]; then
          # A rotated copy over the cap is pure dead weight — nothing reads it
          # and truncating it would leave a file that still says it is 321 MB.
          if rm -f -- "$path" 2>/dev/null; then
            printf 'deleted %s (%s, rotated copy over the cap)\n' "$path" "$(_lc_human "$sz")"
            continue
          fi
          printf 'FAILED to delete %s\n' "$path"
        fi
        total=$(( total + sz ))
        arch_p+=("$path"); arch_s+=("$sz"); arch_t+=("${mtime%%.*}")
        ;;
      *)
        # Counted against the budget — it is real disk — but never acted on.
        total=$(( total + sz ))
        ;;
    esac
  done < <(_lc_scan)

  [ "$total" -le "$budget_b" ] && return 0

  # --- pass 2: directory budget ----------------------------------------------
  # Archives first, oldest first: they are copies, and the oldest copy is the
  # one whose loss costs the least.
  local i idx order
  if [ "${#arch_p[@]}" -gt 0 ]; then
    order="$(
      for i in "${!arch_p[@]}"; do printf '%s\t%s\n' "${arch_t[$i]:-0}" "$i"; done | sort -n
    )"
    while IFS=$'\t' read -r _ idx; do
      [ -n "$idx" ] || continue
      [ "$total" -le "$budget_b" ] && break
      if rm -f -- "${arch_p[$idx]}" 2>/dev/null; then
        total=$(( total - arch_s[idx] ))
        printf 'deleted %s (%s, tree over the %s MB budget)\n' \
               "${arch_p[$idx]}" "$(_lc_human "${arch_s[$idx]}")" "$dir_mb"
      fi
    done <<< "$order"
  fi

  [ "$total" -le "$budget_b" ] && return 0

  # Still over with every archive gone: the live logs themselves are the budget.
  # Biggest first, so the fewest files are disturbed.
  if [ "${#live_p[@]}" -gt 0 ]; then
    order="$(
      for i in "${!live_p[@]}"; do printf '%s\t%s\n' "${live_s[$i]}" "$i"; done | sort -rn
    )"
    while IFS=$'\t' read -r _ idx; do
      [ -n "$idx" ] || continue
      [ "$total" -le "$budget_b" ] && break
      if : > "${live_p[$idx]}" 2>/dev/null; then
        total=$(( total - live_s[idx] ))
        printf 'truncated %s (%s, tree over the %s MB budget)\n' \
               "${live_p[$idx]}" "$(_lc_human "${live_s[$idx]}")" "$dir_mb"
      fi
    done <<< "$order"
  fi

  if [ "$total" -gt "$budget_b" ]; then
    printf 'STILL over budget: %s MB of untouchable files (locks, sockets, unrecognised names)\n' \
           "$(_lc_mb "$total")"
  fi
  return 0
}

# Files over the cap that this module is ALLOWED to act on. mod_verify gates on
# this and not on a raw file count, or one unrecognised 200 MB file somebody left
# in the log directory would fail verification and auto-revert a working module.
_lc_over_cap_count() {
  local blocks mtime path base cls cap_b n=0
  cap_b=$(( $(_lc_file_mb) * 1048576 ))
  while IFS=$'\t' read -r -d '' blocks mtime path; do
    [ -n "$blocks" ] || continue
    cls="$(_lc_class "${path##*/}")"
    [ "$cls" = "other" ] && continue
    [ $(( blocks * 512 )) -gt "$cap_b" ] && n=$(( n + 1 ))
  done < <(_lc_scan)
  printf '%s\n' "$n"
}

_lc_biggest() {                          # -> "<MB> <path>" or empty
  local blocks mtime path best=0 bp=""
  while IFS=$'\t' read -r -d '' blocks mtime path; do
    [ -n "$blocks" ] || continue
    if [ $(( blocks * 512 )) -gt "$best" ]; then best=$(( blocks * 512 )); bp="$path"; fi
  done < <(_lc_scan)
  [ -n "$bp" ] || return 0
  printf '%s %s\n' "$(_lc_mb "$best")" "$bp"
}

# --------------------------------------------------------------- journald ----
_lc_journald_body() {                    # <mb>
  cat <<EOS
# managed by hiddify-toolkit (module: logcap) — DO NOT EDIT BY HAND
# systemd-journald ships with NO SystemMaxUse, which means "use 10% of the
# filesystem" (hard-capped at 4G). Measured uncapped on all seven panels at
# 1.0-2.4 GB each, on boxes whose whole disk is 38 GB.
#
# SystemKeepFree is deliberately NOT set: its default is 15% of the filesystem,
# and any value written here could only ever let journald use MORE than that.
# SystemMaxFileSize is left at its default too (1/8 of SystemMaxUse).
[Journal]
SystemMaxUse=${1}M
RuntimeMaxUse=64M
EOS
}

_lc_journald_is_ours() {
  [ -f "$LC_JOURNALD_FILE" ] || return 1
  grep -q 'managed by hiddify-toolkit (module: logcap)' "$LC_JOURNALD_FILE" 2>/dev/null
}

_lc_journald_is_current() {              # <mb>
  _lc_journald_is_ours || return 1
  grep -qx "SystemMaxUse=${1}M" "$LC_JOURNALD_FILE" 2>/dev/null
}

# Blocks, not apparent size, for the same reason as everywhere else here:
# journald preallocates its files. This is what `journalctl --disk-usage`
# reports, without depending on parsing an English sentence out of it.
_lc_journal_bytes() {
  local d n t=0
  for d in /var/log/journal /run/log/journal; do
    [ -d "$d" ] || continue
    n="$(du -sk "$d" 2>/dev/null | awk '{print $1; exit}')" || n=""
    case "$n" in (*[!0-9]*|'') n=0 ;; esac
    t=$(( t + n * 1024 ))
  done
  printf '%s\n' "$t"
}

_lc_journald_write() {                   # <mb> -> 0 written, 1 unchanged, 2 failed
  local mb="$1" body cur=""
  body="$(_lc_journald_body "$mb")"
  mkdir -p "$LC_JOURNALD_DIR" 2>/dev/null || return 2
  [ -f "$LC_JOURNALD_FILE" ] && { cur="$(cat "$LC_JOURNALD_FILE" 2>/dev/null)" || cur=""; }
  [ "$cur" = "$body" ] && return 1
  printf '%s\n' "$body" > "$LC_JOURNALD_FILE" || return 2
  chmod 0644 "$LC_JOURNALD_FILE" 2>/dev/null || true
  return 0
}

_lc_journald_reload() {
  systemctl restart systemd-journald >/dev/null 2>&1 || return 1
  return 0
}

# --------------------------------------------------------------- log notes ----
# The guard is silent by design, so findings go to toolkit.log — but only when
# they CHANGE, or a permanent condition writes 720 identical lines a day.
_lc_note() {
  local msg="$1" nf prev
  nf="$(ht_state_dir)/${MOD_ID}.note"
  prev="$(cat "$nf" 2>/dev/null)" || prev=""
  [ "$prev" = "$msg" ] && return 0
  mkdir -p "$(ht_state_dir)" 2>/dev/null || true
  printf '%s\n' "$msg" > "$nf" 2>/dev/null || true
  ht_log "[$MOD_ID] $msg"
  return 0
}

_lc_note_clear() { rm -f "$(ht_state_dir)/${MOD_ID}.note" 2>/dev/null; return 0; }

# ====================================================================== API ===
mod_status() {
  local file_mb dir_mb jmb total over big jb jstate orph orph_b orph_over

  file_mb="$(_lc_file_mb)"; dir_mb="$(_lc_dir_mb)"; jmb="$(_lc_journal_mb)"

  printf '%-15s: %s MB per file, %s MB for the whole tree\n' "limits" "$file_mb" "$dir_mb"

  if [ ! -d "$LC_LOGROOT" ]; then
    printf '%-15s: %s does not exist\n' "log tree" "$LC_LOGROOT"
    total=0; over=0
  else
    total="$(_lc_total_bytes)"
    over="$(_lc_over_cap_count)"
    printf '%-15s: %s  —  %s MB on disk\n' "log tree" "$LC_LOGROOT" "$(_lc_mb "$total")"
    big="$(_lc_biggest)"
    [ -n "$big" ] && printf '%-15s: %s MB  %s\n' "biggest" "${big%% *}" "${big#* }"
    [ "$over" != "0" ] && printf '%-15s: %s file(s) over the %s MB cap right now\n' \
                                  "over cap" "$over" "$file_mb"
  fi

  # One /proc walk, reused. mod_status is re-rendered on every menu redraw.
  orph="$(_lc_orphans)"
  orph_b=0; orph_over=0
  if [ -n "$orph" ]; then
    orph_b="$(printf '%s\n' "$orph" | awk -F'\t' '{t+=$1} END{print t+0}')"
    orph_over="$(printf '%s\n' "$orph" | awk -F'\t' -v c=$(( file_mb * 1048576 )) '$1>c{n++} END{print n+0}')"
    if [ "$orph_b" -gt 1048576 ]; then
      printf '%-15s: %s MB deleted but still held open — invisible to du/ls/find\n' \
             "orphaned" "$(_lc_mb "$orph_b")"
      printf '%s\n' "$orph" | awk -F'\t' '$1>1048576{printf "%-15s: %s MB  %s\n","",int($1/1048576),$3}'
    fi
  fi

  if [ "$file_mb" -gt "$LC_TUNING_FIXED_MB" ] && ht_is_enabled tuning; then
    printf '%-15s: the tuning module truncates %s/system/*.log at a fixed %s MB and runs\n' \
           "note" "$LC_LOGROOT" "$LC_TUNING_FIXED_MB"
    printf '%-15s  first, so %s MB is the real ceiling in that one directory\n' \
           "" "$LC_TUNING_FIXED_MB"
  fi

  if [ "$jmb" = "0" ]; then
    printf '%-15s: not managed here (journal_mb=0)\n' "journald"
  else
    jb="$(_lc_journal_bytes)"
    if _lc_journald_is_current "$jmb"; then jstate="capped at ${jmb}M"
    elif _lc_journald_is_ours;    then jstate="ours, but set to a different cap"
    elif [ -f "$LC_JOURNALD_FILE" ]; then jstate="$LC_JOURNALD_FILE exists and is NOT ours"
    else jstate="UNCAPPED (systemd default: 10% of the filesystem)"
    fi
    printf '%-15s: %s  —  %s MB on disk now\n' "journald" "$jstate" "$(_lc_mb "$jb")"
  fi

  # Informational only, and deliberately not something this module manages:
  # /var/log/syslog is rotated by rsyslog's own logrotate (weekly, rotate 4), so
  # it is bounded — just not always small. Worth seeing next to the numbers above.
  if [ -f /var/log/syslog ]; then
    printf '%-15s: %s MB (rsyslog, weekly rotate 4 — not managed by this module)\n' \
      "/var/log/syslog" "$(_lc_mb "$(( $( { stat -c %b /var/log/syslog 2>/dev/null || echo 0; } ) * 512 ))")"
  fi

  # --- the token -------------------------------------------------------------
  # Everything below is judged on OBSERVABLE box state, never on stored config:
  # ht_adopt_applied decides whether to adopt a box by reading this token, and a
  # token that needs the module's own bookkeeping could never report a box that
  # the toolkit has not touched yet.
  if [ "$jmb" != "0" ] && ! _lc_journald_is_ours; then
    printf 'ABSENT   nothing is bounding these logs\n'
    return 0
  fi
  if [ "$jmb" != "0" ] && ! _lc_journald_is_current "$jmb"; then
    printf 'PARTIAL  journald cap file is ours but does not carry SystemMaxUse=%sM\n' "$jmb"
    return 0
  fi
  if [ "$jmb" = "0" ] && ! ht_is_enabled "$MOD_ID"; then
    printf 'ABSENT   journald is not managed here and the sweep is not enabled\n'
    return 0
  fi
  if [ "$over" != "0" ]; then
    printf 'PARTIAL  %s file(s) over the cap — the guard has not swept them yet\n' "$over"
    return 0
  fi
  if [ "$orph_over" != "0" ]; then
    printf 'PARTIAL  %s deleted-but-open file(s) over the cap — someone rm'\''d a live log\n' "$orph_over"
    return 0
  fi
  if [ "$total" -gt $(( dir_mb * 1048576 )) ]; then
    printf 'PARTIAL  tree is %s MB, over the %s MB budget\n' "$(_lc_mb "$total")" "$dir_mb"
    return 0
  fi
  printf 'APPLIED  every log file capped at %s MB, tree budget %s MB, re-checked every 2 min\n' \
         "$file_mb" "$dir_mb"
  return 0
}

mod_apply() {
  local file_mb dir_mb jmb ans out rc

  ht_is_hiddify || { err "hiddify-manager is not installed here"; return 1; }

  file_mb="$(_lc_file_mb)"; dir_mb="$(_lc_dir_mb)"; jmb="$(_lc_journal_mb)"

  # No TTY means the guard, a fleet loop, or `hiddify-toolkit apply logcap` from a
  # script. Take the stored/default limits and never block on a prompt nobody can
  # answer.
  if [ -t 0 ]; then
    printf '\n  Ceilings to hold. Empty = keep the value shown.\n\n'
    read -rp "  max size of ONE log file, MB [$file_mb] > " ans
    ans="${ans//[[:space:]]/}"
    case "$ans" in ('') ;; (*[!0-9]*) err "not a number: $ans"; return 1 ;; (*) ht_conf_set file_mb "$ans" ;; esac

    file_mb="$(_lc_file_mb)"; dir_mb="$(_lc_dir_mb)"
    read -rp "  max size of the WHOLE $LC_LOGROOT tree, MB [$dir_mb] > " ans
    ans="${ans//[[:space:]]/}"
    case "$ans" in ('') ;; (*[!0-9]*) err "not a number: $ans"; return 1 ;; (*) ht_conf_set dir_mb "$ans" ;; esac

    read -rp "  max size of the systemd journal, MB (0 = leave journald alone) [$jmb] > " ans
    ans="${ans//[[:space:]]/}"
    case "$ans" in ('') ;; (*[!0-9]*) err "not a number: $ans"; return 1 ;; (*) ht_conf_set journal_mb "$ans" ;; esac
    printf '\n'
  fi

  file_mb="$(_lc_file_mb)"; dir_mb="$(_lc_dir_mb)"; jmb="$(_lc_journal_mb)"
  ok "holding $LC_LOGROOT at $file_mb MB per file / $dir_mb MB total"

  # --- 1. the log tree, right now --------------------------------------------
  say "=== 1. sweeping $LC_LOGROOT ==="
  [ -d "$LC_LOGROOT" ] || warn "$LC_LOGROOT does not exist — only deleted-but-open logs to check"
  out="$(_lc_sweep)"
  if [ -n "$out" ]; then
    printf '%s\n' "$out" | sed 's/^/    /'
    ht_log "[$MOD_ID] apply sweep: $(printf '%s' "$out" | tr '\n' ';')"
  else
    ok "already within limits ($(_lc_mb "$(_lc_total_bytes)") MB on disk, $(_lc_mb "$(_lc_orphan_bytes)") MB orphaned)"
  fi

  # --- 2. journald ------------------------------------------------------------
  say "=== 2. systemd-journald ==="
  if [ "$jmb" = "0" ]; then
    warn "journal_mb=0 — leaving journald alone"
  else
    if [ -f "$LC_JOURNALD_FILE" ] && ! _lc_journald_is_ours; then
      err "$LC_JOURNALD_FILE exists and was not written by this module — refusing to overwrite it"
      err "move it aside, or set journal_mb=0 in $(ht_state_dir)/conf/${MOD_ID}.conf"
      return 1
    fi
    ht_backup "$LC_JOURNALD_FILE"
    _lc_journald_write "$jmb"; rc=$?
    [ "$rc" = "2" ] && { err "cannot write $LC_JOURNALD_FILE"; return 1; }
    if [ "$rc" = "0" ]; then
      _lc_journald_reload || warn "systemd-journald did not restart cleanly"
      ok "$LC_JOURNALD_FILE — SystemMaxUse=${jmb}M"
    else
      ok "$LC_JOURNALD_FILE already current"
    fi
    # Reclaim now rather than waiting for journald to notice at its next rotation.
    # --vacuum-size only ever removes ARCHIVED journals; the active file is never
    # at risk, which is why this is safe to run on a live box.
    if command -v journalctl >/dev/null 2>&1; then
      journalctl --vacuum-size="${jmb}M" >/dev/null 2>&1 || true
      ok "journal now $(_lc_mb "$(_lc_journal_bytes)") MB"
    fi
  fi

  _lc_note_clear
  ht_conf_set applied_at "$(date -Is)"
  return 0
}

mod_verify() {
  local jmb over total dir_mb

  jmb="$(_lc_journal_mb)"
  if [ "$jmb" != "0" ]; then
    _lc_journald_is_current "$jmb" || { err "$LC_JOURNALD_FILE does not carry SystemMaxUse=${jmb}M"; return 1; }
    [ "$(systemctl is-active systemd-journald 2>/dev/null)" = "active" ] \
      || { err "systemd-journald is not active after the config change"; return 1; }
  fi

  over="$(_lc_orphan_over_cap)"
  [ "$over" = "0" ] || { err "$over deleted-but-open file(s) still over the $(_lc_file_mb) MB cap"; return 1; }

  if [ -d "$LC_LOGROOT" ]; then
    over="$(_lc_over_cap_count)"
    [ "$over" = "0" ] || { err "$over manageable file(s) still over the $(_lc_file_mb) MB cap"; return 1; }
    # Only the files this module may act on are gated. An unrecognised 200 MB
    # file somebody left in the log directory is reported by mod_status and must
    # NOT auto-revert a module that is doing exactly what it promised.
    total="$(_lc_total_bytes)"; dir_mb="$(_lc_dir_mb)"
    if [ "$total" -gt $(( dir_mb * 1048576 )) ]; then
      warn "tree is $(_lc_mb "$total") MB, over the $dir_mb MB budget, and the sweep could not"
      warn "reduce it further — the remainder is files this module never touches"
    fi
  fi

  ok "cap $(_lc_file_mb) MB/file, budget $(_lc_dir_mb) MB$([ "$jmb" != "0" ] && printf ', journal %s MB' "$jmb")"
  return 0
}

mod_revert() {
  local jmb had=0

  jmb="$(_lc_journal_mb)"
  if _lc_journald_is_ours; then
    rm -f "$LC_JOURNALD_FILE" && had=1
    _lc_journald_reload || warn "systemd-journald did not restart cleanly"
    ok "removed $LC_JOURNALD_FILE — journald is back to the systemd default (10% of the filesystem)"
  elif [ -f "$LC_JOURNALD_FILE" ]; then
    warn "$LC_JOURNALD_FILE is not ours — left in place"
  fi
  [ "$had" = "1" ] || ok "no journald cap of ours to remove"

  # Nothing to put back for the log tree: a truncate frees blocks and a deleted
  # rotated copy is gone. Say so plainly rather than implying a rollback.
  ok "log-tree sweep stops at the next guard tick; already-reclaimed space is not restorable"
  ht_conf_set applied_at ""
  _lc_note_clear
  return 0
}

mod_reassert() {
  local jmb out jb rc=0

  ht_is_hiddify || return 0

  # THE HOT PATH. stat over one small directory via a single find — no service
  # action, no fork storm — which is exactly why this is affordable every 2
  # minutes and a daily logrotate is not.
  # Unconditional: _lc_sweep checks for the directory itself, and the deleted-but-open
  # case has no directory to check — on s4 the whole visible tree was 16 KB while
  # 8.2 GB sat behind one fd.
  out="$(_lc_sweep 2>/dev/null)"
  if [ -n "$out" ]; then
    # Not deduped: every line here is a real reclaim that just happened, and two
    # identical lines an hour apart are two different events.
    ht_log "[$MOD_ID] $(printf '%s' "$out" | tr '\n' ';')"
  fi

  jmb="$(_lc_journal_mb)"
  [ "$jmb" = "0" ] && { _lc_note_clear; return 0; }

  # Hiddify's install.sh does not touch journald.conf.d, so this file normally
  # survives — but a systemd package upgrade or a hand-edit can take it, and then
  # nothing is capping the journal while status still says the module is on.
  if [ -f "$LC_JOURNALD_FILE" ] && ! _lc_journald_is_ours; then
    _lc_note "$LC_JOURNALD_FILE was replaced by something else — not overwriting it"
    return 0
  fi
  if ! _lc_journald_is_current "$jmb"; then
    _lc_journald_write "$jmb"
    case "$?" in
      0) _lc_journald_reload || rc=1
         ht_log "[$MOD_ID] journald cap was missing or stale — re-wrote SystemMaxUse=${jmb}M" ;;
      2) _lc_note "cannot write $LC_JOURNALD_FILE"; return 1 ;;
    esac
  fi

  # journald cannot vacuum its ACTIVE journal file, so it legitimately sits a
  # little over the cap; only act outside that slack, or this runs every tick and
  # never achieves anything.
  jb="$(_lc_journal_bytes)"
  if [ "$(_lc_mb "$jb")" -gt $(( jmb + LC_JOURNAL_SLACK_MB )) ] && command -v journalctl >/dev/null 2>&1; then
    journalctl --vacuum-size="${jmb}M" >/dev/null 2>&1 || true
    ht_log "[$MOD_ID] journal was $(_lc_mb "$jb") MB — vacuumed to ${jmb}M"
  fi

  _lc_note_clear
  return "$rc"
}

# Adoption runs on a box that already reports APPLIED without the toolkit having
# applied it — here, one where a previous install wrote the journald cap and the
# state directory was lost. mod_apply is deliberately not re-run; this records
# what it would have recorded, and changes nothing on the box.
mod_adopt() {
  local mb
  if _lc_journald_is_ours; then
    mb="$(grep -m1 '^SystemMaxUse=' "$LC_JOURNALD_FILE" 2>/dev/null | sed 's/^SystemMaxUse=//; s/M$//')"
    case "$mb" in (*[!0-9]*|'') ;; (*) ht_conf_set journal_mb "$mb" ;; esac
    ht_backup "$LC_JOURNALD_FILE"
  fi
  [ -n "$(ht_conf_get applied_at '')" ] || ht_conf_set applied_at "adopted $(date -Is)"
  return 0
}
