# shellcheck shell=bash
# =============================================================================
# hiddify-toolkit module: ipv6 — disable the IPv6 stack, and keep it disabled
# =============================================================================
# These panels have link-local fe80:: only and no default v6 route, so every AAAA
# destination a TUN-mode client pushes in black-holes, and aggressively dual-stack
# services (Google/Gemini) fail. Turning IPv6 off is the fix.
#
# WHY THIS NEEDS A GUARD AT ALL — the trap that ate the previous three attempts:
# /opt/hiddify-manager/common/install.sh runs `sysctl --system` and THEN, further
# down, imperatively runs `sysctl -w net.ipv6.conf.*.disable_ipv6=0`. It does that
# on every apply-config, every update and @reboot. So a file in /etc/sysctl.d/ is
# always undone seconds later, no matter what it is called. Hiddify's own
# "no IPv6 -> turn it off" fallback would have saved us, but it is dead code:
# line 46 assigns ONLY_IPV4=true1 while line 52 tests == true.
#
# The file below is therefore only half the job (it wins the boot-time file pass,
# via the zz- last-wins prefix). The half that actually holds is mod_reassert(),
# re-forcing the live /proc values on the core's 2-minute guard timer.
#
# READ /proc, NEVER THE .conf FILE. On 2026-08-18 all seven boxes were running
# with disable_ipv6=0 while a correct-looking .conf sat on disk. The file is not
# evidence of anything.
#
# THE BLAST RADIUS NOBODY EXPECTS — loopback goes down with everything else:
# writing 1 to all/disable_ipv6 makes the kernel walk for_each_netdev() and flush
# every IPv6 address on every device. `lo` is in that list, so ::1 goes too, and
# there is no way to opt lo out while still writing `all`. A [::] WILDCARD bind
# survives (in6addr_any needs no address anywhere) — that is why xray/haproxy/nginx
# are untouched. A LITERAL bind does not: bind([::1]) returns EADDRNOTAVAIL on the
# service's next restart, and Hiddify restarts its services on every apply-config,
# which is the exact event this module is built around. Our own tuning notes record
# shadowsocks-libev dying on `bind ::1` for precisely this reason. So the module
# detects literal v6 binds and refuses rather than discovering it in production
# (_ipv6_literal_binds below). The alternative fix — stop writing `all` at all,
# write `default` plus each non-lo device by name, and relax mod_verify to `default`
# — would keep lo alive and is still on the table; it was not taken because naming
# devices in a sysctl file loses every interface born later (docker0, wg0, tun*),
# which is the failure the /proc sweep exists to cover.
# =============================================================================

# shellcheck disable=SC2034  # consumed by the core via ht_module_meta
MOD_ID="ipv6"
# shellcheck disable=SC2034
MOD_TITLE="Disable IPv6 (permanently)"
# shellcheck disable=SC2034
MOD_TITLE_FA="غیرفعال‌سازی دائمی IPv6"
# shellcheck disable=SC2034
MOD_DESC="Turns IPv6 off on every interface and holds it off against Hiddify's apply-config, which re-enables it on every run."
# shellcheck disable=SC2034
MOD_GUARD=yes

IPV6_SYSCTL_FILE=/etc/sysctl.d/zz-disable-ipv6.conf
IPV6_LEGACY_FILE=/etc/sysctl.d/99-disable-ipv6.conf
IPV6_LEGACY_UNIT=hiddify-noipv6
IPV6_PROC_DIR=/proc/sys/net/ipv6/conf

# --------------------------------------------------------------- primitives ---

_ipv6_stack_present() { [ -d "$IPV6_PROC_DIR" ]; }

_ipv6_read() {                              # <all|default|eth0|...> -> value or "x"
  local v
  v="$(cat "$IPV6_PROC_DIR/$1/disable_ipv6" 2>/dev/null)"
  printf '%s\n' "${v:-x}"
}

# Sets three globals rather than echoing a packed string, so callers can use the
# interface list without re-parsing it.
_IPV6_TOTAL=0
_IPV6_OFF=0
_IPV6_ON_LIST=""
_ipv6_survey() {
  local f name v
  _IPV6_TOTAL=0; _IPV6_OFF=0; _IPV6_ON_LIST=""
  _ipv6_stack_present || return 0
  for f in "$IPV6_PROC_DIR"/*/disable_ipv6; do
    [ -e "$f" ] || continue
    name="${f#"$IPV6_PROC_DIR"/}"; name="${name%/disable_ipv6}"
    v="$(cat "$f" 2>/dev/null)"
    _IPV6_TOTAL=$((_IPV6_TOTAL + 1))
    if [ "$v" = "1" ]; then
      _IPV6_OFF=$((_IPV6_OFF + 1))
    else
      _IPV6_ON_LIST="$_IPV6_ON_LIST $name"
    fi
  done
  return 0
}

# Results land in _IPV6_CHANGED / _IPV6_STUCK, the same idiom as _ipv6_survey — and
# here it is load-bearing, not style. The old form was `changed="$(_ipv6_force_off)"`:
# a command substitution runs the function in a SUBSHELL, so any global it sets dies
# with that subshell. A counter written inside would have read 0 in every caller,
# forever, and looked like it worked.
# Returns 1 only when the ipv6 kernel module is not loaded at all (nothing to disable
# — a better end state than the one we were going for, not a failure).
_IPV6_CHANGED=0
_IPV6_STUCK=0
_ipv6_force_off() {
  local f v
  _IPV6_CHANGED=0; _IPV6_STUCK=0
  _ipv6_stack_present || return 1
  # `all` sorts first in this glob and does the bulk of the work: the kernel
  # propagates a write to all/disable_ipv6 onto every device that exists right now,
  # so the per-interface writes after it are normally no-ops. Keep sweeping them
  # anyway — an interface born after the last write (docker0, wg0, a tun device)
  # inherits `default`, never `all`, and a single interface left at 0 is a live
  # IPv6 path however tidy the other ten look.
  for f in "$IPV6_PROC_DIR"/*/disable_ipv6; do
    [ -e "$f" ] || continue
    v="$(cat "$f" 2>/dev/null)"
    [ "$v" = "1" ] && continue
    # COUNT the knobs we could not write instead of skipping them silently. Apply
    # used to print "0 knob(s) changed" for a read-only /proc, which is byte-identical
    # to "already correct"; mod_verify caught it at apply time but mod_reassert never
    # runs verify, so a knob that stopped being writable later was a live IPv6 path
    # that nothing on the 2-minute timer would ever mention again.
    if [ ! -w "$f" ] || ! printf '1\n' > "$f" 2>/dev/null; then
      _IPV6_STUCK=$((_IPV6_STUCK + 1)); continue
    fi
    _IPV6_CHANGED=$((_IPV6_CHANGED + 1))
  done
  return 0
}

_ipv6_force_value() {                       # <0|1> — used by revert
  local want="$1" f
  _ipv6_stack_present || return 0
  for f in "$IPV6_PROC_DIR"/*/disable_ipv6; do
    [ -w "$f" ] || continue
    [ "$(cat "$f" 2>/dev/null)" = "$want" ] && continue
    printf '%s\n' "$want" > "$f" 2>/dev/null || true
  done
  return 0
}

_ipv6_file_ok() {
  [ -f "$IPV6_SYSCTL_FILE" ] || return 1
  grep -qE '^net\.ipv6\.conf\.all\.disable_ipv6[[:space:]]*=[[:space:]]*1'     "$IPV6_SYSCTL_FILE" || return 1
  grep -qE '^net\.ipv6\.conf\.default\.disable_ipv6[[:space:]]*=[[:space:]]*1' "$IPV6_SYSCTL_FILE" || return 1
  return 0
}

# Our file's own content is not proof that our file WINS. `sysctl --system` sorts by
# BASENAME across every sysctl.d directory and then applies /etc/sysctl.conf dead last,
# so `zz-` only guarantees we beat Hiddify's hiddify.conf and wg.conf — it loses to
# zz-hiddify-tuning.conf (our own sibling module), to anything zzz-*, and always to
# /etc/sysctl.conf. The guard timer re-forces /proc within 2 minutes so a lost file pass
# is a window rather than a defeat, but nothing used to SHOW the window existed.
_ipv6_conflict_files() {
  local f base ours later
  ours="${IPV6_SYSCTL_FILE##*/}"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    [ "$f" = "$IPV6_SYSCTL_FILE" ] && continue
    base="${f##*/}"
    later="$(printf '%s\n%s\n' "$base" "$ours" | LC_ALL=C sort | tail -1)"
    if [ "$f" = /etc/sysctl.conf ] || { [ "$later" = "$base" ] && [ "$base" != "$ours" ]; }; then
      printf '%s(applied-after-us)\n' "$f"
    else
      printf '%s\n' "$f"
    fi
  # -R, not -r: `sysctl --system` reads every *.conf in the directory INCLUDING
  # symlinks, and Hiddify's own /etc/sysctl.d/hiddify.conf is a symlink into
  # /opt/hiddify-manager. GNU grep -r follows a symlink only when it is named on the
  # command line, so -r reports the single most likely conflict on this platform as
  # absent.
  done < <(grep -RlE '^[[:space:]]*net\.ipv6\.conf\.(all|default)\.disable_ipv6[[:space:]]*=[[:space:]]*0' \
             /etc/sysctl.d /etc/sysctl.conf 2>/dev/null | sort -u)
  return 0
}

_ipv6_write_file() {
  # Quoted heredoc. The standalone script this module replaces used an unquoted one;
  # its body happened to contain no `$`, so it was inert — right up until someone
  # added a line with one and it expanded on the writing host instead of landing in
  # the file. `.lo` is deliberately absent: the file can only ever name all/default,
  # and the /proc sweep covers lo and everything else properly.
  cat > "$IPV6_SYSCTL_FILE" <<'SYSCTL_EOF'
# Managed by hiddify-toolkit (module: ipv6). Do not rename — the zz- prefix is what
# makes `sysctl --system` apply this AFTER Hiddify's own hiddify.conf and wg.conf.
# It is NOT a global last word: sysctl sorts by basename and applies /etc/sysctl.conf
# last, so `zz-hiddify-tuning.conf`, `zzz-*` and /etc/sysctl.conf all still outrank us.
# `hiddify-toolkit status` reports any such file on the "conflicts" line.
#
# This file alone cannot hold the setting: Hiddify's install.sh runs
# `sysctl -w net.ipv6.conf.*.disable_ipv6=0` after the file pass, on every
# apply-config / update / reboot. The toolkit guard timer re-forces the live
# values every 2 minutes; that is the part that actually wins.
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
SYSCTL_EOF
  local rc=$?
  [ "$rc" -eq 0 ] || return 1
  chmod 0644 "$IPV6_SYSCTL_FILE" 2>/dev/null || true
  return 0
}

# ---------------------------------------------------------------- listeners ---

# Listening sockets bound to a LITERAL IPv6 address (not the [::] wildcard).
# disable_ipv6 deletes those addresses — ::1 on lo included — so these binds fail with
# EADDRNOTAVAIL the next time their service restarts, and Hiddify restarts its services
# on every apply-config. Nothing else in this module would notice: mod_verify checks
# sysctls and SSH, so a service killed this way still verifies green, and mod_revert
# re-enables IPv6 without restarting anything, so it stays dead through a revert too.
#
# Do NOT index ss output by column number here. ss prints a leading Netid column only
# when the output mixes protocols, so `ss -ltnu` shifts State to $2 and the address to
# $5 while `ss -ltn` keeps them at $1/$4 — an awk pinned to $4 then matches nothing and
# reports a clean box, which is the worst possible answer from a safety detector. Pick
# the field that LOOKS like [addr]:port instead; that survives any column layout. One
# call per family on top of that, so the layout never mixes in the first place.
# ::ffff:a.b.c.d is excluded deliberately: that is an AF_INET6 socket bound to an IPv4
# address, it needs no IPv6 address on any device and survives the change untouched.
_ipv6_literal_binds() {
  # In `ss -6` output the ONLY column ending in :<digits> is the local address (the
  # peer column is always :*), so match that and nothing else. Do NOT require a
  # closing "]" immediately before the port: iproute2 renders a scoped address as
  # [fe80::5054:ff:fe12:3456]%eth0:546 — the %iface sits OUTSIDE the bracket, and a
  # /^\[.*\]:[0-9]+$/ pattern silently drops every link-local listener there is.
  { ss -ltn -6 2>/dev/null; ss -lun -6 2>/dev/null; } \
    | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /:[0-9]+$/) { print $i; break } }' \
    | grep -vE '^(\[::\]|\*)(%[^:]*)?:[0-9]+$' \
    | grep -vE '^\[?::ffff:' \
    | sort -u || true
}

# --------------------------------------------------------------- ssh safety ---

_ipv6_ssh_ports() {
  local out="" sshd_bin="" prop
  if command -v sshd >/dev/null 2>&1; then
    sshd_bin="sshd"
  elif [ -x /usr/sbin/sshd ]; then
    sshd_bin="/usr/sbin/sshd"
  fi
  if [ -n "$sshd_bin" ]; then
    out="$("$sshd_bin" -T 2>/dev/null | awk '$1=="port"{print $2}')"
  fi
  if [ -z "$out" ]; then
    out="$(awk 'tolower($1)=="port" && $2 ~ /^[0-9]+$/{print $2}' \
           /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null)"
  fi
  # Ubuntu 24.04 enables ssh.socket by default. Under socket activation the real
  # listening port comes from the unit, and `sshd -T` still cheerfully reports
  # whatever sshd_config says — so a box moved to a custom port via the socket unit
  # would get its safety check run against a port nothing listens on, which passes
  # for exactly the wrong reason.
  #
  # Anchor the port on the END of the token, never on the colon alone. A socket unit's
  # Listen value can be an IPv6 literal, and `[2a01:4f8:c17:1::1]:22 (Stream)` scanned
  # for `:[0-9]{1,5}` yields the ports "4" (from :4f8) and "1" (from ::1) alongside the
  # real 22 — invented ports that pollute every operator-facing message and can flip the
  # "no listener anywhere" branch on a box whose real port genuinely has none.
  prop="$(systemctl show ssh.socket sshd.socket -p Listen -p ListenStream --value 2>/dev/null)"
  if [ -n "$prop" ]; then
    out="$out
$(printf '%s\n' "$prop" | grep -oE '(^|:)[0-9]{1,5}([[:space:]]|$)' | tr -cd '0-9\n')"
  fi
  out="$(printf '%s\n' "$out" | tr ' ' '\n' | grep -E '^[0-9]{1,5}$' | sort -un)"
  [ -n "$out" ] || out="22"
  printf '%s\n' "$out"
}

# Positive proof that an AF_INET path into this listener exists, whatever the socket's
# IPV6_V6ONLY option happens to be — the sysctl we would otherwise reason from is the
# global DEFAULT, and V6ONLY is per-socket, so the inference is wrong in both directions.
# 127.0.0.1 is a LITERAL on purpose: "localhost" goes through getaddrinfo and can pick
# ::1, the classic false negative on a box whose IPv6 is being taken down.
# Pass-only signal, never a refusal: a listener bound to one specific EXTERNAL IPv4
# address legitimately refuses 127.0.0.1, and that is not a lockout.
_ipv6_v4_accepts() {                        # <port>
  timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/"$1"' _ "$1" 2>/dev/null
}

# Prints a human detail on stdout. Returns 0 if an IPv4 way into this box survives
# the change, 1 if disabling IPv6 would lock us out.
_ipv6_ssh_guard() {
  local ports plist listen4 listen6 listen6w p n4=0 n6=0 n6w=0 bv6

  ports="$(_ipv6_ssh_ports)"
  plist="$(printf '%s' "$ports" | tr '\n' ',' | sed 's/,$//')"

  # Filter by socket FAMILY, not by how the address is spelled: `ss -4` lists real
  # AF_INET sockets only. Selecting on the text "0.0.0.0:22" (what the old script
  # did) misses a box whose sshd binds one specific IPv4 address.
  listen4="$(ss -ltn -4 2>/dev/null | awk '$1=="LISTEN"{print $4}')"
  listen6="$(ss -ltn -6 2>/dev/null | awk '$1=="LISTEN"{print $4}')"

  # Only a WILDCARD v6 bind can still serve IPv4 once IPv6 is down. A listener on a
  # literal v6 address loses that address to disable_ipv6 and dies with it, so it is not
  # evidence of a way in — it is the next outage. The old code counted both alike: a bare
  # `grep ":22$"` against the raw ss column matches "[2a01:4f8:c17:1::1]:22" and
  # "[fe80::5054:ff:fe12:3456%eth0]:22" exactly as happily as "[::]:22". Those boxes
  # passed the apply gate, passed mod_verify again afterwards (so no auto-rollback), and
  # the guard timer then re-forced the setting every 2 minutes with nobody able to log in.
  listen6w="$(printf '%s\n' "$listen6" | grep -E '^(\[::\]|\*):[0-9]+$')" || true

  while IFS= read -r p; do
    [ -n "$p" ] || continue
    if printf '%s\n' "$listen4"  | grep -qE ":${p}\$"; then n4=$((n4 + 1)); fi
    if printf '%s\n' "$listen6"  | grep -qE ":${p}\$"; then n6=$((n6 + 1)); fi
    if printf '%s\n' "$listen6w" | grep -qE ":${p}\$"; then n6w=$((n6w + 1)); fi
  done <<< "$ports"

  # Only probe when there is no AF_INET listener to point at. On the ordinary box
  # (0.0.0.0:22 present) this costs nothing and keeps sshd's auth log free of the
  # connect-and-hang-up lines a probe leaves behind — mod_status calls this guard on
  # every menu render.
  if [ "$n4" -eq 0 ]; then
    while IFS= read -r p; do
      [ -n "$p" ] || continue
      if _ipv6_v4_accepts "$p"; then n4=$((n4 + 1)); fi
    done <<< "$ports"
  fi

  bv6="$(sysctl -n net.ipv6.bindv6only 2>/dev/null)"
  [ -n "$bv6" ] || bv6=1                    # unreadable -> assume the strict case

  if [ "$n4" -gt 0 ]; then
    printf 'IPv4 path into port(s) %s confirmed\n' "$plist"
    return 0
  fi

  # Last-resort INFERENCE, and known to be weak in both directions: bindv6only is a
  # global default while IPV6_V6ONLY is per-socket. OpenSSH's own server_listen() calls
  # sock_set_v6only() on its AF_INET6 listener, so a standalone sshd's [::]:22 is never
  # v4-mapped — that case is normally saved by its sibling 0.0.0.0:22 landing in n4 above.
  # The branch stays because systemd's ssh.socket (Ubuntu 24.04 default) binds exactly one
  # dual-stack [::]:22 that DOES accept IPv4, and refusing every socket-activated box
  # would be its own outage. The /dev/tcp probe above is the real evidence; this is what
  # is left when the probe could not answer.
  if [ "$n6w" -gt 0 ] && [ "$bv6" = "0" ]; then
    printf 'wildcard dual-stack listener on port(s) %s with net.ipv6.bindv6only=0 — inferred to accept IPv4 as v4-mapped (the 127.0.0.1 probe did not answer)\n' "$plist"
    return 0
  fi

  if [ "$n6" -eq 0 ]; then
    if [ -n "${SSH_CONNECTION:-}" ]; then
      printf 'no listener found on port(s) %s while you are ON an SSH session — the port detection is wrong, not the box\n' "$plist"
      return 1
    fi
    printf 'no SSH listener on port(s) %s and this is not an SSH session — nothing to lose\n' "$plist"
    return 0
  fi

  if [ "$n6w" -eq 0 ]; then
    printf 'SSH listens ONLY on literal IPv6 address(es) on port(s) %s — disable_ipv6 deletes those addresses and takes the listener with them\n' "$plist"
    return 1
  fi

  printf 'SSH listens on IPv6 only (port(s) %s) and net.ipv6.bindv6only=%s — disabling IPv6 would cut every way in\n' "$plist" "$bv6"
  return 1
}

_ipv6_session_is_v6() {
  # SSH_CONNECTION = "<client ip> <client port> <server ip> <server port>"
  local c="${SSH_CONNECTION:-}"
  [ -n "$c" ] || return 1
  case "${c%% *}" in
    *:*) return 0 ;;
  esac
  return 1
}

# ------------------------------------------------------------------- status ---

mod_status() {
  local v_all v_def gv ssh_msg ssh_state file_state token f name v line lit rival

  if _ipv6_file_ok; then file_state="present"
  elif [ -f "$IPV6_SYSCTL_FILE" ]; then file_state="malformed"
  else file_state="absent"; fi
  printf '  sysctl file  : %s (%s)\n' "$file_state" "$IPV6_SYSCTL_FILE"

  if _ipv6_stack_present; then
    v_all="$(_ipv6_read all)"; v_def="$(_ipv6_read default)"
    printf '  live values  : all=%s  default=%s   (1 = IPv6 off)\n' "$v_all" "$v_def"
    _ipv6_survey
    line=""
    for f in "$IPV6_PROC_DIR"/*/disable_ipv6; do
      [ -e "$f" ] || continue
      name="${f#"$IPV6_PROC_DIR"/}"; name="${name%/disable_ipv6}"
      case "$name" in all|default) continue ;; esac
      v="$(cat "$f" 2>/dev/null)"
      line="$line ${name}=${v:-x}"
    done
    printf '  interfaces   :%s\n' "${line:- (none)}"
  else
    v_all="x"; v_def="x"
    _IPV6_TOTAL=0; _IPV6_OFF=0; _IPV6_ON_LIST=""
    printf '  live values  : ipv6 kernel module not loaded — stack absent entirely\n'
  fi

  gv="$(ip -6 addr show scope global 2>/dev/null | grep -c inet6)"
  printf '  global v6 IPs: %s\n' "$gv"

  # The two things that used to be invisible until they bit: services that will fail to
  # re-bind once their literal v6 address is gone, and another sysctl file that outranks
  # ours in the boot-time file pass.
  lit="$(_ipv6_literal_binds | tr '\n' ' ')"
  printf '  v6-literal   : %s\n' "${lit:-none}"
  rival="$(_ipv6_conflict_files | tr '\n' ' ')"
  printf '  conflicts    : %s\n' "${rival:-none}"

  local legacy_bits=""
  [ -f "$IPV6_LEGACY_FILE" ] && legacy_bits="$legacy_bits $IPV6_LEGACY_FILE"
  [ -f "/etc/systemd/system/${IPV6_LEGACY_UNIT}.timer" ] && legacy_bits="$legacy_bits ${IPV6_LEGACY_UNIT}.timer"
  printf '  legacy       :%s\n' "${legacy_bits:- none}"

  if ssh_msg="$(_ipv6_ssh_guard)"; then ssh_state="ok"; else ssh_state="AT-RISK"; fi
  printf '  ssh          : %s — %s\n' "$ssh_state" "$ssh_msg"

  # APPLIED means our change is fully IN EFFECT, not merely installed. A file on
  # disk with all=0 underneath it is the exact state this module exists to fix, and
  # it must never read as healthy.
  if _ipv6_file_ok && { ! _ipv6_stack_present || { [ "$v_all" = "1" ] && [ "$v_def" = "1" ] && [ -z "$_IPV6_ON_LIST" ]; }; }; then
    token="APPLIED"
  elif [ "$file_state" = "absent" ] && [ "$v_all" != "1" ] && [ "$v_def" != "1" ]; then
    token="ABSENT"
  else
    token="PARTIAL"
  fi

  printf '%s  file=%s all=%s default=%s ifaces_off=%s/%s global_v6=%s ssh=%s\n' \
         "$token" "$file_state" "$v_all" "$v_def" "$_IPV6_OFF" "$_IPV6_TOTAL" "$gv" "$ssh_state"
  return 0
}

# -------------------------------------------------------------------- apply ---

mod_apply() {
  local msg prior lit

  ht_is_hiddify || warn "no /opt/hiddify-manager here — applying anyway, but the guard exists for Hiddify's apply-config"

  # SAFETY GATE, before a single byte is written. mod_verify re-runs this check and
  # the core rolls back on failure, but a rollback is cold comfort if the SSH session
  # running the rollback is the thing that died. Refuse up front instead.
  if msg="$(_ipv6_ssh_guard)"; then
    ok "ssh: $msg"
  else
    err "ssh: $msg"
    err "refusing — disabling IPv6 here would remove the way back into this box"
    return 1
  fi

  if _ipv6_session_is_v6 && [ "$(ht_conf_get allow_v6_session no)" != "yes" ]; then
    err "your own session is over IPv6 (${SSH_CONNECTION%% *}) — it would be cut mid-apply"
    err "reconnect over IPv4, or override: echo allow_v6_session=yes >> $(ht_state_dir)/conf/ipv6.conf"
    return 1
  fi

  # THIRD GATE, the same reasoning one layer out: SSH is not the only thing bound to an
  # address we are about to delete, and this is the only place that can catch it.
  # mod_verify reads sysctls and SSH only, so a service killed here verifies GREEN and is
  # never rolled back; mod_revert re-enables IPv6 but restarts nothing, so it stays dead
  # through a revert too. Every refusal above this point runs before any state is written,
  # so a refused apply leaves the conf file untouched.
  lit="$(_ipv6_literal_binds)"
  if [ -n "$lit" ]; then
    warn "these listeners are bound to a LITERAL IPv6 address, not the [::] wildcard:"
    printf '%s\n' "$lit" | sed 's/^/        /'
    warn "disable_ipv6 flushes those addresses (::1 on lo included), so each one fails with"
    warn "EADDRNOTAVAIL on its next restart — and Hiddify restarts its services on every"
    warn "apply-config. Our own tuning notes record shadowsocks-libev dying on 'bind ::1'."
    if [ "$(ht_conf_get allow_v6_literal_binds no)" != "yes" ]; then
      err "refusing — restart-safe those services first, or accept the risk with:"
      err "  echo allow_v6_literal_binds=yes >> $(ht_state_dir)/conf/ipv6.conf"
      return 1
    fi
    ht_log "ipv6: applied over literal v6 binds: $(printf '%s' "$lit" | tr '\n' ' ')"
    ht_conf_set literal_binds "$(printf '%s' "$lit" | tr '\n' ' ')"
  else
    ht_conf_set literal_binds ""
  fi

  # Capture the pre-toolkit state ONCE (ht_backup's rule, applied to a runtime value):
  # if something else on this box had already disabled IPv6, revert must hand that
  # state back rather than blindly switching a stack back on that the operator turned
  # off on purpose. ht_conf_get returns the default for an empty value, so a second
  # apply cannot overwrite the baseline with our own already-applied 1.
  #
  # But the LIVE value is only a trustworthy baseline when nothing has already disabled
  # IPv6 *for us*. Our own file, the standalone predecessor, or its timer all mean the 1
  # we are reading is OURS. Recording it as the operator's intent makes revert a
  # permanent no-op — and an incoherent one, because apply has by then deleted the
  # predecessor's file and unit, so IPv6 is held off by nothing at all: it comes back at
  # the next reboot and the module reads "partial" in the menu until then. The same trap
  # fires with no predecessor at all if /var/lib/hiddify-toolkit is lost (snapshot
  # restore, manual rm) and apply runs a second time over our own applied state.
  # This check must stay ABOVE the legacy retire below, or it has nothing left to see.
  prior="$(ht_conf_get prior_all "")"
  if [ -z "$prior" ]; then
    if [ -f "$IPV6_SYSCTL_FILE" ] \
       || [ -f "$IPV6_LEGACY_FILE" ] \
       || [ -f "/etc/systemd/system/${IPV6_LEGACY_UNIT}.timer" ] \
       || [ -f "/etc/systemd/system/${IPV6_LEGACY_UNIT}.service" ]; then
      prior=0
    else
      prior="$(_ipv6_read all)"
      case "$prior" in 0|1) ;; *) prior=0 ;; esac
    fi
    ht_conf_set prior_all "$prior"
  fi

  # One source of truth. Two files setting the same key means the winner depends on
  # filename order and the loser is invisible. The old file is copied into the module
  # backup dir for the record, but revert deliberately does NOT put it back: restoring
  # a second file that also disables IPv6 would make the revert look silently broken.
  if [ -f "$IPV6_LEGACY_FILE" ]; then
    ht_backup "$IPV6_LEGACY_FILE"
    rm -f "$IPV6_LEGACY_FILE"
    warn "retired $IPV6_LEGACY_FILE (backed up in $(ht_backup_dir), never restored)"
  fi

  ht_retire_legacy_unit "$IPV6_LEGACY_UNIT"

  _ipv6_write_file || { err "could not write $IPV6_SYSCTL_FILE"; return 1; }
  ok "wrote $IPV6_SYSCTL_FILE"

  # Deliberately not `sysctl --system`: that re-applies every file on the box,
  # Hiddify's included, which is a far bigger blast radius than this module asked
  # for. -p on our one file proves it parses; the /proc sweep below is what changes
  # the running kernel, and it reaches interfaces the file can never name.
  sysctl -q -p "$IPV6_SYSCTL_FILE" >/dev/null 2>&1 || warn "sysctl -p reported an error on our file"

  if _ipv6_force_off; then
    ok "IPv6 forced off on every interface ($_IPV6_CHANGED knob(s) changed)"
    if [ "$_IPV6_STUCK" -gt 0 ]; then
      warn "$_IPV6_STUCK disable_ipv6 knob(s) could NOT be written — IPv6 is still up on them"
    fi
  else
    ok "ipv6 kernel module is not loaded — stack already absent; file left in place for when it is"
  fi

  return 0
}

# ------------------------------------------------------------------- verify ---

mod_verify() {
  local rc=0 msg v n lit

  if ! _ipv6_file_ok; then
    err "$IPV6_SYSCTL_FILE missing or does not carry both keys"
    rc=1
  fi

  if _ipv6_stack_present; then
    for n in all default; do
      v="$(_ipv6_read "$n")"
      if [ "$v" != "1" ]; then err "$n/disable_ipv6 = $v (expected 1)"; rc=1; fi
    done
    _ipv6_survey
    if [ -n "$_IPV6_ON_LIST" ]; then
      err "IPv6 still enabled on:$_IPV6_ON_LIST"
      rc=1
    else
      ok "all $_IPV6_TOTAL disable_ipv6 knobs read 1"
    fi
  else
    ok "ipv6 stack absent (module not loaded)"
  fi

  # The check this whole module is gated on: prove we did not just cut our own way in.
  if msg="$(_ipv6_ssh_guard)"; then
    ok "ssh: $msg"
  else
    err "ssh: $msg"
    rc=1
  fi

  # Reported, never fatal. Reaching verify at all means the operator already set
  # allow_v6_literal_binds=yes and accepted this; failing here would roll back the very
  # thing they just overrode. It stays visible because these services do not die now —
  # they die at their next restart, which is the next Hiddify apply-config.
  lit="$(_ipv6_literal_binds)"
  if [ -n "$lit" ]; then
    warn "still bound to literal IPv6 addresses (will fail to re-bind on restart): $(printf '%s' "$lit" | tr '\n' ' ')"
  fi

  return "$rc"
}

# ------------------------------------------------------------------- revert ---

mod_revert() {
  local prior applied=0 lit_at_apply

  # A revert must be a NO-OP when there is nothing of ours to undo. The menu offers
  # "2) revert" unconditionally, whatever mod_status reported, and prior_all defaulted
  # to 0 — so pressing it on a box where this module had never run force-ENABLED IPv6
  # on every interface, silently contradicting the operator's own hand-written
  # /etc/sysctl.d file until the next reboot, and then printed "removed <file>" for a
  # file that never existed.
  [ -f "$IPV6_SYSCTL_FILE" ] && applied=1
  [ -n "$(ht_conf_get prior_all "")" ] && applied=1
  [ -f "/etc/systemd/system/${IPV6_LEGACY_UNIT}.timer" ] && applied=1
  [ -f "/etc/systemd/system/${IPV6_LEGACY_UNIT}.service" ] && applied=1
  if [ "$applied" = "0" ]; then
    ok "nothing to revert — this module was never applied here; IPv6 left exactly as it is"
    return 0
  fi

  prior="$(ht_conf_get prior_all 0)"
  case "$prior" in 0|1) ;; *) prior=0 ;; esac

  if [ -f "$IPV6_SYSCTL_FILE" ]; then
    rm -f "$IPV6_SYSCTL_FILE" && ok "removed $IPV6_SYSCTL_FILE"
  fi

  # Retire the pre-toolkit unit here too, not only on apply. If someone re-ran the old
  # standalone script by hand, its timer is still armed and would re-disable IPv6 two
  # minutes from now — the revert would look like it silently failed.
  ht_retire_legacy_unit "$IPV6_LEGACY_UNIT"

  if _ipv6_stack_present; then
    _ipv6_force_value "$prior"
    if [ "$prior" = "1" ]; then
      ok "IPv6 left disabled — it was already off before this module was applied"
      warn "nothing in this module holds it off any more; unless another file does, it returns at the next reboot"
    else
      # Writing 0 back makes the kernel re-run address configuration, so link-local
      # returns on its own. An interface that stays bare needs a down/up.
      ok "IPv6 re-enabled on every interface"
    fi
  fi

  # Re-enabling an address does not restart the service that failed to bind to it.
  # Anything that died on EADDRNOTAVAIL while we were applied is still dead right now.
  lit_at_apply="$(ht_conf_get literal_binds "")"
  if [ -n "$lit_at_apply" ]; then
    warn "these were bound to literal IPv6 addresses when this module was applied: $lit_at_apply"
    warn "revert restarts nothing — restart those services by hand if they failed to re-bind"
  fi

  # Drop the baseline so the next apply re-reads the real current state instead of
  # replaying a stale one.
  ht_conf_set prior_all ""
  ht_conf_set literal_binds ""

  return 0
}

# ----------------------------------------------------------------- reassert ---

mod_reassert() {
  # Nothing here restarts a service, and nothing here ever should — that is precisely
  # what makes this module safe to run every 2 minutes. The only writes are into
  # procfs, and only into knobs that are not already correct.
  _ipv6_file_ok || _ipv6_write_file || return 1

  _ipv6_stack_present || return 0

  _ipv6_force_off || return 1
  if [ "$_IPV6_CHANGED" != "0" ]; then
    # Worth a log line: a non-zero count here IS the evidence that Hiddify ran
    # apply-config and re-enabled IPv6, which is the only reason this module exists.
    ht_log "ipv6: re-forced $_IPV6_CHANGED knob(s) off (something re-enabled IPv6)"
  fi
  if [ "$_IPV6_STUCK" != "0" ]; then
    # The silent case, and the reason the counter exists: reassert never runs
    # mod_verify, so an unwritable knob would otherwise be a live IPv6 path that
    # nothing on this box ever mentions again.
    ht_log "ipv6: $_IPV6_STUCK disable_ipv6 knob(s) could NOT be written — IPv6 still up on them"
  fi
  return 0
}
