# shellcheck shell=bash
# =============================================================================
# hiddify-toolkit module: outbound-ip
#
# Pick which of this box's IPv4 addresses SERVER-INITIATED traffic leaves from,
# while inbound client connections keep landing on the address they already use.
#
# Why no DNS record and no client config has to change: the nat table is consulted
# only for the FIRST packet of a connection. Replies to an inbound client
# connection belong to an already-established conntrack entry, so they never
# traverse nat/POSTROUTING again and keep their original source address. Only
# connections the box itself opens are NEW on the way out, and only those are
# SNATed.
#
# Deliberately NOT here: judging the reputation of a candidate address. Blocklist
# lookups are a different job and must not gate a network change.
#
# The one way this CAN cut live user traffic, inherent to the design and worth
# knowing before you enable it: the reasoning above holds only while the inbound
# connection's conntrack entry lives. UDP transports (hysteria2, tuic,
# wireguard/warp) expire after nf_conntrack_udp_timeout_stream, 120 s by default.
# A tunnel that goes quiet past that and then gets a server-side keepalive emits a
# packet netfilter sees as NEW, so POSTROUTING rewrites its source to the chosen
# address and the client drops the reply as coming from a stranger. TCP is not at
# practical risk (established entries live for days). Mitigation belongs in
# 10-tuning.sh next to the other nf_conntrack timeouts:
# net.netfilter.nf_conntrack_udp_timeout_stream = 600.
# =============================================================================

# shellcheck disable=SC2034  # the core reads these after sourcing the module
{
MOD_ID="outbound-ip"
MOD_TITLE="Choose the outbound IP"
MOD_TITLE_FA="انتخاب آی‌پی خروجی سرور"
MOD_DESC="Sends all outbound (server-initiated) traffic through an IPv4 address you pick, while inbound keeps landing on the current one — no DNS and no client-config change."
MOD_GUARD=yes
}

# iptables refuses more than one -d per rule, so "do not translate traffic to any
# of these" is five rules, not one, and every one of them must sit ABOVE the SNAT.
# They are additionally scoped with -s <primary>: a bare -d RETURN at the top of
# POSTROUTING would also short-circuit docker's own MASQUERADE for container->LAN
# traffic, which has nothing to do with us.
_OIP_PRIV=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 127.0.0.0/8)

# Independent operators on purpose: one of them going down must not look like a
# failed change.
_OIP_ECHO_URLS=(https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com https://ipinfo.io/ip)

# --------------------------------------------------------------- primitives ---

_oip_is_ipv4() {
  local ip="${1:-}" a b c d extra o
  case "$ip" in ""|*[!0-9.]*) return 1 ;; esac
  IFS=. read -r a b c d extra <<<"$ip"
  [ -n "${d:-}" ] && [ -z "${extra:-}" ] || return 1
  for o in "$a" "$b" "$c" "$d"; do
    [ "$o" -ge 0 ] 2>/dev/null && [ "$o" -le 255 ] 2>/dev/null || return 1
  done
  return 0
}

# "Cannot be a public unicast egress source." Deliberately wider than RFC1918: the
# picker prints this beside a candidate and mod_apply/mod_reassert REFUSE on it, so
# every address the internet will never route back has to land in here. 0/8, 224/4
# and 240/4 used to fall through to "public", get accepted, and then fail later with
# a message about iptables rather than about the address.
_oip_is_private() {
  case "${1:-}" in
    0.*|10.*|127.*|192.168.*|169.254.*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;
    22[4-9].*|23[0-9].*) return 0 ;;                 # 224/4 multicast
    24[0-9].*|25[0-5].*) return 0 ;;                 # 240/4 reserved + 255.255.255.255
  esac
  return 1
}

# "<ip>|<iface>" for every global-scope IPv4 on the box, loopback excluded.
_oip_candidates() {
  ip -4 -o addr show scope global 2>/dev/null | awk '
    $2 != "lo" { split($4, a, "/"); if (a[1] !~ /^127\./ && !seen[a[1]]++) print a[1] "|" $2 }'
}

# The address the kernel picks as source for internet-bound traffic, and its device.
# Safe to call after our SNAT is installed: a route lookup never consults the nat
# table, so this keeps reporting the PRIMARY address, not the translated one.
_oip_primary() {
  ip -4 route get 1.1.1.1 2>/dev/null | awk '
    { for (i = 1; i <= NF; i++) { if ($i == "src") s = $(i+1); if ($i == "dev") d = $(i+1) } }
    END { if (s != "") print s "|" d }'
}

# Exact address comparison. The predecessor script used `grep -q "$IP"`, where the
# dots are regex wildcards and the match is a substring — 203.0.113.5 "found"
# 203.0.113.56 and the address was never added.
_oip_addr_present() {
  ip -4 -o addr show 2>/dev/null | awk -v want="${1:-}" '
    { split($4, a, "/"); if (a[1] == want) found = 1 } END { exit found ? 0 : 1 }'
}

_oip_addr_iface() {
  ip -4 -o addr show 2>/dev/null | awk -v want="${1:-}" '
    { split($4, a, "/"); if (a[1] == want) { print $2; exit } }'
}

_oip_env() {
  OIP_CHOSEN="$(ht_conf_get outbound_ip "")"
  OIP_PRIMARY="$(ht_conf_get source_ip "")"
  OIP_IFACE="$(ht_conf_get iface "")"
  OIP_SOCKS="$(ht_conf_get socks_port 1234)"
  local live; live="$(_oip_primary)"
  OIP_LIVE_PRIMARY="${live%%|*}"
  OIP_LIVE_IFACE="${live##*|}"
  # Reassert and revert work off the STORED pair, so they always undo exactly what
  # apply installed. A box whose primary address changed under us therefore reads
  # as PARTIAL in mod_status instead of silently rebuilding rules that match nothing.
  [ -n "$OIP_PRIMARY" ] || OIP_PRIMARY="$OIP_LIVE_PRIMARY"
  [ -n "$OIP_IFACE" ]   || OIP_IFACE="$OIP_LIVE_IFACE"
  return 0
}

# ------------------------------------------------------------------- probes ---

_oip_egress_once() {
  local u v
  for u in "${_OIP_ECHO_URLS[@]}"; do
    v="$(curl -4 -fsS --max-time "${1:-8}" "$u" 2>/dev/null | tr -d '[:space:]')"
    if _oip_is_ipv4 "$v"; then printf '%s\n' "$v"; return 0; fi
  done
  return 1
}

# Up to N answers from DIFFERENT operators, so one lying or captive-portalled
# service cannot on its own condemn a good change (or bless a bad one).
_oip_egress_probe() {
  local want="${1:-2}" got=0 u v
  for u in "${_OIP_ECHO_URLS[@]}"; do
    [ "$got" -lt "$want" ] || break
    v="$(curl -4 -fsS --max-time 8 "$u" 2>/dev/null | tr -d '[:space:]')"
    _oip_is_ipv4 "$v" || continue
    printf '%s\n' "$v"
    got=$((got + 1))
  done
  [ "$got" -gt 0 ]
}

_oip_socks_listening() {
  ss -lnt 2>/dev/null | awk -v p=":${1:-1234}" '$4 ~ p"$" { found = 1 } END { exit found ? 0 : 1 }'
}

# socks5h, never socks5: the "h" makes the PROXY resolve the name, which is what a
# real client does. Resolving locally would test this box's DNS, not the tunnel.
_oip_tunnel_code() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 15 \
       --proxy "socks5h://127.0.0.1:${1:-1234}" https://www.google.com/ 2>/dev/null
}

# mod_status is re-rendered for EVERY module on every menu redraw, and module_menu
# renders this one twice per keystroke (once through ht_module_state, once for the
# body). _oip_egress_once walks up to four services at --max-time 4, so uncached that
# was up to ~32 s of frozen UI per keypress — on a box whose egress is broken, which
# is the only box anyone opens this menu on. The cache is keyed on the state it
# describes, not just on time, so an apply or a revert invalidates it on the spot
# instead of reporting the pre-change answer for another minute.
_OIP_EGRESS_TTL=60
_oip_egress_cached() {                   # <state-signature> -> ip (may be empty)
  local sig="${1:-}" now at csig v
  now="$(date +%s)"
  at="$(ht_conf_get egress_probe_at 0)"; case "$at" in ''|*[!0-9]*) at=0 ;; esac
  csig="$(ht_conf_get egress_probe_sig "")"
  if [ "$csig" = "$sig" ] && [ "$((now - at))" -lt "$_OIP_EGRESS_TTL" ]; then
    ht_conf_get egress_probe_ip ""
    return 0
  fi
  v="$(_oip_egress_once 4)"
  # `hiddify-toolkit status` deliberately does NOT need_root, so the cache write can
  # fail with EACCES. That must never spray permission errors into the middle of the
  # report, and must never swallow the answer we are already holding.
  if [ "$(id -u)" -eq 0 ]; then
    ht_conf_set egress_probe_sig "$sig"   >/dev/null 2>&1
    ht_conf_set egress_probe_at  "$now"   >/dev/null 2>&1
    ht_conf_set egress_probe_ip  "${v:-}" >/dev/null 2>&1
  fi
  printf '%s\n' "$v"
  return 0
}

# ------------------------------------------------------------------- notes ----
# mod_reassert runs 720 times a day and is silent by design, so its findings go to
# the toolkit log — but only when they CHANGE. A permanent condition (a hand-edited
# conf we refuse to honour) otherwise writes 720 identical lines a day until the log
# is the thing nobody reads.
_oip_note() {                            # <message>
  local msg="$1" nf prev
  nf="$(ht_state_dir)/${MOD_ID}.note"
  prev="$(cat "$nf" 2>/dev/null)" || prev=""
  [ "$prev" = "$msg" ] && return 0
  mkdir -p "$(ht_state_dir)" 2>/dev/null || true
  printf '%s\n' "$msg" > "$nf" 2>/dev/null || true
  ht_log "[$MOD_ID] $msg"
  return 0
}

_oip_note_clear() {
  rm -f "$(ht_state_dir)/${MOD_ID}.note" 2>/dev/null || true
  return 0
}

# ht_conf_get returns whatever is in the file, including a hand-typed word where a
# number belongs; $(( )) on that is a runtime error inside the guard.
_oip_count_bump() {                      # <key>
  local k="${1:-}" v
  v="$(ht_conf_get "$k" 0)"
  case "$v" in ''|*[!0-9]*) v=0 ;; esac
  ht_conf_set "$k" "$((v + 1))"
}

# -------------------------------------------------------------------- rules ---

_oip_rules_delete() {                    # <iface> <primary> <chosen>
  local ifc="${1:-}" pri="${2:-}" ch="${3:-}" c
  [ -n "$ifc" ] && [ -n "$pri" ] && [ -n "$ch" ] || return 0
  # Loops, not single deletes: a half-finished earlier run can leave duplicates,
  # and `-D` removes one copy per call.
  while iptables -w 5 -t nat -C POSTROUTING -o "$ifc" -s "$pri" -j SNAT --to-source "$ch" 2>/dev/null; do
    iptables -w 5 -t nat -D POSTROUTING -o "$ifc" -s "$pri" -j SNAT --to-source "$ch" 2>/dev/null || break
  done
  for c in "${_OIP_PRIV[@]}"; do
    while iptables -w 5 -t nat -C POSTROUTING -o "$ifc" -s "$pri" -d "$c" -j RETURN 2>/dev/null; do
      iptables -w 5 -t nat -D POSTROUTING -o "$ifc" -s "$pri" -d "$c" -j RETURN 2>/dev/null || break
    done
  done
  return 0
}

_oip_rules_install() {                   # <iface> <primary> <chosen>
  local ifc="${1:-}" pri="${2:-}" ch="${3:-}" c
  [ -n "$ifc" ] && [ -n "$pri" ] && [ -n "$ch" ] || return 1
  _oip_rules_delete "$ifc" "$pri" "$ch"
  # INSERT at 1, never append: anything appended lands after whatever blanket
  # MASQUERADE another package (or a future Hiddify) put in POSTROUTING, and a
  # shadowed rule still answers `-C` with "present", so nothing ever self-heals.
  # SNAT goes in first and each RETURN is pushed in above it, so the finished
  # block is [RETURN x5][SNAT] at the top of the chain.
  iptables -w 5 -t nat -I POSTROUTING 1 -o "$ifc" -s "$pri" -j SNAT --to-source "$ch" 2>/dev/null || return 1
  for c in "${_OIP_PRIV[@]}"; do
    iptables -w 5 -t nat -I POSTROUTING 1 -o "$ifc" -s "$pri" -d "$c" -j RETURN 2>/dev/null || return 1
  done
  return 0
}

# WHOLE-TOKEN matching, with the line padded so its first and last fields are
# bounded like every other one.
#
# The extra patterns used to be tested as bare substrings, and `--to-source` is the
# LAST field on an `iptables -S` line, so nothing terminated it: with the chosen
# address 198.51.100.19, a live rule pointing at 198.51.100.197 matched. That is not
# cosmetic. _oip_purge_foreign_snat then read the stale foreign SNAT as "already
# ours" and left it; mod_revert deleted only its own exact spec; the re-scan still
# saw a rule, so revert returned non-zero; bin/hiddify-toolkit skipped
# ht_mark_disabled; the module stayed ENABLED and the guard timer put the whole SNAT
# block back two minutes after the operator was told the revert had failed. Exactly
# the class the predecessor's `grep -q "$IP"` fell into (see _oip_addr_present).
_oip_line_matches() {                    # <line> <iface> <primary> [extra...]
  local l="$1" ifc="$2" pri="$3"; shift 3
  local hay=" $l " pat
  [[ "$hay" == *" -o $ifc "* ]] || return 1
  [[ "$hay" == *" -s $pri/32 "* || "$hay" == *" -s $pri "* ]] || return 1
  for pat in "$@"; do
    while [[ "$pat" == " "* ]]; do pat="${pat# }"; done   # callers pass " -d 10.0.0.0/8 "
    while [[ "$pat" == *" " ]]; do pat="${pat% }"; done
    [ -n "$pat" ] || continue
    [[ "$hay" == *" $pat "* ]] || return 1
  done
  return 0
}

# Presence is not enough — ORDER is the whole contract. Scan once and record where
# our SNAT sits relative to our RETURNs, and where our block sits in the chain.
_oip_rules_scan() {                      # <iface> <primary> <chosen>
  local ifc="${1:-}" pri="${2:-}" ch="${3:-}" l c n=0
  _OIP_RET_N=0; _OIP_RET_MAX=0; _OIP_RET_MIN=0
  _OIP_SNAT_IDX=0; _OIP_SNAT_N=0; _OIP_FIRST_RULE=0
  [ -n "$ifc" ] && [ -n "$pri" ] && [ -n "$ch" ] || return 0
  while IFS= read -r l; do
    n=$((n + 1))
    [[ "$l" == "-A POSTROUTING "* ]] || continue
    [ "$_OIP_FIRST_RULE" -eq 0 ] && _OIP_FIRST_RULE="$n"
    if _oip_line_matches "$l" "$ifc" "$pri" "-j SNAT" "--to-source $ch"; then
      _OIP_SNAT_N=$((_OIP_SNAT_N + 1))
      # FIRST match, never the last. iptables walks top-down and stops at the first
      # terminating target, so in a chain that ended up [SNAT][RETURN x5][SNAT] the
      # copy that actually fires is the one at the top. Recording the last one made
      # that chain report "SNAT sits below every RETURN" and read as perfectly
      # healthy while every private-destination packet from this box was translated.
      [ "$_OIP_SNAT_IDX" -eq 0 ] && _OIP_SNAT_IDX="$n"
      continue
    fi
    for c in "${_OIP_PRIV[@]}"; do
      if _oip_line_matches "$l" "$ifc" "$pri" " -d $c " "-j RETURN"; then
        _OIP_RET_N=$((_OIP_RET_N + 1)); _OIP_RET_MAX="$n"
        [ "$_OIP_RET_MIN" -eq 0 ] && _OIP_RET_MIN="$n"
        break
      fi
    done
  done < <(iptables -w 5 -t nat -S POSTROUTING 2>/dev/null)
  return 0
}

_oip_rules_ok() {
  [ "${_OIP_SNAT_IDX:-0}" -gt 0 ] || return 1
  # Exactly one, and a duplicate is not "extra safety": the copies sit at different
  # depths and only the topmost is ever consulted. Reporting not-ok is what makes
  # _oip_rules_install run, and its first act is to delete every copy.
  [ "${_OIP_SNAT_N:-0}" -eq 1 ] || return 1
  [ "${_OIP_RET_N:-0}" -eq "${#_OIP_PRIV[@]}" ] || return 1
  [ "${_OIP_SNAT_IDX}" -gt "${_OIP_RET_MAX:-0}" ] || return 1
  return 0
}

_oip_rules_state() {                     # -> ok | partial | absent
  if _oip_rules_ok; then printf 'ok\n'
  elif [ "${_OIP_SNAT_IDX:-0}" -eq 0 ] && [ "${_OIP_RET_N:-0}" -eq 0 ]; then printf 'absent\n'
  else printf 'partial\n'; fi
}

# A leftover SNAT from an earlier hand-rolled script (or a previous choice made
# outside the toolkit) rewrites the SAME source address to a different target. Ours
# is inserted above it so we still win, but leaving it means revert hands the box
# back to that stale address instead of its primary. Only rules that hijack OUR
# source are touched.
_oip_purge_foreign_snat() {              # <iface> <primary> <chosen>
  local ifc="$1" pri="$2" ch="$3" l removed=0
  local -a parts=()
  while IFS= read -r l; do
    [[ "$l" == "-A POSTROUTING "* ]] || continue
    [[ " $l " == *" -j SNAT "* ]] || continue
    _oip_line_matches "$l" "$ifc" "$pri" "-j SNAT" || continue
    # Whole-token, for the reason spelled out on _oip_line_matches: a bare substring
    # here declares a rule pointing at 198.51.100.197 to be "already ours" when we
    # chose 198.51.100.19, and the stale SNAT survives into the revert.
    [[ " $l " == *" --to-source $ch "* ]] && continue
    read -r -a parts <<<"$l"
    parts[0]="-D"
    if iptables -w 5 -t nat "${parts[@]}" 2>/dev/null; then
      removed=$((removed + 1))
    else
      # Word-splitting a rule that carries `-m comment --comment "two words"` yields
      # tokens iptables will not take back, and the -D fails. Say so. Counting zero
      # and moving on leaves exactly the silent stale SNAT this function exists to
      # stop, and revert would later hand the box to it.
      warn "could not delete a stale SNAT — remove it by hand: iptables -w 5 -t nat -D ${l#-A }"
    fi
  done < <(iptables -w 5 -t nat -S POSTROUTING 2>/dev/null)
  [ "$removed" -gt 0 ] && warn "removed $removed stale SNAT rule(s) that also rewrote $pri"
  return 0
}

# Every rule we install, checked by EXACT spec. _oip_rules_scan matches by SHAPE,
# which is the right question for "is the chain healthy"; this answers "did our own
# delete actually work", and the two stop agreeing the moment somebody else's rule
# shares our shape.
_oip_own_rules_present() {               # <iface> <primary> <chosen>
  local ifc="${1:-}" pri="${2:-}" ch="${3:-}" c
  [ -n "$ifc" ] && [ -n "$pri" ] && [ -n "$ch" ] || return 1
  iptables -w 5 -t nat -C POSTROUTING -o "$ifc" -s "$pri" -j SNAT --to-source "$ch" 2>/dev/null && return 0
  for c in "${_OIP_PRIV[@]}"; do
    iptables -w 5 -t nat -C POSTROUTING -o "$ifc" -s "$pri" -d "$c" -j RETURN 2>/dev/null && return 0
  done
  return 1
}

# The standalone predecessor (/root/floating-ip-outbound.sh) appended its private-range
# excludes with NO -s scoping:  -A POSTROUTING -o eth0 -d 10.0.0.0/8 -j RETURN.
# Nothing else in this module can see that shape — every helper here demands
# " -s <primary> " — so those five rules survive apply, revert AND uninstall, forever.
# They are not inert either: an unscoped RETURN in nat/POSTROUTING terminates chain
# traversal for ANY packet leaving that device toward a private destination, which is
# precisely the docker container->LAN MASQUERADE hazard the _OIP_PRIV comment at the
# top warns about, and it bites as soon as docker's appended rules land below them
# (any `systemctl restart docker`). `iptables -C` needs an exact spec, so our own
# -s-scoped RETURNs can never be caught by this. The caller still gates it on legacy
# artifacts being present, so a third party's identical rule is never eaten.
_oip_purge_legacy_rules() {              # <iface>
  local ifc="${1:-}" d c n=0
  local -a devs=(eth0)                   # the predecessor hardcoded eth0
  [ -n "$ifc" ] && [ "$ifc" != "eth0" ] && devs+=("$ifc")
  for d in "${devs[@]}"; do
    for c in "${_OIP_PRIV[@]}"; do
      while iptables -w 5 -t nat -C POSTROUTING -o "$d" -d "$c" -j RETURN 2>/dev/null; do
        iptables -w 5 -t nat -D POSTROUTING -o "$d" -d "$c" -j RETURN 2>/dev/null || break
        n=$((n + 1))
      done
    done
  done
  [ "$n" -gt 0 ] && warn "removed $n unscoped legacy RETURN rule(s) left by floating-ip-outbound.sh"
  return 0
}

# ------------------------------------------------------------------- picker ---

_oip_pick() {                            # sets OIP_CHOSEN
  local stored; stored="$(ht_conf_get outbound_ip "")"
  local -a ips=() ifs=()
  local a i
  while IFS='|' read -r a i; do
    [ -n "$a" ] || continue
    ips+=("$a"); ifs+=("$i")
  done < <(_oip_candidates)

  # No TTY: the guard timer, `hiddify-toolkit apply outbound-ip` from a script, or a
  # fleet loop. Use what was stored and never block on a prompt nobody can answer.
  if [ ! -t 0 ]; then
    if [ -n "$stored" ]; then OIP_CHOSEN="$stored"; return 0; fi
    err "no outbound IP stored and no terminal to ask on"
    err "run 'hiddify-toolkit' interactively, or put outbound_ip=<addr> in $(ht_state_dir)/conf/${MOD_ID}.conf"
    return 1
  fi

  if [ "${#ips[@]}" -eq 0 ]; then
    err "no global-scope IPv4 address found on this box"
    return 1
  fi

  local n=0 note
  printf '\n  IPv4 addresses on this server:\n\n'
  for n in "${!ips[@]}"; do
    note=""
    [ "${ips[$n]}" = "${OIP_LIVE_PRIMARY:-}" ] && note="${note}  (current egress)"
    _oip_is_private "${ips[$n]}" && note="${note}  (not a public address — cannot be an internet egress)"
    [ "${ips[$n]}" = "$stored" ] && note="${note}  (current choice)"
    printf '   %d) %-16s on %-10s%s\n' "$((n + 1))" "${ips[$n]}" "${ifs[$n]}" "$note"
  done
  printf '\n  Enter a number, or type an address the provider routes here but that is\n'
  printf '  not configured yet%s.\n\n' "$([ -n "$stored" ] && printf ' (empty = keep %s)' "$stored")"

  local ans; read -rp "  outbound IP > " ans
  ans="${ans//[[:space:]]/}"
  if [ -z "$ans" ]; then
    [ -n "$stored" ] || { err "nothing chosen"; return 1; }
    OIP_CHOSEN="$stored"; return 0
  fi
  # A bare number is an index; anything else must be a literal address. `1.2.3.4`
  # can never be mistaken for an index, so no ambiguity to resolve.
  if [ "$ans" -ge 1 ] 2>/dev/null && [ "$ans" -le "${#ips[@]}" ] 2>/dev/null; then
    OIP_CHOSEN="${ips[$((ans - 1))]}"
    return 0
  fi
  if _oip_is_ipv4 "$ans"; then OIP_CHOSEN="$ans"; return 0; fi
  err "not a number in range and not an IPv4 address: $ans"
  return 1
}

# ------------------------------------------------------------------ status ----

mod_status() {
  _oip_env
  if [ -z "$OIP_CHOSEN" ]; then
    printf 'default egress  : %s on %s\n' "${OIP_LIVE_PRIMARY:-unknown}" "${OIP_LIVE_IFACE:-unknown}"
    # `paste -sd', '` looks right and is not: GNU paste CYCLES through the
    # delimiter characters, so three addresses come out "a,b c".
    printf 'candidates      : %s\n' \
      "$(_oip_candidates | awk -F'|' '{ printf "%s%s", sep, $1; sep = ", " } END { printf "\n" }')"
    # No egress probe while unconfigured: mod_status is rendered for every module on
    # every menu redraw, and a network round-trip per redraw is felt immediately.
    printf 'ABSENT  no outbound IP chosen yet\n'
    return 0
  fi

  _oip_rules_scan "$OIP_IFACE" "$OIP_PRIMARY" "$OIP_CHOSEN"
  local rules; rules="$(_oip_rules_state)"
  local addr="no"; _oip_addr_present "$OIP_CHOSEN" && addr="yes"
  # Space-separated, never '|': ht_conf_set writes through `sed s|^k=.*|k=v|`.
  local egress; egress="$(_oip_egress_cached "$OIP_CHOSEN $OIP_PRIMARY $OIP_IFACE $rules $addr")"

  printf 'chosen egress   : %s\n' "$OIP_CHOSEN"
  printf 'observed egress : %s\n' "${egress:-unreachable (no echo service answered)}"
  printf 'inbound stays on: %s on %s\n' "$OIP_PRIMARY" "$OIP_IFACE"
  printf 'address on box  : %s%s\n' "$addr" \
    "$([ "$addr" = "yes" ] && printf ' (%s)' "$(_oip_addr_iface "$OIP_CHOSEN")")"
  printf 'nat rules       : %s (%s/%s RETURN, SNAT x%s%s)\n' "$rules" \
    "${_OIP_RET_N}" "${#_OIP_PRIV[@]}" "${_OIP_SNAT_N}" \
    "$([ "${_OIP_SNAT_N}" -gt 1 ] && printf ' — duplicates, only the top one fires')"

  local reasserts; reasserts="$(ht_conf_get reasserts 0)"
  [ "$reasserts" != "0" ] && printf 're-installed    : %s time(s), last %s — something keeps flushing nat\n' \
    "$reasserts" "$(ht_conf_get reassert_last unknown)"

  # Our SNAT sitting below our own RETURNs is only half the contract. Anything with a
  # terminating target INSERTED above the whole block shadows it, and a shadowed rule
  # still answers `-C` with "present", so nothing here ever self-heals. Report it and
  # deliberately keep it OUT of _oip_rules_ok: if the other tool re-inserts on its own
  # schedule, folding this into the health test would have the two of us rewriting the
  # chain at each other every 2 minutes — and a non-terminating rule above us (LOG,
  # MARK, CONNMARK) is harmless anyway, so this cannot be a state, only a warning.
  if [ "${_OIP_RET_MIN:-0}" -gt 0 ] && [ "${_OIP_FIRST_RULE:-0}" -gt 0 ] &&
     [ "${_OIP_RET_MIN}" -ne "${_OIP_FIRST_RULE}" ]; then
    printf 'WARNING         : %s rule(s) sit above our block in nat/POSTROUTING and may shadow it\n' \
      "$(( _OIP_RET_MIN - _OIP_FIRST_RULE ))"
  fi

  local note; note="$(cat "$(ht_state_dir)/${MOD_ID}.note" 2>/dev/null)" || note=""
  [ -n "$note" ] && printf 'guard           : %s\n' "$note"

  local drift="no"
  if [ -n "${OIP_LIVE_PRIMARY:-}" ] && [ "$OIP_LIVE_PRIMARY" != "$OIP_PRIMARY" ]; then
    drift="yes"
    printf 'WARNING         : primary is now %s, rules were built for %s — re-apply\n' \
      "$OIP_LIVE_PRIMARY" "$OIP_PRIMARY"
  fi

  local token="PARTIAL" summary
  if [ "$rules" = "ok" ] && [ "$addr" = "yes" ] && [ "$drift" = "no" ] &&
     { [ -z "$egress" ] || [ "$egress" = "$OIP_CHOSEN" ]; }; then
    token="APPLIED"; summary="outbound via $OIP_CHOSEN, inbound on $OIP_PRIMARY"
  elif [ "$rules" = "absent" ] && [ "$drift" = "no" ]; then
    token="ABSENT"; summary="chosen $OIP_CHOSEN but no rules installed"
  else
    summary="rules=$rules address=$addr observed=${egress:-unknown} expected=$OIP_CHOSEN"
  fi
  printf '%s  %s\n' "$token" "$summary"
  return 0
}

# ------------------------------------------------------------------- apply ----

mod_apply() {
  _oip_env
  if [ -z "${OIP_LIVE_PRIMARY:-}" ] || [ -z "${OIP_LIVE_IFACE:-}" ]; then
    err "cannot determine the default-route source address — is there a default route?"
    return 1
  fi
  # A box that egresses through a tunnel (warp/wireguard is common on Hiddify) or sits
  # behind provider NAT reports a PRIVATE source here, and the rule we would build —
  # -o warp -s 10.x.x.x -j SNAT --to-source <public> — cannot ever work. Left to run,
  # it installs fine, mod_verify then fails and the core auto-reverts, and for the
  # 30-50 s those probes take the box has no egress at all. Refuse up front, the way
  # 20-ipv6.sh refuses on its SSH guard.
  if _oip_is_private "$OIP_LIVE_PRIMARY"; then
    err "the default route leaves via $OIP_LIVE_IFACE with source $OIP_LIVE_PRIMARY (not a public address)"
    err "this box egresses through a tunnel or provider NAT — SNATing to a public address here cannot work"
    return 1
  fi

  _oip_pick || return 1

  if ! _oip_is_ipv4 "$OIP_CHOSEN"; then err "not an IPv4 address: $OIP_CHOSEN"; return 1; fi
  if _oip_is_private "$OIP_CHOSEN"; then
    err "$OIP_CHOSEN is not a public unicast address (private, link-local, multicast or reserved)"
    err "it cannot be an internet egress"
    return 1
  fi
  if [ "$OIP_CHOSEN" = "$OIP_LIVE_PRIMARY" ]; then
    err "$OIP_CHOSEN is already the default egress — nothing to apply"
    err "(use revert if a previous choice is still in place)"
    return 1
  fi

  # Rules always leave through the DEFAULT-ROUTE device, even when the chosen
  # address lives on another interface: -o matches where the packet exits, and it
  # exits where the route says, not where the address is configured.
  local ifc="$OIP_LIVE_IFACE" pri="$OIP_LIVE_PRIMARY" ch="$OIP_CHOSEN"

  # Probe the tunnel BEFORE touching anything: on a box whose tunnel is already
  # broken, mod_verify must not blame this change and auto-revert a good SNAT.
  # Above the already-applied fast path on purpose — bin/hiddify-toolkit runs
  # mod_verify after EVERY mod_apply, including the one that changed nothing, and
  # comparing today's tunnel against a baseline captured on some earlier day is how a
  # perfectly good SNAT gets rolled back for an outage that has nothing to do with it.
  local before_tunnel=""
  if _oip_socks_listening "$OIP_SOCKS"; then before_tunnel="$(_oip_tunnel_code "$OIP_SOCKS")"; fi
  ht_conf_set tunnel_before "${before_tunnel:-none}"

  # The standalone predecessor shipped its own hiddify-floatingip.timer. Two timers
  # enforcing the same thing means revert looks broken: the orphan puts it back.
  # Sample the evidence BEFORE ht_retire_legacy_unit deletes the unit files — they and
  # /root/floating-ip-outbound.sh are the only proof that the unscoped RETURN rules on
  # this box are the predecessor's and therefore ours to clear. Without that gate we
  # would be deleting a rule some other tool may legitimately own. This sits ABOVE the
  # already-applied fast path on purpose: returning early past it is how an orphan
  # timer and five unscoped RETURNs survive on a box that reads as perfectly healthy.
  local legacy=no
  if [ -f /etc/systemd/system/hiddify-floatingip.timer ] ||
     [ -f /etc/systemd/system/hiddify-floatingip.service ] ||
     [ -f /root/floating-ip-outbound.sh ]; then
    legacy=yes
  fi
  ht_retire_legacy_unit hiddify-floatingip
  if [ "$legacy" = "yes" ]; then
    _oip_purge_legacy_rules "$ifc"
    [ -f /root/floating-ip-outbound.sh ] &&
      warn "/root/floating-ip-outbound.sh is still on disk and is superseded by this module — delete it"
  fi

  # Undo the PREVIOUS choice before installing the new one. addr_added is a single
  # flag: apply with A (addr_added=yes), apply again with B, and the flag now
  # describes B while A stays configured on the interface — mod_revert can never
  # remove it, so every re-choice stranded one more /32 for good. The old rule SHAPE
  # has the same problem after a primary change: -s <old primary> matches nothing, but
  # nothing ever cleans it either.
  local prev prev_pri prev_ifc
  prev="$(ht_conf_get outbound_ip "")"
  prev_pri="$(ht_conf_get source_ip "$pri")"
  prev_ifc="$(ht_conf_get iface "$ifc")"
  if [ -n "$prev" ] &&
     { [ "$prev" != "$ch" ] || [ "$prev_pri" != "$pri" ] || [ "$prev_ifc" != "$ifc" ]; }; then
    _oip_rules_delete "$prev_ifc" "$prev_pri" "$prev"
    # Only an address WE added, and never one that is somebody's primary.
    if [ "$prev" != "$ch" ] && [ "$(ht_conf_get added_addr "")" = "$prev" ] &&
       [ "$prev" != "$prev_pri" ] && [ "$prev" != "$pri" ] && _oip_addr_present "$prev"; then
      if ip addr del "$prev/32" dev "$(_oip_addr_iface "$prev")" 2>/dev/null; then
        ok "removed the previously chosen $prev/32 (this module had added it)"
      else
        warn "could not remove the previously chosen $prev/32 — left configured"
      fi
    fi
  fi

  _oip_rules_scan "$ifc" "$pri" "$ch"
  if _oip_rules_ok && _oip_addr_present "$ch" && [ "$(ht_conf_get outbound_ip "")" = "$ch" ]; then
    ok "already applied — outbound is $ch, inbound stays on $pri"
    ht_conf_set source_ip "$pri"; ht_conf_set iface "$ifc"
    _oip_note_clear
    return 0
  fi

  local added="no"
  if ! _oip_addr_present "$ch"; then
    if ip addr add "$ch/32" dev "$ifc" 2>/dev/null; then
      added="yes"
      ok "added $ch/32 to $ifc (runtime only — mod_reassert re-adds it after a reboot)"
    else
      err "could not add $ch/32 to $ifc"
      return 1
    fi
  fi
  # Only an address WE added may ever be removed on revert. Deleting one that came
  # from netplan would take the box off the network on the next reboot-less revert.
  ht_conf_set addr_added "$added"
  # By VALUE, not as a flag: this is what lets a later apply/revert know exactly which
  # address this module put on the interface, even when the operator re-runs through
  # the conf-edit route and `prev` therefore equals `ch`.
  if [ "$added" = "yes" ]; then ht_conf_set added_addr "$ch"; fi

  _oip_purge_foreign_snat "$ifc" "$pri" "$ch"
  if ! _oip_rules_install "$ifc" "$pri" "$ch"; then
    err "installing the nat rules failed"
    _oip_rules_delete "$ifc" "$pri" "$ch"
    [ "$added" = "yes" ] && ip addr del "$ch/32" dev "$ifc" 2>/dev/null
    return 1
  fi

  ht_conf_set outbound_ip "$ch"
  ht_conf_set source_ip   "$pri"
  ht_conf_set iface       "$ifc"

  _oip_note_clear
  ok "outbound now SNATs $pri -> $ch on $ifc (inbound untouched)"
  # New connections pick the rule up immediately; this is only to let the freshly
  # added address settle before mod_verify opens its probes.
  sleep 1
  return 0
}

# ------------------------------------------------------------------ verify ----

mod_verify() {
  _oip_env
  [ -n "$OIP_CHOSEN" ] || { err "no outbound IP stored — nothing to verify"; return 1; }

  _oip_rules_scan "$OIP_IFACE" "$OIP_PRIMARY" "$OIP_CHOSEN"
  if ! _oip_rules_ok; then
    err "nat rules incomplete or mis-ordered (RETURN ${_OIP_RET_N}/${#_OIP_PRIV[@]}, SNAT x${_OIP_SNAT_N} first idx ${_OIP_SNAT_IDX}, last RETURN idx ${_OIP_RET_MAX})"
    return 1
  fi

  local -a seen=(); local ip
  while IFS= read -r ip; do seen+=("$ip"); done < <(_oip_egress_probe 2)
  if [ "${#seen[@]}" -eq 0 ]; then
    # Fail closed. An unverifiable change is not a verified one, and rolling back
    # costs nothing compared with discovering the box has no egress at all.
    err "no echo service answered — cannot prove the egress IP"
    return 1
  fi
  for ip in "${seen[@]}"; do
    if [ "$ip" != "$OIP_CHOSEN" ]; then
      err "egress reads $ip, expected $OIP_CHOSEN"
      return 1
    fi
  done
  ok "egress verified as $OIP_CHOSEN by ${#seen[@]} independent service(s)"

  if ! _oip_socks_listening "$OIP_SOCKS"; then
    warn "nothing listening on 127.0.0.1:${OIP_SOCKS} — user-tunnel check skipped"
    return 0
  fi
  local code before
  code="$(_oip_tunnel_code "$OIP_SOCKS")"
  before="$(ht_conf_get tunnel_before "")"
  if [ "$code" = "200" ]; then
    ok "live user tunnel through 127.0.0.1:${OIP_SOCKS} still returns 200"
    return 0
  fi
  if [ "$before" != "200" ]; then
    warn "tunnel returns ${code:-none}, but it was ${before:-unknown} before this change — not caused here"
    return 0
  fi
  err "live user tunnel through 127.0.0.1:${OIP_SOCKS} returns ${code:-none} (was 200 before)"
  return 1
}

# ------------------------------------------------------------------ revert ----

mod_revert() {
  _oip_env
  if [ -z "$OIP_CHOSEN" ]; then
    ok "nothing configured — nothing to undo"
    return 0
  fi

  _oip_rules_delete "$OIP_IFACE" "$OIP_PRIMARY" "$OIP_CHOSEN"
  # The primary may have changed since apply; clean that shape too, otherwise a
  # rule built after a re-apply survives the revert.
  if [ -n "${OIP_LIVE_PRIMARY:-}" ] && [ "$OIP_LIVE_PRIMARY" != "$OIP_PRIMARY" ]; then
    _oip_rules_delete "${OIP_LIVE_IFACE:-$OIP_IFACE}" "$OIP_LIVE_PRIMARY" "$OIP_CHOSEN"
  fi

  if [ "$(ht_conf_get added_addr "")" = "$(ht_conf_get outbound_ip "")" ] &&
     [ "$OIP_CHOSEN" != "$OIP_PRIMARY" ] && _oip_addr_present "$OIP_CHOSEN"; then
    if ip addr del "$OIP_CHOSEN/32" dev "$(_oip_addr_iface "$OIP_CHOSEN")" 2>/dev/null; then
      ok "removed $OIP_CHOSEN/32 (this module had added it)"
    else
      warn "could not remove $OIP_CHOSEN/32 — left in place, it is harmless"
    fi
  fi
  ht_conf_set addr_added no
  ht_conf_set added_addr ""

  # Established flows keep their existing translation until they expire; `conntrack
  # -F` on a live VPN exit would drop every customer session to tidy up a table
  # that empties itself. Not worth it.
  _oip_rules_scan "$OIP_IFACE" "$OIP_PRIMARY" "$OIP_CHOSEN"
  if [ "$(_oip_rules_state)" != "absent" ]; then
    if _oip_own_rules_present "$OIP_IFACE" "$OIP_PRIMARY" "$OIP_CHOSEN"; then
      warn "iptables refused to delete a rule this module installed"
    else
      warn "nat rules of our shape survived, but none of them is ours to spec-delete"
    fi
    warn "inspect and clear by hand: iptables -w 5 -t nat -S POSTROUTING"
    ht_log "[$MOD_ID] revert left rules behind in nat/POSTROUTING"
    # And still SUCCESS, deliberately. Everything this module can remove IS removed.
    # Returning non-zero makes bin/hiddify-toolkit skip ht_mark_disabled, so the module
    # stays ENABLED, the guard fires two minutes later, mod_reassert finds an
    # incomplete block and reinstalls the entire SNAT — putting back the exact change
    # the operator was just told could not be reverted. That is the same orphan trap
    # ht_retire_legacy_unit exists to prevent, only self-inflicted.
  fi
  _oip_note_clear

  # The choice is kept on purpose, so re-applying does not make you find the
  # address again; mod_status reads it as ABSENT until rules exist.
  ok "outbound SNAT removed — egress is back to ${OIP_LIVE_PRIMARY:-$OIP_PRIMARY} (choice $OIP_CHOSEN remembered)"
  return 0
}

# ---------------------------------------------------------------- reassert ----

# Runs every 2 minutes while enabled: no probes, no DNS, no service action of any
# kind, and writes only when something is actually missing.
mod_reassert() {
  _oip_env
  [ -n "$OIP_CHOSEN" ] && [ -n "$OIP_PRIMARY" ] && [ -n "$OIP_IFACE" ] || return 1

  # Re-run the gates mod_apply used, on EVERY tick, against whatever the conf says
  # right now. This path writes to a live box unattended: there is no mod_verify
  # behind it and the core's auto-rollback exists only on the apply path, so nothing
  # downstream will catch a bad value. Two ways one gets in: _oip_pick's own error
  # message tells the operator to hand-write outbound_ip=<addr> into the conf, and a
  # fleet script can write the file wholesale. An unvalidated address SNATed onto
  # every server-initiated connection is a black hole for panel updates, cert renewal
  # and every proxied customer connection — and the guard would faithfully re-create
  # it every 2 minutes, forever. Refuse instead of writing.
  if ! _oip_is_ipv4 "$OIP_CHOSEN"; then
    _oip_note "refusing to re-assert: outbound_ip '$OIP_CHOSEN' is not an IPv4 address"; return 1
  fi
  if _oip_is_private "$OIP_CHOSEN"; then
    _oip_note "refusing to re-assert: outbound_ip $OIP_CHOSEN is not a public unicast address"; return 1
  fi
  if ! _oip_is_ipv4 "$OIP_PRIMARY"; then
    _oip_note "refusing to re-assert: source_ip '$OIP_PRIMARY' is not an IPv4 address"; return 1
  fi
  if _oip_is_private "$OIP_PRIMARY"; then
    _oip_note "refusing to re-assert: source_ip $OIP_PRIMARY is not a public unicast address"; return 1
  fi
  if [ "$OIP_CHOSEN" = "$OIP_PRIMARY" ]; then
    _oip_note "refusing to re-assert: outbound_ip and source_ip are both $OIP_CHOSEN"; return 1
  fi

  # No address, no rules. SNAT happily rewrites packets to an address that is not on
  # this box and then nothing can route the answers back — a silent black hole the
  # guard would rebuild every 2 minutes. If the provider took the floating IP away,
  # degrade to the primary and say so, rather than keeping the box off the internet.
  if ! _oip_addr_present "$OIP_CHOSEN"; then
    if ! ip addr add "$OIP_CHOSEN/32" dev "$OIP_IFACE" 2>/dev/null; then
      _oip_note "cannot add $OIP_CHOSEN/32 to $OIP_IFACE — removing the SNAT, egress falls back to $OIP_PRIMARY"
      _oip_rules_delete "$OIP_IFACE" "$OIP_PRIMARY" "$OIP_CHOSEN"
      return 1
    fi
  fi

  # Rebuild wholesale rather than filling in the gaps. A partial flush that took
  # only the RETURN rules would otherwise get them re-added BELOW the SNAT, and
  # private-range exclusion dies silently while every `-C` still says "present".
  _oip_rules_scan "$OIP_IFACE" "$OIP_PRIMARY" "$OIP_CHOSEN"
  if ! _oip_rules_ok; then
    if ! _oip_rules_install "$OIP_IFACE" "$OIP_PRIMARY" "$OIP_CHOSEN"; then
      _oip_note "could not re-install the nat rules on $OIP_IFACE"
      return 1
    fi
    # Counted, not logged. Hiddify's apply-config flushes nat often enough that an
    # ht_log per re-install turns the log into noise; the count is what tells an
    # operator whether the guard is doing its job or fighting something.
    _oip_count_bump reasserts
    ht_conf_set reassert_last "$(date -Is)"
  fi
  _oip_note_clear
  return 0
}
