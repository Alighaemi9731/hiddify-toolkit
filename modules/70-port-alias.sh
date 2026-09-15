# shellcheck shell=bash
# =============================================================================
# hiddify-toolkit module: port-alias
#
# Keep an OLD client port answering after the panel has moved to a new one, without
# the panel listing the old port — so subscriptions carry only the new port and no
# config is duplicated.
#
# Why this cannot be done inside Hiddify: every port in http_ports / tls_ports is
# (a) bound by HAProxy, whose config is re-rendered and restarted on every
# apply-config, so a port dropped from the list stops answering at the next apply,
# and (b) expanded by the panel into one config PER PORT, so keeping both ports in
# the list hands every user each config twice.
#
# Why a REDIRECT is equivalent to HAProxy binding the old port: the frontend routes
# on path / Host / SNI, never on the local port. A connection redirected from the
# old port to the new one takes exactly the path a client of the new port takes.
# Pair ports of the SAME kind: http -> http, tls -> tls.
#
# Two properties the rules below are built around:
#   - `-m addrtype --dst-type LOCAL`: PREROUTING also sees traffic this box only
#     FORWARDS (wireguard / warp clients browsing to some site on port 8080). An
#     unscoped REDIRECT would hijack those connections into our own HAProxy.
#   - The redirect exists only while something LISTENS on the target port. If the
#     panel still binds the old port and the new one is gone, removing the rule is
#     what keeps the old port alive instead of redirecting it into nothing.
#
# The firewall needs no change: nat/PREROUTING rewrites the port before filter/INPUT
# runs, so INPUT sees the TARGET port, which Hiddify already opens.
# =============================================================================

# shellcheck disable=SC2034  # the core reads these after sourcing the module
{
MOD_ID="port-alias"
MOD_TITLE="Keep an old port working"
MOD_DESC="Redirects an old client port (e.g. 8080) to the port the panel now uses (e.g. 2095), so old configs keep connecting while subscriptions list only the new port — and apply-config no longer cuts them off."
MOD_GUARD=yes
}

_PA_TAG="hiddify-toolkit:port-alias"

# --------------------------------------------------------------- primitives ---

_pa_is_port() { [ "${1:-}" -ge 1 ] 2>/dev/null && [ "${1:-}" -le 65535 ] 2>/dev/null; }

# Normalize "8080:2095, 8880:2095" into one "from:to" per line; fail on anything else.
_pa_parse() {                             # <spec>
  local spec="${1//[[:space:]]/}" pair from to rc=0
  [ -n "$spec" ] || return 1
  local IFS=,
  for pair in $spec; do
    [ -n "$pair" ] || continue
    from="${pair%%:*}"; to="${pair#*:}"
    if [ "$pair" = "$from" ] || ! _pa_is_port "$from" || ! _pa_is_port "$to" || [ "$from" = "$to" ]; then
      err "bad alias '$pair' — expected <old-port>:<new-port>, e.g. 8080:2095"; rc=1; continue
    fi
    printf '%s:%s\n' "$from" "$to"
  done
  return $rc
}

_pa_pairs() { _pa_parse "$(ht_conf_get aliases "")" 2>/dev/null; }

_pa_listening() {                         # <proto tcp|udp> <port>
  local flag=-Hltn; [ "$1" = "udp" ] && flag=-Hlun
  ss "$flag" 2>/dev/null | awk -v p=":$2" '{ if (substr($4, length($4) - length(p) + 1) == p) f = 1 } END { exit f ? 0 : 1 }'
}

# Ports the panel itself lists, one per line (443/80 are implicit in Hiddify's templates).
_pa_panel_ports() {                       # <http|tls>
  python3 - "$1" 2>/dev/null <<'PY'
import json, sys
try:
    c = json.load(open("/opt/hiddify-manager/current.json"))
    h = c.get("chconfigs", {}).get("0") or c.get("hconfigs") or {}
    key = "http_ports" if sys.argv[1] == "http" else "tls_ports"
    base = ["80"] if sys.argv[1] == "http" else ["443"]
    for p in base + [p.strip() for p in str(h.get(key) or "").split(",") if p.strip()]:
        print(p)
except Exception:
    pass
PY
}

_pa_port_kind() {                         # <port> -> http | tls | ""
  _pa_panel_ports http | grep -qx "$1" && { echo http; return; }
  _pa_panel_ports tls  | grep -qx "$1" && { echo tls; return; }
  echo ""
}

_pa_rule() {                              # <proto> <from> <to>  -> rule spec (no table/chain)
  printf -- '-p %s -m addrtype --dst-type LOCAL --dport %s -m comment --comment %s -j REDIRECT --to-ports %s' \
    "$1" "$2" "$_PA_TAG" "$3"
}

_pa_has() {                               # <ipt> <proto> <from> <to>
  # shellcheck disable=SC2046
  "$1" -w -t nat -C PREROUTING $(_pa_rule "$2" "$3" "$4") >/dev/null 2>&1
}

_pa_add() {                               # <ipt> <proto> <from> <to>
  _pa_has "$@" && return 0
  # shellcheck disable=SC2046
  "$1" -w -t nat -I PREROUTING 1 $(_pa_rule "$2" "$3" "$4") >/dev/null 2>&1
}

# Every rule this module owns, as the exact `-A PREROUTING ...` lines iptables prints.
_pa_owned_lines() {                       # <ipt>
  "$1" -w -t nat -S PREROUTING 2>/dev/null | grep -F -- "$_PA_TAG"
}

_pa_line_key() {                          # <"-A PREROUTING ..." line> -> "<proto> <from> <to>"
  printf '%s\n' "$1" | awk '{ for (i = 1; i < NF; i++) {
      if ($i == "-p") p = $(i+1); if ($i == "--dport") f = $(i+1); if ($i == "--to-ports") t = $(i+1) }
    print p, f, t }'
}

_pa_delete_line() {                       # <ipt> <"-A PREROUTING ..." line>
  local line="${2#-A PREROUTING }"
  # shellcheck disable=SC2086
  eval "\"$1\" -w -t nat -D PREROUTING $line" >/dev/null 2>&1
}

_pa_v6_usable() { command -v ip6tables >/dev/null 2>&1 && ip6tables -w -t nat -S PREROUTING >/dev/null 2>&1; }

_pa_ipts() { echo iptables; _pa_v6_usable && echo ip6tables; }

# The rule set that SHOULD be live right now, one "<proto> <from> <to>" per line.
# TCP when the target listens on TCP; UDP additionally when it listens on UDP (QUIC on a
# tls port). Nothing for a pair whose target is not listening — see the header.
_pa_desired() {
  local pair from to
  while IFS= read -r pair; do
    [ -n "$pair" ] || continue
    from="${pair%%:*}"; to="${pair#*:}"
    _pa_listening tcp "$to" && printf 'tcp %s %s\n' "$from" "$to"
    _pa_listening udp "$to" && printf 'udp %s %s\n' "$from" "$to"
  done < <(_pa_pairs)
}

# Make the live rules equal the desired set. Prints nothing; returns 1 if a write failed.
_pa_converge() {
  local ipt proto from to line keep rc=0 desired
  desired="$(_pa_desired)"
  for ipt in $(_pa_ipts); do
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      # Match on the parsed triple, never the text: iptables prints an implicit
      # `-m tcp` the rule was not written with, and a text compare would delete and
      # re-add the redirect on every guard tick.
      keep=0
      printf '%s\n' "$desired" | grep -qxF -- "$(_pa_line_key "$line")" && keep=1
      [ "$keep" = "1" ] || _pa_delete_line "$ipt" "$line" || rc=1
    done < <(_pa_owned_lines "$ipt")
    while read -r proto from to; do
      [ -n "$proto" ] || continue
      if ! _pa_add "$ipt" "$proto" "$from" "$to"; then
        # IPv4 is the contract; an IPv6 nat table that refuses a rule is reported, not fatal.
        [ "$ipt" = "iptables" ] && rc=1
      fi
    done <<<"$desired"
  done
  return $rc
}

# nat sees only the FIRST packet of a connection, so this counts connections, not traffic.
_pa_counter() {                           # <proto> <from> <to> -> connections redirected (IPv4)
  local num=6; [ "$1" = "udp" ] && num=17
  iptables -w -t nat -L PREROUTING -nvx 2>/dev/null | awk -v p="$1" -v n="$num" -v f="dpt:$2 " -v t="ports $3" '
    index($0, "port-alias") && ($4 == p || $4 == n) && index($0, f) && index($0 " ", t " ") { print $1; exit }'
}

# ------------------------------------------------------------------ status ----

mod_status() {
  local pair from to kind st="ABSENT" any=0 bad=0
  local pairs; pairs="$(_pa_pairs)"
  if [ -z "$pairs" ]; then
    printf 'aliases         : none configured\n'
    [ -n "$(_pa_owned_lines iptables)" ] && { printf 'leftover rules  : present\n'; echo "PARTIAL  rules left behind with no alias configured"; return 0; }
    echo "ABSENT  no port alias"
    return 0
  fi
  while IFS= read -r pair; do
    [ -n "$pair" ] || continue
    from="${pair%%:*}"; to="${pair#*:}"; kind="$(_pa_port_kind "$to")"
    local cnt; cnt="$(_pa_counter tcp "$from" "$to")"
    printf '%-6s -> %-6s  target %-6s kind %-5s rule %s%s\n' "$from" "$to" \
      "$(_pa_listening tcp "$to" && echo up || echo DOWN)" "${kind:-?}" \
      "$(_pa_has iptables tcp "$from" "$to" && echo live || echo missing)" \
      "$([ -n "$cnt" ] && printf '  (%s connections since boot/re-add)' "$cnt")"
    if _pa_has iptables tcp "$from" "$to"; then any=1; elif _pa_listening tcp "$to"; then bad=1; fi
    _pa_listening tcp "$from" && printf '        note: %s is still bound by the panel itself — fine, but the alias only takes over once it is removed from the panel\n' "$from"
  done <<<"$pairs"
  _pa_v6_usable || printf 'ipv6            : no usable ip6tables nat table (IPv4 only)\n'
  if [ "$bad" = "1" ]; then st="PARTIAL  a redirect is missing for a listening target"
  elif [ "$any" = "1" ]; then st="APPLIED  old ports redirected"
  else st="PARTIAL  configured, but no target port is listening"
  fi
  echo "$st"
}

# ------------------------------------------------------------------- apply ----

_pa_pick() {
  local stored; stored="$(ht_conf_get aliases "")"
  if [ -n "${PORT_ALIASES:-}" ]; then PA_SPEC="$PORT_ALIASES"; return 0; fi
  if [ ! -t 0 ]; then
    if [ -n "$stored" ]; then PA_SPEC="$stored"; return 0; fi
    err "no alias stored and no terminal to ask on"
    err "run: PORT_ALIASES=8080:2095 hiddify-toolkit apply port-alias"
    return 1
  fi
  printf '\n  Panel ports now:  http %s   tls %s\n\n' \
    "$(_pa_panel_ports http | paste -sd, -)" "$(_pa_panel_ports tls | paste -sd, -)"
  printf '  Enter <old-port>:<new-port>, comma-separated for several (e.g. 8080:2095)%s.\n\n' \
    "$([ -n "$stored" ] && printf ' — empty keeps %s' "$stored")"
  local ans; read -rp "  aliases > " ans
  PA_SPEC="${ans:-$stored}"
  [ -n "$PA_SPEC" ] || { err "nothing entered"; return 1; }
}

mod_apply() {
  local PA_SPEC pairs pair from to kind
  _pa_pick || return 1
  pairs="$(_pa_parse "$PA_SPEC")" || return 1
  [ -n "$pairs" ] || { err "no alias given"; return 1; }
  while IFS= read -r pair; do
    from="${pair%%:*}"; to="${pair#*:}"
    kind="$(_pa_port_kind "$to")"
    if [ -z "$kind" ]; then
      err "$to is not in the panel's http_ports or tls_ports — add it in the panel and apply-config first"
      return 1
    fi
    if [ "$(_pa_port_kind "$from")" = "$kind" ] || [ -z "$(_pa_port_kind "$from")" ]; then :; else
      err "$from and $to are different kinds (http vs tls) — a redirect between them cannot work"
      return 1
    fi
    _pa_listening tcp "$to" || warn "$to is not listening yet — the redirect will appear once it is"
    ok "alias $from -> $to ($kind)"
  done <<<"$pairs"
  ht_conf_set aliases "$(printf '%s' "$pairs" | paste -sd, -)"
  _pa_converge || { err "could not install the redirect rules"; return 1; }
}

mod_verify() {
  local pair from to fail=0
  while IFS= read -r pair; do
    [ -n "$pair" ] || continue
    from="${pair%%:*}"; to="${pair#*:}"
    _pa_listening tcp "$to" || continue
    if ! _pa_has iptables tcp "$from" "$to"; then err "redirect $from -> $to is not live"; fail=1; continue; fi
    # With INPUT DROP (the panel's firewall switch) the TARGET port must be open, since
    # that is the port filter/INPUT sees after the rewrite.
    if iptables -w -S INPUT 2>/dev/null | head -1 | grep -q -- '-P INPUT DROP' &&
       ! iptables -w -S INPUT 2>/dev/null | grep -qE -- "-p tcp (-m tcp )?--dport $to (-m conntrack --ctstate NEW )?-j ACCEPT"; then
      err "firewall is on and does not accept tcp/$to — redirected clients would be dropped"; fail=1
    fi
  done < <(_pa_pairs)
  return $fail
}

mod_revert() {
  local ipt line rc=0
  for ipt in iptables ip6tables; do
    command -v "$ipt" >/dev/null 2>&1 || continue
    while IFS= read -r line; do
      [ -n "$line" ] && { _pa_delete_line "$ipt" "$line" || rc=1; }
    done < <(_pa_owned_lines "$ipt")
  done
  [ "$rc" = "0" ] && ok "redirects removed"
  return $rc
}

mod_reassert() { _pa_converge; }
