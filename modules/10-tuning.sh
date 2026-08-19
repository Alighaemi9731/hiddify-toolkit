# shellcheck shell=bash
# =============================================================================
# hiddify-toolkit module — kernel & network tuning                (id: tuning)
# =============================================================================
# Hiddify ships /opt/hiddify-manager/common/sysctl.conf hardcoded for a small
# VM. Those values never scale when the VM is resized, and every net.netfilter.*
# line in it silently fails at boot (systemd-sysctl runs before nf_conntrack is
# loaded), so the panel asks for nf_conntrack_max=2097152 and the running kernel
# quietly stays at the 262144 default.
#
# PERSISTENCE — the whole trick is FILENAME ORDERING.
#   common/install.sh (every apply-config, every update, @reboot) does
#     ln -sf .../sysctl.conf /etc/sysctl.d/hiddify.conf && sysctl --system
#   and `sysctl --system` applies /etc/sysctl.d/* in filename order, LAST WINS.
#   Our competitors there are hiddify.conf (h) and wg.conf (w); we are
#   zz-hiddify-tuning.conf (z) and therefore always land last. Rename this file
#   to anything sorting earlier and every value in it is silently lost.
#   /etc/sysctl.conf is applied dead last by procps and today sets only
#   default_qdisc/tcp_congestion_control — any NEW key added here must be
#   checked against it or that key never takes effect.
#
# Every path the standalone apply-tuning.sh wrote is byte-identical here, so a
# box that was tuned by hand is ADOPTED, not double-tuned. The one path that
# script never had — /etc/modprobe.d/zz-hiddify-tuning.conf, the conntrack hash
# size — is deliberately kept OUT of the mod_status score for the same reason:
# scoring it would report PARTIAL on every hand-tuned box, and the core only
# adopts (and therefore only guards) a box that reports APPLIED.
# =============================================================================

# shellcheck disable=SC2034  # MOD_* are consumed by the core after sourcing
MOD_ID="tuning"
MOD_TITLE="Kernel & network tuning"
MOD_DESC="Re-computes tcp_mem / TIME_WAIT / conntrack / file-max / backlogs / ephemeral ports from this box's real RAM and CPU, preloads nf_conntrack so the netfilter values actually apply, spreads NIC softirq over every core (RPS/RFS), adds the logrotate Hiddify ships without, and neutralises the hiddify-cli crash loop."
MOD_GUARD=yes

TUN_SYSCTL_FILE=/etc/sysctl.d/zz-hiddify-tuning.conf
TUN_MODULES_FILE=/etc/modules-load.d/zz-hiddify-tuning.conf
TUN_RPS_SCRIPT=/usr/local/sbin/hiddify-rps.sh
TUN_RPS_UNIT=/etc/systemd/system/hiddify-rps.service
TUN_LOGROTATE=/etc/logrotate.d/hiddify-manager
TUN_CLI_DIR=/opt/hiddify-manager/other/hiddify-cli
TUN_CLI_DROPIN_DIR=/etc/systemd/system/hiddify-cli.service.d
TUN_CLI_DROPIN=/etc/systemd/system/hiddify-cli.service.d/zz-disable.conf
TUN_ERRLOG=/opt/hiddify-manager/log/system/hiddify_panel.err.log
TUN_LOGDIR=/opt/hiddify-manager/log/system
# /etc/modules-load.d/ can name a module but cannot pass it PARAMETERS, and
# nf_conntrack's hash table size is a module parameter. Hence a second file.
TUN_MODPROBE_FILE=/etc/modprobe.d/zz-hiddify-tuning.conf

# Size of the GLOBAL RFS flow table (net.core.rps_sock_flow_entries). Must be a
# power of two, and it must stay >= the SUM of the per-queue rps_flow_cnt
# values. That sum is per-QUEUE, so the boot script divides this by the number
# of rx queues; writing the whole value into every queue on a 4-queue NIC makes
# the sum 4x the global table and RFS silently degrades to plain RPS with no
# error anywhere. See Documentation/networking/scaling.rst.
TUN_RFS_ENTRIES=32768

# Spin-loop threshold for the panel err log: 100 KiB/s. Normal logging is a few
# bytes/s; the EPIPE loop measured 4.0 MB/s (14 GB/hour) on s4.
TUN_SPIN_BPS=102400

# -----------------------------------------------------------------------------
# detection + scaling
# -----------------------------------------------------------------------------

# Sets every TUN_* derived value. Called by each entry point, because the core
# sources this module into a fresh subshell per call — nothing survives between
# mod_apply and mod_verify.
_tun_derive() {
  TUN_NIC="$(ip -o route show default 2>/dev/null | awk '{print $5; exit}')" || TUN_NIC=""
  if [ -z "${TUN_NIC:-}" ]; then
    TUN_NIC="$(ip -o link show 2>/dev/null | awk -F': ' '$2!="lo"{print $2; exit}')" || TUN_NIC=""
  fi
  TUN_NCPU="$(nproc 2>/dev/null)" || TUN_NCPU=""
  [ -n "$TUN_NCPU" ] || TUN_NCPU=1
  TUN_RAM_KB="$(awk '/MemTotal/{print $2; exit}' /proc/meminfo 2>/dev/null)" || TUN_RAM_KB=""
  [ -n "$TUN_RAM_KB" ] || { err "cannot read MemTotal from /proc/meminfo"; return 1; }
  TUN_PAGE="$(getconf PAGESIZE 2>/dev/null)" || TUN_PAGE=""
  [ -n "$TUN_PAGE" ] || TUN_PAGE=4096
  TUN_RAM_MB=$(( TUN_RAM_KB / 1024 ))
  TUN_RAM_PAGES=$(( TUN_RAM_KB * 1024 / TUN_PAGE ))

  # tcp_mem is in PAGES (low/pressure/max). Hiddify pins 25600/51200/102400
  # (100/200/400 MB) on every box regardless of RAM. 10% / 13% / 20%.
  TUN_TCP_MEM_LOW=$(( TUN_RAM_PAGES * 10 / 100 ))
  TUN_TCP_MEM_PRESSURE=$(( TUN_RAM_PAGES * 13 / 100 ))
  TUN_TCP_MEM_MAX=$(( TUN_RAM_PAGES * 20 / 100 ))

  # TIME_WAIT sockets are ~200 bytes each; Hiddify pins 5000, which pegs at a
  # few hundred new conns/sec. Cap first, then floor — 262144 is ~52 MB.
  TUN_TW_BUCKETS=$(( TUN_RAM_MB * 32 ))
  if [ "$TUN_TW_BUCKETS" -gt 262144 ]; then TUN_TW_BUCKETS=262144; fi
  if [ "$TUN_TW_BUCKETS" -lt 32768 ];  then TUN_TW_BUCKETS=32768;  fi

  # conntrack entry ~300 bytes. Cap at 1M (~300 MB) so the table alone can
  # never OOM the box.
  TUN_CT_MAX=$(( TUN_RAM_MB * 64 ))
  if [ "$TUN_CT_MAX" -gt 1048576 ]; then TUN_CT_MAX=1048576; fi
  if [ "$TUN_CT_MAX" -lt 262144 ];  then TUN_CT_MAX=262144;  fi

  # Hiddify pins fs.file-max at 200000 — LOWER than the per-process LimitNOFILE
  # it grants haproxy (524288) and xray (infinity). The system-wide cap binds
  # first, so "Too many open files in system" takes down every service at once.
  TUN_FILE_MAX=$(( TUN_RAM_MB * 256 ))
  if [ "$TUN_FILE_MAX" -gt 2000000 ]; then TUN_FILE_MAX=2000000; fi
  if [ "$TUN_FILE_MAX" -lt 200000 ];  then TUN_FILE_MAX=200000;  fi

  _tun_scrape_reserved
  return 0
}

# HAProxy binds FIXED sp_special_reality_tcp_<port> ports that live INSIDE the
# ephemeral range. If an outbound socket grabs one while HAProxy is restarting,
# HAProxy cannot bind and that inbound dies. Only 32768-65535 can be stolen.
#
# haproxy.cfg is NOT the whole story, and believing it was is the scariest thing
# that was ever in this file. We raise the ephemeral ceiling from Ubuntu's 60999
# to 65535, which newly exposes 61000-65535 to ephemeral allocation, and
# ip_local_reserved_ports is consulted for UDP as much as for TCP. On these
# boxes that band holds sshd-on-a-high-port, the WireGuard UDP port and the
# hysteria2/tuic ports — none of which appear in haproxy.cfg. Lose the race for
# one of them and the service cannot re-bind on its next restart; lose it for
# sshd and you have lost the box. So the scrape is UNIONED with what is
# actually listening right now.
#
# The union is also MONOTONIC: every port ever seen is remembered in the module
# conf. That is not hoarding. `ss -lu` can catch a short-lived UNCONN socket,
# and without the memory that port would land in the sysctl file on one reassert
# and vanish on the next — rewriting a generated file every 2 minutes, which is
# the one thing every body in this module is shaped to avoid. Reserving a stray
# port out of 32768 costs nothing; a rewrite storm costs the whole design.
# Prune by clearing `reserved_seen=` in this module's conf.
#
# The `|| x=""` on every capture is not decoration: under `set -o pipefail` a
# no-match grep fails the whole assignment, and the standalone script aborted
# right there.
_tun_scrape_reserved() {
  local from_cfg="" from_tcp="" from_udp="" seen=""
  TUN_RESERVED=""

  if [ -f /opt/hiddify-manager/haproxy/haproxy.cfg ]; then
    # [a-zA-Z0-9_]* — the original [a-z_]* excluded DIGITS, so a listener named
    # sp_special_h2_tcp_49658 quietly never made it into the reserved list.
    from_cfg="$(grep -oE 'sp_special[a-zA-Z0-9_]*_[0-9]{4,5}' \
        /opt/hiddify-manager/haproxy/haproxy.cfg 2>/dev/null \
      | grep -oE '[0-9]{4,5}$')" || from_cfg=""
  fi

  # TCP: LISTEN only. A LISTEN socket IS a server socket by definition, so this
  # catches sshd-on-a-high-port and every panel listener and can never catch a
  # transient one. Test $1=="tcp" rather than dropping -u, because without -u the
  # Netid column disappears and the local address moves from $5 to $4.
  from_tcp="$(ss -Hlntu 2>/dev/null | awk '$1=="tcp"{print $5}' | sed 's/.*://' \
    | grep -oE '^[0-9]+$')" || from_tcp=""

  # UDP has NO listen state: `ss -lu` reports every UNCONNECTED socket, and on a box
  # relaying UDP that includes the per-session socket sing-box/hysteria opens at an
  # ephemeral port (ListenPacket), plus chrony's client port and warp's source port.
  # Unioning those into a set we then REMEMBER FOREVER grew the reserved list without
  # bound and rewrote this module's generated sysctl file on EVERY 2-minute tick —
  # measured at ~3 new ports/tick, 628 reserved on a live box inside a day. So read
  # the UDP side from CONFIGURATION, which is stable by construction.
  from_udp="$( { wg show all listen-port 2>/dev/null | awk '{print $NF}'
      grep -rhoE 'ListenPort[[:space:]]*=[[:space:]]*[0-9]+' /etc/wireguard 2>/dev/null
      grep -rhoE '"listen_port"[[:space:]]*:[[:space:]]*[0-9]+' \
        /opt/hiddify-manager/singbox /opt/hiddify-manager/xray 2>/dev/null
      # Load-bearing `:` — under `set -o pipefail` the GROUP's status is the last
      # grep's, and a no-match there would fail the whole substitution and send the
      # `|| from_udp=""` below straight over ports we did find.
      :
    } | grep -oE '[0-9]+$')" || from_udp=""

  seen="$(ht_conf_get reserved_seen '' | tr ',' '\n')" || seen=""

  # head -256 is a backstop, not sizing: a reserved list that grows without bound
  # rewrites the generated file on every tick and eventually overruns the fixed line
  # buffer procps `sysctl -p` reads each line into — and it fails asymmetrically,
  # because systemd's boot-time parser has no such limit.
  TUN_RESERVED="$(printf '%s\n%s\n%s\n%s\n' "$from_cfg" "$from_tcp" "$from_udp" "$seen" \
    | grep -E '^[0-9]+$' | sort -un \
    | awk '$1>=32768 && $1<=65535' | head -256 | paste -sd, -)" || TUN_RESERVED=""
  return 0
}

# Persisted ONLY from the paths that write the sysctl file (apply, reassert) —
# never from mod_status, which must not mutate state to make its own output true.
_tun_remember_reserved() {
  [ -n "${TUN_RESERVED:-}" ] || return 0
  [ "$TUN_RESERVED" = "$(ht_conf_get reserved_seen '')" ] && return 0
  ht_conf_set reserved_seen "$TUN_RESERVED"
  return 0
}

# CPU bitmap for sysfs. `printf '%x' $(((1<<NCPU)-1))` — what the standalone
# script used — is wrong twice above 32 CPUs: 64-bit shift overflow, and sysfs
# wants 32-bit words separated by commas ("ffffffff,ffffffff"), not one long
# hex run. Build it a nibble at a time instead, so no arithmetic can overflow.
_tun_cpu_mask() {                     # <ncpu> -> e.g. "f" / "ff" / "ffffffff,ffffffff"
  local n="${1:-1}" full=0 rem=0 s="" out="" i=0
  full=$(( n / 4 )); rem=$(( n % 4 ))
  case "$rem" in 1) s="1" ;; 2) s="3" ;; 3) s="7" ;; esac
  for (( i = 0; i < full; i++ )); do s="${s}f"; done
  [ -n "$s" ] || s="0"
  while [ "${#s}" -gt 8 ]; do
    out=",${s: -8}${out}"
    s="${s:0:${#s}-8}"
  done
  printf '%s%s\n' "$s" "$out"
  return 0
}

# The kernel pads its printed mask to nr_cpu_ids width (which is not nproc) and
# groups it with commas, so string equality against our generated form is a
# false-mismatch machine. Compare normalised values only.
_tun_norm_mask() {
  local v="${1//,/}"
  v="$(printf '%s' "$v" | tr '[:upper:]' '[:lower:]')"
  v="${v#"${v%%[!0]*}"}"
  [ -n "$v" ] || v="0"
  printf '%s\n' "$v"
  return 0
}

# -----------------------------------------------------------------------------
# file bodies (deterministic — see _tun_install_file)
# -----------------------------------------------------------------------------

_tun_modules_body() {
  cat <<'EOS'
# managed by hiddify-toolkit (module: tuning) — DO NOT EDIT BY HAND
# net.netfilter.* sysctls silently fail at boot because systemd-sysctl.service
# runs before nf_conntrack is loaded (it loads later, with the iptables rules).
# systemd-modules-load.service is ordered Before=systemd-sysctl.service, so
# naming the module here is what makes those settings stick on every boot.
nf_conntrack
EOS
  return 0
}

# NOTE: no timestamp, no hostname, nothing per-run. The body must be a pure
# function of (RAM, CPUs, reserved ports) or mod_reassert cannot tell "drifted"
# from "regenerated", and the guard would rewrite this file every 2 minutes.
_tun_sysctl_body() {
  cat <<EOS
# =============================================================================
# managed by hiddify-toolkit (module: tuning) — DO NOT EDIT BY HAND
#
# The filename MUST sort after hiddify.conf and wg.conf in /etc/sysctl.d/, so
# that Hiddify's own 'sysctl --system' (common/install.sh, on every install,
# update and @reboot) re-applies these values LAST. Never rename to a lower
# prefix; never edit /opt/hiddify-manager/common/sysctl.conf (updates wipe it).
#
# Sized for: ${TUN_RAM_MB}MB RAM / ${TUN_NCPU} vCPU
# =============================================================================

# --- TCP memory ceiling ------------------------------------------------------
# Hiddify pins 25600/51200/102400 pages (100/200/400MB) on EVERY box, so
# rescaling the VM does nothing for it. Symptom when too low:
# TCPMemoryPressuresChrono climbing, PruneCalled / TCPRcvQDrop / TCPOFODrop.
net.ipv4.tcp_mem = ${TUN_TCP_MEM_LOW} ${TUN_TCP_MEM_PRESSURE} ${TUN_TCP_MEM_MAX}

# --- TIME_WAIT ---------------------------------------------------------------
# Hiddify pins 5000; ~500 new conns/sec steady state needs ~30k.
# Symptom when too low: TCPTimeWaitOverflow in the hundreds/sec, SYN retrans.
net.ipv4.tcp_max_tw_buckets = ${TUN_TW_BUCKETS}

# --- accept / SYN queues (headroom; harmless if never hit) -------------------
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# --- ephemeral ports ---------------------------------------------------------
# Widened UPWARD only. Do NOT lower the floor to 1024: Hiddify binds fixed
# services at 1234/2000/2039/3306/6379/8181/9000/10085/10086/17078 and an
# ephemeral socket stealing one breaks that service on its next restart.
net.ipv4.ip_local_port_range = 32768 65535
EOS
  if [ -n "${TUN_RESERVED:-}" ]; then
    cat <<EOS

# Fixed HAProxy reality ports that live inside the ephemeral range.
net.ipv4.ip_local_reserved_ports = ${TUN_RESERVED}
EOS
  fi
  cat <<EOS

# --- file descriptors --------------------------------------------------------
# Hiddify pins 200000, BELOW the per-process LimitNOFILE it grants haproxy
# (524288) and xray (infinity) — so the system-wide cap binds first and
# 'Too many open files in system' takes down every service at once.
fs.file-max = ${TUN_FILE_MAX}

# --- conntrack ---------------------------------------------------------------
# These only apply because nf_conntrack is preloaded via
# /etc/modules-load.d/zz-hiddify-tuning.conf.
net.netfilter.nf_conntrack_max = ${TUN_CT_MAX}
# Kernel default is 432000 (5 DAYS) — dead entries accumulate until the table
# fills and the kernel starts dropping packets. 24h is ample.
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
EOS
  if [ "$(ht_conf_get rps yes)" != "no" ]; then
    cat <<EOS

# --- RFS (flow table; the per-queue half is set by hiddify-rps.service) ------
net.core.rps_sock_flow_entries = ${TUN_RFS_ENTRIES}
EOS
  fi
  return 0
}

_tun_rps_script_body() {
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    '# managed by hiddify-toolkit (module: tuning) — DO NOT EDIT BY HAND' \
    "RFS_ENTRIES=${TUN_RFS_ENTRIES}"
  cat <<'EOS'
# virtio NICs on nearly every VPS expose exactly ONE rx queue (ethtool -l ->
# "Combined: 1", pre-set maximum also 1), so ALL packet processing lands on the
# single CPU taking the IRQ no matter how many vCPUs are bought. That is why
# "rescaling the VM didn't help". RPS fans that work out in software.
#
# rps_cpus / rps_flow_cnt / xps_cpus are sysfs: wiped on every boot and every
# NIC re-init. Hence a unit, not a sysctl file.
#
# NIC, CPU count and mask are recomputed HERE, at boot, so a VM rescale is
# picked up without re-running the toolkit.
set -u
NIC="$(ip -o route show default 2>/dev/null | awk '{print $5; exit}')"
# Same fallback as _tun_derive in the module. Without it, a box with no IPv4
# default route resolves a NIC module-side, expects a mask on it, and gets none
# here — mod_verify then fails and the core auto-reverts the entire healthy
# sysctl layer over a cosmetic RPS mismatch. The two must agree or they fight.
if [ -z "${NIC:-}" ]; then
  NIC="$(ip -o link show 2>/dev/null | awk -F': ' '$2!="lo"{print $2; exit}')"
fi
[ -n "${NIC:-}" ] || exit 0
NCPU="$(nproc 2>/dev/null)" || NCPU=1
[ -n "$NCPU" ] || NCPU=1

full=$(( NCPU / 4 )); rem=$(( NCPU % 4 )); m=""
case "$rem" in 1) m="1" ;; 2) m="3" ;; 3) m="7" ;; esac
for (( i = 0; i < full; i++ )); do m="${m}f"; done
[ -n "$m" ] || m="0"
# Above 32 CPUs sysfs wants comma-separated 32-bit words, and a plain
# `printf '%x' $(((1<<NCPU)-1))` would have overflowed long before that.
out=""
while [ "${#m}" -gt 8 ]; do
  out=",${m: -8}${out}"
  m="${m:0:${#m}-8}"
done
MASK="${m}${out}"

# Count the rx queues. rps_sock_flow_entries is ONE table shared by all of them,
# so rps_flow_cnt has to be RFS_ENTRIES/N per queue: write the full value into
# every queue of a 4-queue NIC and the sum is 4x the global table, at which
# point RFS quietly stops being RFS and degrades to plain RPS. Nothing logs it,
# nothing errors — you only see it as flows landing on the wrong CPU.
QN=0
for q in /sys/class/net/"$NIC"/queues/rx-*; do [ -d "$q" ] && QN=$(( QN + 1 )); done
[ "$QN" -ge 1 ] || QN=1

# The whole premise of this unit is the SINGLE-queue virtio NIC that pins all
# packet work on one core. A NIC with a queue per CPU already spreads rx in
# hardware, with its own per-queue IRQ affinity; forcing an all-CPU rps_cpus on
# top of that buys nothing but softirq redirection and cross-CPU IPIs — on a
# module whose entire purpose is throughput. Leave it alone.
if [ "$QN" -gt 1 ] && [ "$QN" -ge "$NCPU" ]; then
  exit 0
fi

# Floor to a power of two. The kernel ROUNDS UP whatever it is handed, so
# rounding up here (or leaving a non-power-of-two) puts the sum straight back
# above the global table.
PER=$(( RFS_ENTRIES / QN ))
p=1
while [ $(( p * 2 )) -le "$PER" ]; do p=$(( p * 2 )); done
PER="$p"

for q in /sys/class/net/"$NIC"/queues/rx-*; do
  [ -e "$q/rps_cpus" ]     && printf '%s' "$MASK" > "$q/rps_cpus"     2>/dev/null
  [ -e "$q/rps_flow_cnt" ] && printf '%s' "$PER"  > "$q/rps_flow_cnt" 2>/dev/null
done
for q in /sys/class/net/"$NIC"/queues/tx-*; do
  [ -e "$q/xps_cpus" ] && printf '%s' "$MASK" > "$q/xps_cpus" 2>/dev/null
done
# Load-bearing: without it the oneshot inherits the last [ -e ] test's status,
# and a NIC with no tx-* knob would leave the unit sitting in `failed`.
exit 0
EOS
  return 0
}

# nf_conntrack_max on its own only lengthens every hash chain: the bucket count
# is fixed at module LOAD time (~65536 by default), so at 1M conntracks the
# average chain goes from 4 entries to 16 and every lookup pays for it. The
# kernel's own ratio is 1 bucket per 4 entries. modules-load.d cannot carry
# parameters, so the size for the next boot lives here.
_tun_modprobe_body() {
  cat <<EOS
# managed by hiddify-toolkit (module: tuning) — DO NOT EDIT BY HAND
# Bucket count for the conntrack hash table, sized 1:4 against
# net.netfilter.nf_conntrack_max = ${TUN_CT_MAX} (see zz-hiddify-tuning.conf).
# Applies at module load; the running kernel is set once, at apply time, via
# /sys/module/nf_conntrack/parameters/hashsize (that write REALLOCATES the
# table, which is why it is never done from the 2-minute reassert).
options nf_conntrack hashsize=$(( TUN_CT_MAX / 4 ))
EOS
  return 0
}

_tun_rps_unit_body() {
  cat <<'EOS'
# managed by hiddify-toolkit (module: tuning) — DO NOT EDIT BY HAND
[Unit]
Description=Hiddify RPS/RFS tuning (spread NIC softirq across all CPUs)
Documentation=man:hiddify-toolkit(8)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/hiddify-rps.sh

[Install]
WantedBy=multi-user.target
EOS
  return 0
}

_tun_logrotate_body() {
  cat <<'EOS'
# managed by hiddify-toolkit (module: tuning) — DO NOT EDIT BY HAND
# Hiddify ships NO rotation for these. One stuck client socket puts the panel in
# an EPIPE loop that wrote >14 GB/hour on s4 and filled a 38 GB disk on s6.
#
# copytruncate is MANDATORY: the panel holds these fds open and never reopens
# them on SIGHUP, so rename-based rotation orphans the fd and reclaims nothing.
/opt/hiddify-manager/log/system/*.log {
    size 100M
    rotate 3
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOS
  return 0
}

_tun_cli_dropin_body() {
  cat <<'EOS'
# managed by hiddify-toolkit (module: tuning) — DO NOT EDIT BY HAND
# Neutralises the hiddify-cli crash loop (corrupt LevelDB after a hard power-off
# plus "unknown load balance strategy" from the config it regenerates from
# SUB_LINK on every start — repairing the DB alone never stops it).
#
# `systemctl disable` does NOT hold: other/hiddify-cli/install.sh re-creates the
# unit symlink and re-runs `systemctl enable` unconditionally on every
# apply-config (observed: disabled at 458 restarts, back at 1,162 the next day).
# A drop-in survives because install.sh replaces the .service FILE and never
# touches the .service.d/ DIRECTORY. A failed Condition makes systemd SKIP the
# unit (inactive, not failed) and Restart= does not fire on condition failures.
#
# The clean permanent fix is the panel setting: hiddifycli_enable = false.
[Unit]
ConditionPathExists=/nonexistent-hiddify-cli-disabled-by-tuning
EOS
  return 0
}

# -----------------------------------------------------------------------------
# small helpers
# -----------------------------------------------------------------------------

# Only ever delete or overwrite a file we can prove is ours. A hand-written
# /etc/logrotate.d/hiddify-manager from a previous admin must survive a revert.
# The legacy standalone script's marker counts as ours — same fix, same paths.
_tun_is_ours() {
  [ -f "$1" ] || return 1
  grep -qiE 'managed by (hiddify-toolkit|apply-tuning\.sh)' "$1" 2>/dev/null
}

# 0 = written (content changed), 1 = already current, 2 = write failed.
_tun_install_file() {                 # <path> <mode> <content>
  local path="$1" mode="$2" content="$3" cur=""
  if [ -f "$path" ]; then cur="$(cat "$path" 2>/dev/null)" || cur=""; fi
  if [ "$cur" = "$content" ]; then return 1; fi
  printf '%s\n' "$content" > "$path" || return 2
  chmod "$mode" "$path" 2>/dev/null || true
  return 0
}

# sysctl prints tcp_mem and ip_local_port_range TAB-separated; normalise or
# every comparison against a space-joined expectation is a false mismatch.
_tun_sysctl_get() {                   # <key> -> normalised value on stdout
  local v
  v="$(sysctl -n "$1" 2>/dev/null)" || return 1
  v="$(printf '%s' "$v" | tr -s '[:space:]' ' ')"
  v="${v% }"
  printf '%s\n' "$v"
  return 0
}

_tun_match() {                        # <key> <expected>
  local got
  got="$(_tun_sysctl_get "$1")" || return 1
  [ "$got" = "$2" ]
}

_tun_has_conntrack() { [ -e /proc/sys/net/netfilter/nf_conntrack_max ]; }

_tun_hashsize_want() { printf '%s\n' "$(( TUN_CT_MAX / 4 ))"; }

# APPLY-TIME ONLY. Writing this file makes the kernel allocate a new hash table
# and rehash every live conntrack into it — cheap enough once, absolutely not
# something to do from a job that runs every 2 minutes. Never shrinks: a smaller
# table pays the same rehash cost for a worse table.
_tun_set_hashsize() {
  local p=/sys/module/nf_conntrack/parameters/hashsize cur="" want=""
  want="$(_tun_hashsize_want)"
  if [ ! -w "$p" ]; then
    warn "no writable $p — hash size will apply on the next nf_conntrack load"
    return 0
  fi
  cur="$(cat "$p" 2>/dev/null)" || cur=""
  case "$cur" in ''|*[!0-9]*) cur=0 ;; esac
  if [ "$cur" -ge "$want" ]; then
    ok "conntrack hash buckets already $cur (want $want)"
    return 0
  fi
  if printf '%s' "$want" > "$p" 2>/dev/null; then
    ok "conntrack hash buckets ${cur} -> ${want} (running kernel)"
  else
    warn "could not set conntrack hash buckets — left at ${cur}"
  fi
  return 0
}

# Quiet whole-kernel check used by status and reassert.
_tun_core_ok() {
  _tun_match net.ipv4.tcp_mem "$TUN_TCP_MEM_LOW $TUN_TCP_MEM_PRESSURE $TUN_TCP_MEM_MAX" || return 1
  _tun_match net.ipv4.tcp_max_tw_buckets "$TUN_TW_BUCKETS" || return 1
  _tun_match net.core.somaxconn 65535 || return 1
  _tun_match net.ipv4.tcp_max_syn_backlog 65535 || return 1
  _tun_match net.ipv4.ip_local_port_range "32768 65535" || return 1
  _tun_match fs.file-max "$TUN_FILE_MAX" || return 1
  if _tun_has_conntrack; then
    _tun_match net.netfilter.nf_conntrack_max "$TUN_CT_MAX" || return 1
    _tun_match net.netfilter.nf_conntrack_tcp_timeout_established 86400 || return 1
  fi
  return 0
}

_tun_rps_wanted() { [ "$(ht_conf_get rps yes)" != "no" ]; }

# How many rx queues the NIC exposes. Nothing in the standalone script ever
# counted them; it just asserted "virtio has one" and wrote as if that were
# always true.
_tun_rx_queues() {                    # -> count (never below 1)
  local q="" n=0
  for q in /sys/class/net/"${TUN_NIC:-}"/queues/rx-*; do
    [ -d "$q" ] && n=$(( n + 1 ))
  done
  [ "$n" -ge 1 ] || n=1
  printf '%s\n' "$n"
  return 0
}

# True when the hardware already spreads rx over every CPU, which is the case
# where hiddify-rps.sh deliberately does NOTHING. Status and verify MUST use the
# same test as the boot script: if they disagree, a multiqueue box fails verify
# and the core auto-reverts an otherwise perfect sysctl layer over a mask that
# was never meant to be set.
_tun_rps_hw_covered() {
  local qn=""
  qn="$(_tun_rx_queues)"
  [ "$qn" -gt 1 ] && [ "$qn" -ge "${TUN_NCPU:-1}" ]
}

# The same arithmetic hiddify-rps.sh does, kept here so status/verify can print
# the real per-queue value instead of the global one. Power-of-two FLOOR: the
# kernel rounds up, and the sum of these must not exceed TUN_RFS_ENTRIES.
_tun_flow_cnt_per_queue() {
  local qn="" per=0 p=1
  qn="$(_tun_rx_queues)"
  per=$(( TUN_RFS_ENTRIES / qn ))
  while [ $(( p * 2 )) -le "$per" ]; do p=$(( p * 2 )); done
  printf '%s\n' "$p"
  return 0
}

_tun_rps_ok() {
  local f="/sys/class/net/${TUN_NIC:-}/queues/rx-0/rps_cpus" want="" got=""
  # No RPS knob at all (container, exotic driver) — nothing to enforce, and
  # failing here would auto-revert a perfectly good sysctl layer.
  [ -e "$f" ] || return 0
  # Multiqueue NIC: hiddify-rps.sh exits before touching anything, so there is
  # no mask to compare against. Same reasoning as the line above.
  _tun_rps_hw_covered && return 0
  want="$(_tun_norm_mask "$(_tun_cpu_mask "$TUN_NCPU")")"
  got="$(_tun_norm_mask "$(cat "$f" 2>/dev/null || echo 0)")"
  [ "$want" = "$got" ]
}

# -----------------------------------------------------------------------------
# baseline (the rollback contract)
# -----------------------------------------------------------------------------

_tun_baseline_file() { printf '%s/sysctl-before.txt\n' "$(ht_backup_dir)"; }

# The OLDEST /root/tuning-backup-*/sysctl-before.txt the standalone apply-tuning.sh
# left behind. Oldest, because that script wrote a fresh directory on every run
# and only the first one holds pristine values.
_tun_legacy_baseline() {              # -> path on stdout, 1 if there is none
  local legacy=""
  legacy="$(find /root -maxdepth 1 -type d -name 'tuning-backup-*' 2>/dev/null | sort | head -1)" || legacy=""
  [ -n "$legacy" ] || return 1
  [ -f "$legacy/sysctl-before.txt" ] || return 1
  printf '%s\n' "$legacy/sysctl-before.txt"
  return 0
}

# WHERE THE PRISTINE VALUES LIVE — resolved on the READ path, not only when we
# capture. This matters because of a path that does not go through mod_apply at
# all: the core's ht_adopt_applied() marks any module whose mod_status says
# APPLIED as enabled, so it gets a guard — and a box tuned by the old standalone
# script reports exactly that. Adoption never runs mod_apply, so it never ran
# _tun_capture_baseline either. Resolve only at capture time and revert on such
# a box removes the files, prints "reverted", and leaves tcp_mem, file-max,
# tw_buckets, conntrack_max and the widened port range live until the next
# reboot — while the real pristine values sit in /root/tuning-backup-* the whole
# time. Ask here, every time.
_tun_baseline_source() {              # -> a replayable baseline file, 1 if none
  local bf=""
  bf="$(_tun_baseline_file)"
  [ -f "$bf" ] && { printf '%s\n' "$bf"; return 0; }
  _tun_legacy_baseline
}

# 0 = captured now, 1 = already had one (never re-capture), 2 = failed.
# Pass "adopt" to take a legacy baseline ONLY and never snapshot the live kernel.
#
# The standalone script wrote a NEW /root/tuning-backup-<ts>/ on every run, so a
# second apply captured the ALREADY-TUNED values and `rollback-tuning.sh` with
# no argument then "restored" the tuning it was meant to remove. Capture once,
# and when this box was already tuned by that script, adopt its OLDEST baseline
# instead of recording the tuned kernel as pristine.
_tun_capture_baseline() {             # [adopt]
  local mode="${1:-apply}" bf="" legacy="" k=""
  bf="$(_tun_baseline_file)"
  [ -f "$bf" ] && return 1

  if [ -f "$TUN_SYSCTL_FILE" ] || [ "$mode" = "adopt" ]; then
    legacy="$(_tun_legacy_baseline)" || legacy=""
    if [ -n "$legacy" ]; then
      cp -a "$legacy" "$bf" || return 2
      ht_conf_set baseline_source "$legacy"
      ok "baseline adopted from $legacy (this box was already tuned by hand)"
      return 0
    fi
    # Adoption stops here on purpose. The live kernel on an adopted box holds
    # the TUNED values; recording those as "pristine" would make revert a
    # no-op that prints success — strictly worse than having no baseline, which
    # at least says so out loud in mod_status.
    [ "$mode" = "adopt" ] && return 1
    # Same argument as the paragraph above, and it does not stop at adopt mode:
    # reaching here at all means the box is ALREADY tuned (our file is on disk)
    # while we hold no baseline, so the live kernel IS the tuned kernel. Snapshot
    # it and revert silently becomes a no-op that reports success, while
    # mod_status starts printing a confident "baseline: <path> (source=live)" over
    # it. Record nothing — mod_status then keeps saying NONE, which is the truth.
    warn "already tuned by hand and no pristine baseline survives — recording none"
    warn "  revert can remove our files but cannot restore the previous values"
    return 1
  fi

  # The `key = value` / `# rps_cpus = ` layout IS the parsing contract of
  # _tun_restore_baseline. Do not prettify it (aligned columns, tabs) — the
  # replay parser splits on the first ' =' and the first '= '.
  {
    echo "# hiddify-toolkit tuning baseline  $(date -Is)"
    echo "# host=$(hostname)  NIC=${TUN_NIC}  CPUs=${TUN_NCPU}  RAM=${TUN_RAM_MB}MB"
    for k in net.ipv4.tcp_mem net.ipv4.tcp_max_tw_buckets net.core.somaxconn \
             net.ipv4.tcp_max_syn_backlog net.ipv4.ip_local_port_range \
             net.ipv4.ip_local_reserved_ports fs.file-max \
             net.core.rps_sock_flow_entries net.netfilter.nf_conntrack_max \
             net.netfilter.nf_conntrack_tcp_timeout_established \
             net.netfilter.nf_conntrack_tcp_timeout_time_wait \
             net.netfilter.nf_conntrack_tcp_timeout_fin_wait \
             net.netfilter.nf_conntrack_tcp_timeout_close_wait; do
      printf '%s = %s\n' "$k" "$(sysctl -n "$k" 2>/dev/null || echo UNSET)"
    done
    printf '# rps_cpus = %s\n' \
      "$(cat "/sys/class/net/${TUN_NIC}/queues/rx-0/rps_cpus" 2>/dev/null || echo NA)"
  } > "$bf" || return 2
  ht_conf_set baseline_source live
  ok "baseline -> $bf"
  return 0
}

_tun_restore_baseline() {
  local bf="" line="" key="" val="" old_rps="" q=""
  bf="$(_tun_baseline_source)" || {
    warn "no baseline anywhere (ours or /root/tuning-backup-*) — files removed,"
    warn "  running values left as they are until the next reboot"
    return 1
  }
  ok "replaying baseline from $bf"
  while IFS= read -r line; do
    case "$line" in '#'*) continue ;; esac
    [ -n "${line// /}" ] || continue
    key="${line%% =*}"
    val="${line#*= }"
    # A key that did not exist at capture time (net.netfilter.* on a box where
    # conntrack was not loaded) must be SKIPPED, not zeroed. It reverts for real
    # at the next boot, once our modules-load file is gone.
    [ "$val" = "UNSET" ] && continue
    sysctl -qw "$key=$val" >/dev/null 2>&1 || warn "could not restore $key"
  done < "$bf"

  # sed, not `grep -oP \K`: PCRE support is a build option and the standalone
  # script's `|| echo ""` swallowed "grep has no -P" as "nothing captured".
  old_rps="$(sed -n 's/^# rps_cpus = //p' "$bf" 2>/dev/null | head -1)" || old_rps=""
  if [ -n "$old_rps" ] && [ "$old_rps" != "NA" ] && [ -n "${TUN_NIC:-}" ]; then
    for q in /sys/class/net/"$TUN_NIC"/queues/rx-*; do
      [ -e "$q/rps_cpus" ]     && printf '%s' "$old_rps" > "$q/rps_cpus"     2>/dev/null
      [ -e "$q/rps_flow_cnt" ] && printf '%s' "0"        > "$q/rps_flow_cnt" 2>/dev/null
    done
  fi
  return 0
}

# -----------------------------------------------------------------------------
# service-touching sections — apply only, NEVER reassert
# -----------------------------------------------------------------------------

# hiddify-cli is a CLIENT that dials out through other servers. On a panel that
# really does chain its egress, disabling it cuts that path — so we act only
# when all three hold: no chained xray outbound, SUB_LINK points at this host,
# and the routing config was actually readable. Every unknown means HANDS OFF.
_tun_cli_guard() {
  local n="" tags="" sub="" chained=no localsub=no t="" flag="" st=""
  n="$(systemctl show hiddify-cli -p NRestarts --value 2>/dev/null)" || n=""
  [ -n "$n" ] || n=0

  # Keyed on the DIRECTORY, not on whether the unit happens to be loaded now:
  # Hiddify re-creates AND re-enables it on any apply-config, so the drop-in has
  # to be placed pre-emptively or a host that looks clean today regresses
  # tomorrow.
  if [ ! -d "$TUN_CLI_DIR" ]; then
    ok "hiddify-cli not installed on this host — nothing to do"
    return 0
  fi
  if [ -f "$TUN_CLI_DROPIN" ]; then
    ok "hiddify-cli already neutralised (drop-in present, restarts=${n})"
    return 0
  fi

  tags="$(python3 -c "
import json
try:
    d=json.load(open('/opt/hiddify-manager/xray/configs/03_routing.json'))
    print(','.join(sorted({r.get('outboundTag') for r in d['routing']['rules'] if r.get('outboundTag')})))
except Exception: print('UNKNOWN')
" 2>/dev/null)" || tags="UNKNOWN"
  # Empty output means the parse produced nothing useful; treat it exactly like
  # UNKNOWN. The standalone script fell through to "no chained outbound" here.
  [ -n "$tags" ] || tags="UNKNOWN"

  sub="$(grep -oE '^SUB_LINK=https?://[^/]+' "$TUN_CLI_DIR/.env" 2>/dev/null | sed 's|SUB_LINK=||')" || sub=""

  local -a taglist=()
  IFS=',' read -ra taglist <<< "$tags"
  for t in "${taglist[@]}"; do
    case "$t" in
      freedom|blackhole|forbidden_sites|DNS-Internal|api|UNKNOWN|"") ;;
      *) chained=yes ;;
    esac
  done
  case "$sub" in *127.0.0.1*|*localhost*) localsub=yes ;; esac

  if [ "$tags" = "UNKNOWN" ] || [ "$chained" = "yes" ] || [ "$localsub" != "yes" ]; then
    warn "hiddify-cli MAY carry real egress here — left completely alone"
    warn "  outboundTags=[${tags}] SUB_LINK=[${sub:-?}] — check by hand"
    return 0
  fi

  mkdir -p "$TUN_CLI_DROPIN_DIR" || { err "cannot create $TUN_CLI_DROPIN_DIR"; return 1; }
  _tun_install_file "$TUN_CLI_DROPIN" 0644 "$(_tun_cli_dropin_body)"
  st="$?"
  if [ "$st" = "2" ]; then err "cannot write $TUN_CLI_DROPIN"; return 1; fi
  systemctl daemon-reload
  systemctl stop hiddify-cli.service >/dev/null 2>&1 || true
  systemctl reset-failed hiddify-cli >/dev/null 2>&1 || true
  # Remembered so revert (and the core's auto-rollback after a failed verify)
  # only ever removes a drop-in THIS module placed. Resurrecting a crash loop
  # somebody else stopped, because an unrelated sysctl key mismatched, is not a
  # rollback — it is an outage.
  ht_conf_set cli_neutralised yes
  ok "hiddify-cli neutralised via drop-in (was ${n} restarts)"

  flag="$(jq -r '.chconfigs["0"].hiddifycli_enable' /opt/hiddify-manager/current.json 2>/dev/null)" || flag="?"
  if [ "$flag" = "true" ]; then
    warn "  panel setting hiddifycli_enable is still TRUE — turn it off in the"
    warn "  panel for the clean permanent fix; the drop-in is belt-and-braces"
  fi
  return 0
}

# One dead client socket puts the panel's app.py in an endless EPIPE loop.
# Truncating does NOT stop it — only a restart clears the stuck socket. Safe:
# user traffic flows haproxy -> xray/singbox and never touches hiddify-panel;
# only the admin UI and subscription serving blink for a few seconds.
_tun_panel_guard() {
  local s1=0 s2=0 s3=0 s4=0 rate=0
  if [ ! -f "$TUN_ERRLOG" ]; then
    ok "no panel err log — nothing to check"
    return 0
  fi
  s1="$(stat -c %s "$TUN_ERRLOG" 2>/dev/null)" || s1=0
  sleep 10
  s2="$(stat -c %s "$TUN_ERRLOG" 2>/dev/null)" || s2=0
  rate=$(( (s2 - s1) / 10 ))
  if [ "$rate" -lt "$TUN_SPIN_BPS" ]; then
    ok "panel err log growth ${rate} B/s — normal, no restart"
    return 0
  fi
  if ! systemctl cat hiddify-panel >/dev/null 2>&1; then
    warn "panel log spinning at $(( rate / 1024 )) KB/s but hiddify-panel is not a unit here"
    return 0
  fi
  warn "panel spinning at $(( rate / 1024 )) KB/s ($(( rate * 3600 / 1073741824 )) GB/h) — restarting"
  systemctl restart hiddify-panel || { err "hiddify-panel restart failed"; return 1; }
  sleep 12
  : > "$TUN_ERRLOG"
  s3="$(stat -c %s "$TUN_ERRLOG" 2>/dev/null)" || s3=0
  sleep 10
  s4="$(stat -c %s "$TUN_ERRLOG" 2>/dev/null)" || s4=0
  if [ "$(( (s4 - s3) / 10 ))" -lt "$TUN_SPIN_BPS" ]; then
    ok "loop cleared (panel=$(systemctl is-active hiddify-panel 2>/dev/null))"
    return 0
  fi
  warn "still spinning after restart — investigate by hand"
  return 0
}

# Truncate in place, never rm: the writer holds the fd, so unlinking frees zero
# bytes until the service restarts.
_tun_reclaim_logs() {
  local f="" sz=0 freed=0
  [ -d "$TUN_LOGDIR" ] || return 0
  for f in "$TUN_LOGDIR"/*.log; do
    [ -f "$f" ] || continue
    sz="$(stat -c %s "$f" 2>/dev/null)" || sz=0
    if [ "$sz" -gt 104857600 ]; then
      : > "$f" || continue
      freed=$(( freed + sz ))
      ok "truncated $(basename "$f") ($(( sz / 1048576 )) MB)"
    fi
  done
  if [ "$freed" -gt 0 ]; then ok "reclaimed $(( freed / 1048576 )) MB"; fi
  return 0
}

# -----------------------------------------------------------------------------
# mod_status
# -----------------------------------------------------------------------------
mod_status() {
  local have=0 total=0 rc=0 v="" state="" bsrc=""
  if ! _tun_derive; then
    echo "cannot read this box's CPU/RAM"
    echo "UNKNOWN"
    return 1
  fi

  printf 'box            : NIC=%s  CPUs=%s  RAM=%sMB  page=%sB\n' \
    "${TUN_NIC:-?}" "$TUN_NCPU" "$TUN_RAM_MB" "$TUN_PAGE"
  printf 'sized for      : tcp_mem=%s %s %s  tw=%s  conntrack=%s  file-max=%s\n' \
    "$TUN_TCP_MEM_LOW" "$TUN_TCP_MEM_PRESSURE" "$TUN_TCP_MEM_MAX" \
    "$TUN_TW_BUCKETS" "$TUN_CT_MAX" "$TUN_FILE_MAX"

  total=$(( total + 1 ))
  if _tun_is_ours "$TUN_SYSCTL_FILE"; then
    have=$(( have + 1 )); printf 'sysctl file    : %s\n' "$TUN_SYSCTL_FILE"
  else
    printf 'sysctl file    : absent\n'
  fi

  total=$(( total + 1 ))
  if _tun_core_ok; then
    have=$(( have + 1 )); printf 'running kernel : matches (all checked keys)\n'
  else
    printf 'running kernel : DRIFTED — an apply-config probably just ran\n'
  fi

  total=$(( total + 1 ))
  if [ -f "$TUN_MODULES_FILE" ]; then
    have=$(( have + 1 ))
    if _tun_has_conntrack; then
      v="$(sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null)" || v="?"
      printf 'nf_conntrack   : preloaded, in use (count=%s / max=%s)\n' \
        "${v:-?}" "$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo '?')"
    else
      printf 'nf_conntrack   : preload file present, module NOT loaded\n'
    fi
  else
    printf 'nf_conntrack   : no preload file (net.netfilter.* silently no-ops at boot)\n'
  fi

  # Deliberately NOT scored. A box tuned by the standalone apply-tuning.sh never
  # had this file, and counting it would report PARTIAL there — which would stop
  # the core's ht_adopt_applied from ever adopting (and therefore guarding)
  # exactly the boxes this module was written to take over.
  if [ -f "$TUN_MODPROBE_FILE" ]; then
    printf 'conntrack hash : %s buckets running (want %s), %s in place\n' \
      "$(cat /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || echo NA)" \
      "$(_tun_hashsize_want)" "$TUN_MODPROBE_FILE"
  else
    printf 'conntrack hash : %s buckets running (want %s), no modprobe.d file\n' \
      "$(cat /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || echo NA)" \
      "$(_tun_hashsize_want)"
  fi

  if _tun_rps_wanted; then
    total=$(( total + 1 ))
    state="$(systemctl is-active hiddify-rps.service 2>/dev/null)" || state="unknown"
    if [ -f "$TUN_RPS_SCRIPT" ] && [ -f "$TUN_RPS_UNIT" ] && _tun_rps_ok; then
      have=$(( have + 1 ))
      if _tun_rps_hw_covered; then
        printf 'RPS/RFS        : unit=%s  %s rx queues for %s CPUs — hardware already spreads rx, no mask forced\n' \
          "$state" "$(_tun_rx_queues)" "$TUN_NCPU"
      else
        printf 'RPS/RFS        : unit=%s  rps_cpus=%s (want %s)  %s rx queue(s) x rps_flow_cnt %s <= %s global\n' "$state" \
          "$(cat "/sys/class/net/${TUN_NIC}/queues/rx-0/rps_cpus" 2>/dev/null || echo NA)" \
          "$(_tun_cpu_mask "$TUN_NCPU")" \
          "$(_tun_rx_queues)" "$(_tun_flow_cnt_per_queue)" "$TUN_RFS_ENTRIES"
      fi
    else
      printf 'RPS/RFS        : not in place (unit=%s)\n' "$state"
    fi
  else
    printf 'RPS/RFS        : disabled by config (rps=no)\n'
  fi

  total=$(( total + 1 ))
  if _tun_is_ours "$TUN_LOGROTATE"; then
    have=$(( have + 1 )); printf 'logrotate      : %s\n' "$TUN_LOGROTATE"
  else
    printf 'logrotate      : absent (Hiddify ships none — logs grow unbounded)\n'
  fi

  # Deliberately NOT part of the score: on a box that chains its egress, no
  # drop-in is the CORRECT state, and counting it would report PARTIAL forever.
  if [ ! -d "$TUN_CLI_DIR" ]; then
    printf 'hiddify-cli    : not installed\n'
  elif [ -f "$TUN_CLI_DROPIN" ]; then
    printf 'hiddify-cli    : neutralised (restarts=%s)\n' \
      "$(systemctl show hiddify-cli -p NRestarts --value 2>/dev/null || echo '?')"
  else
    printf 'hiddify-cli    : running/looping or left alone (restarts=%s)\n' \
      "$(systemctl show hiddify-cli -p NRestarts --value 2>/dev/null || echo '?')"
  fi

  if [ -f "$TUN_ERRLOG" ]; then
    printf 'panel err log  : %s MB (growth is only measured during apply)\n' \
      "$(( $( { stat -c %s "$TUN_ERRLOG" 2>/dev/null || echo 0; } ) / 1048576 ))"
  fi

  # Resolved, not merely "did WE capture one" — on a box adopted from the
  # standalone script the only pristine copy is under /root, and claiming "none
  # captured yet" there is how an operator ends up trusting a revert that has
  # nothing to replay.
  bsrc="$(_tun_baseline_source)" || bsrc=""
  if [ -z "$bsrc" ]; then
    printf 'baseline       : NONE — a revert would remove the files but leave the values live\n'
  elif [ "$bsrc" = "$(_tun_baseline_file)" ]; then
    printf 'baseline       : %s (source=%s)\n' "$bsrc" "$(ht_conf_get baseline_source '?')"
  else
    printf 'baseline       : %s (legacy apply-tuning.sh backup, used as-is)\n' "$bsrc"
  fi

  if [ "$have" -eq "$total" ]; then
    printf 'APPLIED  %s/%s components in place\n' "$have" "$total"
  elif [ "$have" -eq 0 ]; then
    printf 'ABSENT  nothing from this module is installed\n'
  else
    printf 'PARTIAL  %s/%s components in place\n' "$have" "$total"
  fi
  # Deliberately 0 even for PARTIAL: ht_module_state throws the whole output
  # away and prints UNKNOWN when mod_status exits non-zero, so signalling drift
  # through the exit code is exactly how a correct PARTIAL turns into "?".
  # The token on the last line is the only channel that survives.
  return "$rc"
}

# -----------------------------------------------------------------------------
# mod_apply
# -----------------------------------------------------------------------------
mod_apply() {
  local rc=0 st=""

  # The scaling profile is written for a Hiddify panel. On an unrelated box the
  # kernel has usually auto-sized everything correctly and this would RAISE the
  # TCP ceiling on a small VM for buffers whose usage is zero (relay-invoice was
  # checked and deliberately skipped for exactly that reason).
  if ! ht_is_hiddify && [ "$(ht_conf_get force no)" != "yes" ]; then
    err "/opt/hiddify-manager not found — this profile is for Hiddify panel servers"
    err "override with: hiddify-toolkit ... (set force=yes in $(ht_state_dir)/conf/${MOD_ID}.conf)"
    return 1
  fi
  _tun_derive || return 1

  say "=== detected ==="
  ok "NIC=${TUN_NIC:-?}  CPUs=${TUN_NCPU}  RAM=${TUN_RAM_MB}MB  page=${TUN_PAGE}B"
  ok "tcp_mem   = ${TUN_TCP_MEM_LOW} ${TUN_TCP_MEM_PRESSURE} ${TUN_TCP_MEM_MAX} pages ($(( TUN_TCP_MEM_LOW * TUN_PAGE / 1048576 ))/$(( TUN_TCP_MEM_PRESSURE * TUN_PAGE / 1048576 ))/$(( TUN_TCP_MEM_MAX * TUN_PAGE / 1048576 )) MB)"
  ok "tw_buckets= ${TUN_TW_BUCKETS}   conntrack=${TUN_CT_MAX}   file-max=${TUN_FILE_MAX}"
  if [ -n "${TUN_RESERVED:-}" ]; then ok "reserved  = ${TUN_RESERVED}"; else ok "reserved  = (none found)"; fi

  _tun_capture_baseline
  st="$?"
  if [ "$st" = "2" ]; then
    err "could not write the rollback baseline — refusing to change anything"
    return 1
  fi
  # Remember every port we are about to reserve, so the generated body stays
  # byte-stable across reasserts (see _tun_scrape_reserved).
  _tun_remember_reserved

  # --- 1. nf_conntrack preload ------------------------------------------------
  say "=== 1. preload nf_conntrack (so net.netfilter.* actually applies) ==="
  ht_backup "$TUN_MODULES_FILE"
  _tun_install_file "$TUN_MODULES_FILE" 0644 "$(_tun_modules_body)"
  st="$?"
  if [ "$st" = "2" ]; then err "cannot write $TUN_MODULES_FILE"; rc=1; else ok "$TUN_MODULES_FILE"; fi
  # Written BEFORE the modprobe below on purpose: on a box where nf_conntrack is
  # not loaded yet, the module then comes up with the right bucket count and no
  # rehash is needed at all.
  ht_backup "$TUN_MODPROBE_FILE"
  _tun_install_file "$TUN_MODPROBE_FILE" 0644 "$(_tun_modprobe_body)"
  st="$?"
  if [ "$st" = "2" ]; then
    err "cannot write $TUN_MODPROBE_FILE"; rc=1
  else
    ok "$TUN_MODPROBE_FILE (hashsize=$(_tun_hashsize_want))"
  fi
  # Load it now as well, or every net.netfilter.* line in step 2 is rejected in
  # THIS run and only starts working after a reboot.
  modprobe nf_conntrack >/dev/null 2>&1 || true
  if ! _tun_has_conntrack; then
    warn "nf_conntrack unavailable in this kernel/namespace — netfilter keys will not apply"
  else
    # Already-loaded module: resize the live table once, here. Raising
    # nf_conntrack_max without this just makes every hash chain longer.
    _tun_set_hashsize
  fi

  # --- 2. sysctl --------------------------------------------------------------
  say "=== 2. write $TUN_SYSCTL_FILE ==="
  ht_backup "$TUN_SYSCTL_FILE"
  _tun_install_file "$TUN_SYSCTL_FILE" 0644 "$(_tun_sysctl_body)"
  st="$?"
  case "$st" in
    0) ok "$TUN_SYSCTL_FILE" ;;
    1) ok "$TUN_SYSCTL_FILE (already current)" ;;
    *) err "cannot write $TUN_SYSCTL_FILE"; rc=1 ;;
  esac

  # --- 3. RPS/RFS -------------------------------------------------------------
  if _tun_rps_wanted; then
    say "=== 3. RPS/RFS across all ${TUN_NCPU} CPUs (virtio NICs have 1 hw queue) ==="
    ht_backup "$TUN_RPS_SCRIPT"
    ht_backup "$TUN_RPS_UNIT"
    _tun_install_file "$TUN_RPS_SCRIPT" 0755 "$(_tun_rps_script_body)"
    st="$?"
    if [ "$st" = "2" ]; then err "cannot write $TUN_RPS_SCRIPT"; rc=1; fi
    _tun_install_file "$TUN_RPS_UNIT" 0644 "$(_tun_rps_unit_body)"
    st="$?"
    if [ "$st" = "2" ]; then err "cannot write $TUN_RPS_UNIT"; rc=1; fi
    systemctl daemon-reload
    systemctl enable --now hiddify-rps.service >/dev/null 2>&1 || true
    # enable --now is a no-op when the oneshot is already RemainAfterExit=yes,
    # so run the script directly to pick up a changed CPU count.
    "$TUN_RPS_SCRIPT" >/dev/null 2>&1 || warn "hiddify-rps.sh reported a problem"
    ok "$TUN_RPS_SCRIPT + $TUN_RPS_UNIT (mask=$(_tun_cpu_mask "$TUN_NCPU"))"
  elif [ -f "$TUN_RPS_UNIT" ] || [ -f "$TUN_RPS_SCRIPT" ]; then
    # The standalone script's --no-rps only dropped the sysctl line: the unit
    # stayed enabled and kept re-applying the mask at every boot forever, so
    # "rps off" was never actually off. Take the unit away too.
    say "=== 3. RPS/RFS off (rps=no) — removing the unit ==="
    systemctl disable --now hiddify-rps.service >/dev/null 2>&1 || true
    if _tun_is_ours "$TUN_RPS_SCRIPT"; then rm -f "$TUN_RPS_SCRIPT"; fi
    if _tun_is_ours "$TUN_RPS_UNIT";   then rm -f "$TUN_RPS_UNIT";   fi
    systemctl daemon-reload
    warn "hiddify-rps removed; the live rps_cpus mask stays until the next boot"
  fi

  # --- 4. logrotate -----------------------------------------------------------
  say "=== 4. logrotate for hiddify logs (Hiddify ships none) ==="
  ht_backup "$TUN_LOGROTATE"
  _tun_install_file "$TUN_LOGROTATE" 0644 "$(_tun_logrotate_body)"
  st="$?"
  if [ "$st" = "2" ]; then
    err "cannot write $TUN_LOGROTATE"; rc=1
  elif command -v logrotate >/dev/null 2>&1; then
    if logrotate -d "$TUN_LOGROTATE" >/dev/null 2>&1; then
      ok "$TUN_LOGROTATE (validated)"
    else
      warn "$TUN_LOGROTATE did not validate — check it by hand"
    fi
  else
    warn "$TUN_LOGROTATE written, but logrotate is not installed on this host"
  fi
  _tun_reclaim_logs

  # --- 5 + 6. the only two service-touching sections --------------------------
  if [ "$(ht_conf_get services yes)" != "no" ]; then
    # BOTH of these are opportunistic remediation of somebody else's bug, and
    # neither may decide the fate of the kernel layer above. They used to do
    # `|| rc=1`, and a non-zero mod_apply makes the core print "apply failed —
    # nothing was enabled", skip mod_verify, skip the rollback AND skip the
    # enable marker. On a box where hiddify-panel merely happens to be masked
    # while its log spins, that left every file written and live, no guard timer
    # to re-assert them, invisible to `uninstall` (which only reverts enabled
    # modules) — and an operator told the exact opposite. Warn and carry on.
    say "=== 5. hiddify-cli crash loop (only if provably unused) ==="
    _tun_cli_guard   || warn "hiddify-cli section did not complete — the tuning itself is unaffected"
    say "=== 6. panel EPIPE spin loop (restart only if actively bleeding) ==="
    _tun_panel_guard || warn "panel section did not complete — the tuning itself is unaffected"
    # Cosmetic: a unit left in `failed` pollutes `systemctl --failed` monitoring.
    # NAMED units only. Bare `reset-failed` resets every unit on the box, which
    # erases an xray/haproxy failure that predates this run and is very possibly
    # the only record the admin's monitoring has of it — plus every start-rate
    # limit counter system-wide.
    systemctl reset-failed hiddify-cli hiddify-panel >/dev/null 2>&1 || true
  else
    say "=== 5+6. service sections skipped (services=no) ==="
  fi

  # --- 7. apply ---------------------------------------------------------------
  say "=== 7. apply ==="
  # Mirror exactly what Hiddify itself runs, so the printed ordering proves our
  # file wins under real conditions.
  sysctl --system 2>&1 | grep -E "Applying (/etc/sysctl.d/(hiddify|wg|zz-)|/etc/sysctl.conf)" || true
  ok "sysctl --system done"
  return "$rc"
}

# -----------------------------------------------------------------------------
# mod_verify — always against the RUNNING kernel, never against the file
# -----------------------------------------------------------------------------
mod_verify() {
  local fail=0 got="" r="" want="" hs=""
  _tun_derive || return 1

  _tun_check() {                      # <key> <expected>
    local g
    g="$(_tun_sysctl_get "$1")" || { warn "$1 = (unreadable)"; return 1; }
    if [ "$g" = "$2" ]; then ok "$1 = $g"; return 0; fi
    warn "$1 = '$g' (expected '$2')"
    return 1
  }

  _tun_check net.ipv4.tcp_mem "$TUN_TCP_MEM_LOW $TUN_TCP_MEM_PRESSURE $TUN_TCP_MEM_MAX" || fail=1
  _tun_check net.ipv4.tcp_max_tw_buckets "$TUN_TW_BUCKETS" || fail=1
  _tun_check net.core.somaxconn "65535" || fail=1
  _tun_check net.ipv4.tcp_max_syn_backlog "65535" || fail=1
  _tun_check net.ipv4.ip_local_port_range "32768 65535" || fail=1
  _tun_check fs.file-max "$TUN_FILE_MAX" || fail=1

  # Conntrack is checked only where it EXISTS. Inside an LXC/OpenVZ container
  # the keys are simply absent, and failing here would make the core auto-revert
  # a sysctl layer that is otherwise perfectly applied.
  if _tun_has_conntrack; then
    _tun_check net.netfilter.nf_conntrack_max "$TUN_CT_MAX" || fail=1
    _tun_check net.netfilter.nf_conntrack_tcp_timeout_established "86400" || fail=1
    # Reported, never fatal: a kernel built without a writable hashsize knob is
    # a performance detail, and failing here would auto-revert an otherwise
    # perfect sysctl layer over it.
    hs="$(cat /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null)" || hs=""
    case "$hs" in
      ''|*[!0-9]*) warn "conntrack hash buckets not readable" ;;
      *) if [ "$hs" -lt "$(_tun_hashsize_want)" ]; then
           warn "conntrack hash buckets = $hs (want $(_tun_hashsize_want); applies on the next nf_conntrack load)"
         else
           ok "conntrack hash buckets = $hs"
         fi ;;
    esac
  else
    warn "nf_conntrack not loaded — netfilter keys not verifiable on this host"
  fi

  if [ -n "${TUN_RESERVED:-}" ]; then
    got="$(_tun_sysctl_get net.ipv4.ip_local_reserved_ports)" || got=""
    if [ -n "$got" ]; then ok "net.ipv4.ip_local_reserved_ports = $got"
    else warn "net.ipv4.ip_local_reserved_ports is empty (expected $TUN_RESERVED)"; fi
  fi

  if _tun_rps_wanted; then
    want="$(_tun_cpu_mask "$TUN_NCPU")"
    r="$(cat "/sys/class/net/${TUN_NIC}/queues/rx-0/rps_cpus" 2>/dev/null)" || r=""
    if [ -z "$r" ]; then
      warn "no rps_cpus knob on ${TUN_NIC} — RPS not available here"
    elif _tun_rps_hw_covered; then
      # hiddify-rps.sh exits before touching a multiqueue NIC, so there is no
      # mask to expect. Verify has to agree with it — otherwise every dedicated
      # box "fails verification" and the core rolls back the whole module.
      ok "$(_tun_rx_queues) rx queues for ${TUN_NCPU} CPUs — hardware spreads rx, RPS deliberately not applied"
    elif _tun_rps_ok; then
      ok "rps_cpus = $r (rps_flow_cnt $(_tun_flow_cnt_per_queue) x $(_tun_rx_queues) queue(s) <= ${TUN_RFS_ENTRIES} global)"
    else
      warn "rps_cpus = '$r' (expected '$want')"; fail=1
    fi
  fi

  [ -f "$TUN_LOGROTATE" ] || { warn "$TUN_LOGROTATE missing"; fail=1; }
  [ -f "$TUN_MODULES_FILE" ] || { warn "$TUN_MODULES_FILE missing"; fail=1; }

  if [ "$fail" -ne 0 ]; then
    warn "some values did not take — inspect above"
    return 1
  fi
  return 0
}

# -----------------------------------------------------------------------------
# mod_revert
# -----------------------------------------------------------------------------
mod_revert() {
  local rc=0
  # NIC is needed to restore rps_cpus; a failure here must not block the rest.
  _tun_derive || true

  # Remove only what we can prove is ours — and put back what was there before.
  # ht_backup keeps a pristine copy of every file apply overwrote, but nothing
  # ever restored it: a hand-written /etc/logrotate.d/hiddify-manager from a
  # previous admin was overwritten on apply, deleted on revert, and its only
  # surviving copy then went with `rm -rf $HT_STATE` at uninstall. The comment
  # above _tun_is_ours promised that file would survive a revert; now it does.
  _tun_drop_file() {
    local p="$1" bk=""
    [ -e "$p" ] || return 0
    if ! _tun_is_ours "$p"; then
      warn "left $p alone — it is not ours (no managed-by marker)"
      return 0
    fi
    bk="$(ht_backup_dir)/$(printf '%s' "$p" | sed 's|/|_|g')"
    # Only restore something that is NOT itself one of our markers, or a legacy
    # apply-tuning.sh file would be "restored" over its own replacement.
    if [ -f "$bk" ] && ! _tun_is_ours "$bk"; then
      if cp -a "$bk" "$p"; then
        ok "restored the pre-existing $p (from $bk)"
        return 0
      fi
      warn "could not restore $bk over $p — removing ours instead"
    fi
    rm -f "$p" && ok "removed $p"
    return 0
  }

  _tun_drop_file "$TUN_SYSCTL_FILE"
  _tun_drop_file "$TUN_MODULES_FILE"
  _tun_drop_file "$TUN_MODPROBE_FILE"
  _tun_drop_file "$TUN_LOGROTATE"

  systemctl disable --now hiddify-rps.service >/dev/null 2>&1 || true
  _tun_drop_file "$TUN_RPS_SCRIPT"
  _tun_drop_file "$TUN_RPS_UNIT"

  # Only ever remove a drop-in THIS module placed (see _tun_cli_guard): the
  # core also calls revert automatically when verify fails, and a tcp_mem
  # mismatch must not hand a crash loop back to a box somebody else fixed.
  if [ "$(ht_conf_get cli_neutralised no)" = "yes" ] && [ -f "$TUN_CLI_DROPIN" ]; then
    rm -f "$TUN_CLI_DROPIN"
    rmdir "$TUN_CLI_DROPIN_DIR" 2>/dev/null || true
    ht_conf_set cli_neutralised no
    ok "removed $TUN_CLI_DROPIN (hiddify-cli will start crash-looping again)"
    systemctl daemon-reload
    if [ "$(systemctl is-enabled hiddify-cli 2>/dev/null)" = "enabled" ]; then
      systemctl start hiddify-cli >/dev/null 2>&1 || true
    fi
  else
    systemctl daemon-reload
  fi

  # ORDER MATTERS: our files are gone, so re-apply Hiddify's own layer FIRST and
  # only then force the captured values back. Replaying before `sysctl --system`
  # lets Hiddify's file overwrite everything we just restored.
  sysctl --system >/dev/null 2>&1 || true
  # A missing baseline is reported and survivable (the files are gone either
  # way), so it must not fail the revert — reverting twice has to stay clean.
  _tun_restore_baseline || true

  say "reverted. current values:"
  local k
  for k in net.ipv4.tcp_mem net.ipv4.tcp_max_tw_buckets fs.file-max \
           net.netfilter.nf_conntrack_max net.ipv4.ip_local_port_range \
           net.ipv4.ip_local_reserved_ports; do
    ok "$k = $(sysctl -n "$k" 2>/dev/null || echo UNSET)"
  done
  # Not restorable, and honesty beats a clean-looking report: log truncation and
  # any panel restart done at apply time are gone for good, xps_cpus was never
  # captured (the standalone script never recorded it either), and the live
  # conntrack hash table keeps the size we gave it until the module is reloaded
  # — shrinking it back would be another full rehash for no benefit at all.
  return "$rc"
}

# -----------------------------------------------------------------------------
# mod_adopt — OPTIONAL hook. The core calls it from ht_adopt_applied() when it
# marks an already-APPLIED box as enabled WITHOUT ever running mod_apply.
# -----------------------------------------------------------------------------
# Adoption is how a box tuned by the old standalone apply-tuning.sh gets a guard
# without being tuned twice. By design it skips mod_apply — and mod_apply is the
# only thing that ever RECORDED anything. The record that matters is the
# rollback baseline: adopt without it and "2) revert to previous state" removes
# our files, prints "reverted", and leaves every tuned value live. So take the
# one chance we get, here.
#
# What this must never do is fall back to snapshotting the live kernel: on an
# adopted box those ARE the tuned values, and a baseline of tuned values makes
# revert a no-op that reports success. "adopt" mode takes a legacy baseline or
# nothing at all, and mod_status says so out loud when it got nothing.
mod_adopt() {
  # Best-effort, and always 0. Nothing here may block adoption — a module that
  # fails to be adopted gets no guard, and no guard is how these settings
  # quietly disappear on the next apply-config. _tun_derive is called for its
  # side effects only; the legacy-baseline copy below needs nothing from it, so
  # a box where derive fails still gets the one record worth having.
  _tun_derive || true
  _tun_capture_baseline adopt || true
  return 0
}

# -----------------------------------------------------------------------------
# mod_reassert — runs every 2 minutes. Quiet, fast, and it must never touch a
# service unless it actually had to re-apply something. The panel restart and
# the hiddify-cli DECISION (is this box safe to neutralise?) are deliberately
# absent — those measure, and measuring costs a 10-second sleep. The single
# service call in here is the `stop` that follows re-creating a drop-in we
# already own, and it only runs in the branch where that file had gone missing.
# -----------------------------------------------------------------------------
mod_reassert() {
  local rc=0 changed=0 st=""
  _tun_derive || return 1
  # Freeze whatever the live scrape just found, so the body we write below is
  # the body the NEXT cycle computes too (see _tun_scrape_reserved).
  _tun_remember_reserved

  _tun_install_file "$TUN_MODULES_FILE" 0644 "$(_tun_modules_body)"
  st="$?"
  case "$st" in 0) changed=1 ;; 2) rc=1 ;; esac

  # Re-created because it is a plain file write with zero runtime effect — the
  # bucket count in it is read at module LOAD. The running table is pointedly
  # NOT resized here: that write reallocates and rehashes every live conntrack,
  # which is an apply-time action, not something to do 720 times a day.
  _tun_install_file "$TUN_MODPROBE_FILE" 0644 "$(_tun_modprobe_body)"
  st="$?"
  case "$st" in 2) rc=1 ;; esac

  # Only modprobe when the keys are genuinely missing — a fork every 2 minutes
  # for a module that is already loaded is pure waste.
  _tun_has_conntrack || modprobe nf_conntrack >/dev/null 2>&1 || true

  _tun_install_file "$TUN_SYSCTL_FILE" 0644 "$(_tun_sysctl_body)"
  st="$?"
  case "$st" in 0) changed=1 ;; 2) rc=1 ;; esac

  # An apply-config re-runs `sysctl --system`, which re-applies our file too —
  # so most cycles find nothing drifted and do nothing at all. When it has
  # drifted, load OUR file only: `sysctl --system` here would re-assert every
  # other file on the box (including ones another module deliberately beat).
  if [ "$changed" = "1" ] || ! _tun_core_ok; then
    sysctl -q -p "$TUN_SYSCTL_FILE" >/dev/null 2>&1 || true
    _tun_core_ok || rc=1
  fi

  if _tun_rps_wanted; then
    _tun_install_file "$TUN_RPS_SCRIPT" 0755 "$(_tun_rps_script_body)"
    st="$?"
    case "$st" in 2) rc=1 ;; esac
    _tun_install_file "$TUN_RPS_UNIT" 0644 "$(_tun_rps_unit_body)"
    st="$?"
    case "$st" in
      0) systemctl daemon-reload
         systemctl enable hiddify-rps.service >/dev/null 2>&1 || true ;;
      2) rc=1 ;;
    esac
    # sysfs, so a NIC re-init wipes it. Run the script itself rather than
    # `systemctl start`: the unit is RemainAfterExit=yes and starting it again
    # is a service action for no gain.
    if ! _tun_rps_ok; then
      [ -x "$TUN_RPS_SCRIPT" ] && { "$TUN_RPS_SCRIPT" >/dev/null 2>&1 || rc=1; }
    fi
  fi

  # Cheap file re-creation only. Nothing here reloads or restarts logrotate.
  if [ ! -f "$TUN_LOGROTATE" ]; then
    _tun_install_file "$TUN_LOGROTATE" 0644 "$(_tun_logrotate_body)"
    st="$?"
    if [ "$st" = "2" ]; then rc=1; fi
  fi

  # The logrotate file above CANNOT bound the failure it was written for, and it
  # took a dead 38 GB disk on s6 to understand why: `size 100M` is a condition
  # logrotate evaluates when it runs, and on Ubuntu 24.04 it runs from
  # logrotate.timer, OnCalendar=daily. The EPIPE loop writes 4 MB/s. Between two
  # daily runs that is ~345 GB; `rotate 3` never gets a turn. This truncate is
  # the only thing that actually holds the line, and doing it once at apply time
  # meant the box was exactly as exposed as before the module existed for every
  # minute in between. It is stat + truncate over one directory — no service
  # action, no fork storm — so it belongs on the 2-minute cycle. The RESTART
  # half of the same problem stays in mod_apply on purpose.
  _tun_reclaim_logs >/dev/null 2>&1 || true

  # Only ever re-place a drop-in THIS module placed (cli_neutralised=yes), so we
  # can never re-neutralise a unit somebody else deliberately brought back.
  # The drop-in survives Hiddify's other/hiddify-cli/install.sh because that
  # script replaces the .service FILE and leaves .service.d/ alone — which is an
  # assumption about a vendor script we do not control. If it ever stops being
  # true, the 12,500-restart loop comes back and nothing puts the file back
  # until a human re-applies by hand. Writing a 4-line file is not a service
  # action; the stop below runs ONLY in the branch that actually had to
  # re-create it, which is exactly what the reassert contract allows.
  if [ "$(ht_conf_get cli_neutralised no)" = "yes" ] && [ ! -f "$TUN_CLI_DROPIN" ]; then
    mkdir -p "$TUN_CLI_DROPIN_DIR" 2>/dev/null || true
    _tun_install_file "$TUN_CLI_DROPIN" 0644 "$(_tun_cli_dropin_body)"
    st="$?"
    case "$st" in
      0) systemctl daemon-reload
         systemctl stop hiddify-cli.service >/dev/null 2>&1 || true ;;
      2) rc=1 ;;
    esac
  fi

  return "$rc"
}
