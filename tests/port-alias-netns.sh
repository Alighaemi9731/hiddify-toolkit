#!/usr/bin/env bash
# Run as root on Linux. All firewall and listener changes stay in disposable namespaces.
set -euo pipefail
TEST_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ "${1:-}" != --inner ]; then
  exec unshare --mount --net --fork --propagation private bash "$0" --inner
fi
mount -t tmpfs tmpfs /run
TEST_TMP="$(mktemp -d)"
cleanup() {
  kill "${listener_pid:-}" 2>/dev/null || true
  ip netns del pa-client 2>/dev/null || true
  rm -rf "$TEST_TMP"
}
trap cleanup EXIT
export HT_STATE="$TEST_TMP/state"
# shellcheck source=lib/core.sh
. "$TEST_ROOT/lib/core.sh"
# shellcheck source=modules/70-port-alias.sh
. "$TEST_ROOT/modules/70-port-alias.sh"
_pa_boot_install() { : > "$_PA_BOOT_UNIT"; }
systemctl() { :; } # Test boot-unit integration separately on the real host.
_PA_BOOT_UNIT="$TEST_TMP/no-unit"
ht_conf_set aliases '8080:80,2052:80,2095:80'
ht_conf_set backend nft
ip link set lo up
ip netns add pa-client
ip link add pa-server type veth peer name pa-peer
ip link set pa-peer netns pa-client
ip addr add 192.0.2.1/24 dev pa-server
ip -6 addr add fd00:1234::1/64 dev pa-server nodad
ip link set pa-server up
ip netns exec pa-client ip addr add 192.0.2.2/24 dev pa-peer
ip netns exec pa-client ip -6 addr add fd00:1234::2/64 dev pa-peer nodad
ip netns exec pa-client ip link set lo up
ip netns exec pa-client ip link set pa-peer up
python3 - <<'PY' &
import http.server, socket, threading
class Server(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()
def udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 80))
    while True:
        data, addr = sock.recvfrom(1024)
        sock.sendto(data, addr)
threading.Thread(target=udp, daemon=True).start()
class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass
Server(("::", 80), Handler).serve_forever()
PY
listener_pid=$!
for _ in {1..50}; do
  if _pa_listening tcp 80 && _pa_listening udp 80; then break; fi
  sleep 0.1
done
iptables -P INPUT DROP
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p udp --dport 80 -j ACCEPT
# Exercise replacement of a previously enabled iptables alias.
iptables -t nat -A PREROUTING -p tcp --dport 2095 -m comment --comment "$_PA_TAG" -j REDIRECT --to-ports 80
_pa_converge
mod_verify
test -z "$(_pa_owned_lines iptables)"
probe() {
  local p
  for p in 80 8080 2052 2095; do
    ip netns exec pa-client curl --noproxy '*' -fsS --max-time 3 "http://192.0.2.1:$p/" >/dev/null
    ip netns exec pa-client curl --noproxy '*' -gfsS --max-time 3 "http://[fd00:1234::1]:$p/" >/dev/null
  done
}
probe
ip netns exec pa-client python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(b"legacy-udp", ("192.0.2.1", 8080))
assert s.recv(1024) == b"legacy-udp"
PY
test "$(_pa_counter tcp 8080 80)" -ge 2
# Transit packets must not be intercepted as if they targeted this server.
ip netns exec pa-client ip route add 198.51.100.1/32 via 192.0.2.1
count="$(_pa_counter tcp 8080 80)"
if ip netns exec pa-client curl --noproxy '*' -fsS --max-time 1 'http://198.51.100.1:8080/' >/dev/null 2>&1; then exit 1; fi
test "$count" = "$(_pa_counter tcp 8080 80)"
before="$(nft -a -s list table inet "$_PA_NFT_TABLE")"
_pa_converge
test "$before" = "$(nft -a -s list table inet "$_PA_NFT_TABLE")"
# The actual destructive operation Hiddify performs, confined to this namespace.
iptables -t nat -F
iptables -t nat -X
ip6tables -t nat -F
ip6tables -t nat -X
probe
# A restart must not remove TCP redirects, even while the target is absent.
_pa_listening() { return 1; }
_pa_converge
_pa_nft_has tcp 8080 80
probe
nft delete table inet "$_PA_NFT_TABLE"
_pa_converge
probe
mod_revert
if nft list table inet "$_PA_NFT_TABLE" >/dev/null 2>&1; then exit 1; fi
if _pa_parse '8080:80,8080:443' >/dev/null 2>&1; then exit 1; fi
if _pa_parse '08080:80' >/dev/null 2>&1; then exit 1; fi
printf 'PASS: IPv4/IPv6 TCP, UDP, INPUT DROP, transit exclusion, migration, flush survival, restart, repair, idempotency, revert, parsing\n'
