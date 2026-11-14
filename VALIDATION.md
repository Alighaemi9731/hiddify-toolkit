# Toolkit 2.0.0 acceptance

Validated on **2026-11-14**, Ubuntu 24.04 / Hiddify Manager and Panel **14.2.0**,
server `46.62.164.112`. This is evidence for this tested version and layout,
not a guarantee for every future panel version or every provider/network.

## Automated checks

- **15 unit tests pass**: independently reversible/idempotent source changes,
  CDN/Direct composition, trailing-dot and IPv4/IPv6 host parsing, preserved DNS
  rejection, unknown/duplicate source refusal, whole-batch validation before writes,
  rollback after network failure, first-install defaults, explicit revert surviving
  reinstall, prepare without restart, live-flock detection, alias conflict release,
  boot restore before a gateway listens, port/IP input validation, Hiddify 12 refusal.
- ShellCheck and `git diff --check` pass.
- **10 isolated Linux network-namespace packet tests pass**: source NAT to an
  assigned secondary IPv4, incoming connection replies, HTTP/TLS TCP aliasing,
  loopback, forwarded VPN traffic exclusion, IPv6 aliasing, native panel DNAT taking
  precedence, iptables flush/restore survival, independent revert of the two tables.
  Namespace tests change no host network interfaces, routes, sysctls or firewall.
- Controlled TLS tests use the **actual installed panel function** in a namespace:
  HTTP/1.1 + TLS 1.3 accepted, h2 + TLS 1.3 accepted, TLS 1.2 still rejected.

## Live panel acceptance

- The four built-in features enabled automatically on installation.
- The three modified panel documents compile with the panel's Python interpreter.
- Built-in installation left Xray, hiddify-core and HAProxy PIDs unchanged and left
  the native nftables ruleset unchanged. Only the panel was restarted.
- Actual authenticated Admin V2 API requests saved a Direct domain resolving to
  `131.123.41.185` and a CDN domain resolving to the tested server's own IP.
  Both names had a trailing dot, and the saved name retained it.
- Test names were longer than the ACME issuance limit to avoid requesting test
  certificates. The records were deleted afterward. Existing domain settings and
  order were checked and preserved.
- Actual API requests for unresolved DNS and a double trailing dot still returned 400.
- Live optional TCP aliases `38080:80` and `38443:443` returned the same responses
  as their gateways, both locally and from a separate server. This establishes
  forwarding equivalence; the fallback virtual host itself returned HTTP 502 on
  the HTTPS gateway and alias alike, which is not a successful application request.
  The authenticated panel API returned 200.
- A complete native `scripts/apply_configs.sh` exited **0**. Owned aliases survived.
  The native certificate phase took several minutes; source/alias ownership was
  checked independently of the panel's certificate results.
- A controlled replacement of the trailing-dot source during the held native
  installation lock was not fought by the guard. After the native operation ended,
  the guard repaired the source and the API acceptance tests passed again.
- The boot network unit recreated a deliberately removed owned alias table without
  restarting the panel.
- A no-op reassert did not change the panel PID.
- With the panel stopped, uninstall restored the **exact original SHA256 hashes**
  of all three panel documents, removed owned code/state/drop-in/tables, and
  preserved native firewall tables.
- Clean reinstall while the panel was stopped enabled exactly the four defaults.
  The guard was then stopped and one patch deliberately reversed. A real native
  `systemctl start hiddify-panel` ran ExecStartPre, repaired that source, and served
  the panel successfully. This verifies startup repair separately from the timer.
- Reinstalling an intact installation preserved the panel PID.
- Final requested state: four defaults enabled; `outbound-ip` and `port-alias` off.

## Limits and operational observations

The server has only one public IPv4. Actual secondary-IP SNAT was exercised with
real packets in isolated namespaces; an additional provider-assigned production
IP was not invented or attached to the server. The production choice remains off.

No reboot was forced; the boot unit was exercised directly. No sustained capacity
or peak-user load benchmark was performed. Toolkit 2 deliberately does not contain
performance, IPv6-control, WARP, ECH, log-capping or dashboard modules.

The panel's existing Granian service took around 90 seconds to stop. An initial
60-second toolkit restart deadline caused the pilot installer to roll back.
The release uses a 180-second restart deadline and a 240-second guard deadline;
subsequent installation/lifecycle tests completed successfully. Toolkit 2 does
not modify the native service's kill policy or shutdown implementation.

Private acceptance evidence and original source copies are retained on the test
server in `/root/ht-v2-acceptance`, not in the public release. They contain no
published API credentials. The seven Hiddify 12 servers were not upgraded or
modified as part of this release.
