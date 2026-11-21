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
or peak-user load benchmark was performed. Toolkit 2.0 deliberately did not contain
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

## Installer update: 2.0.1

The six features are unchanged. Four additional installer tests bring the unit
suite to **19 passing tests**: numeric stable-v2 selection, release pagination,
missing-channel refusal and invalid/API-error response refusal. The default
installer now selects a published stable v2 release, never unreleased main,
v1 releases, other major releases, drafts or prereleases. Source VERSION must
belong to v2 and match an explicitly selected v2 tag. ShellCheck and diff checks pass.

## Performance release: 2.1.0

Validated on **2026-11-22**, Hiddify Manager/Panel **14.2.0**, Ubuntu **26.04.1**,
kernel **7.0.0-30-generic**, x86_64, four vCPU and approximately 7.56 GiB RAM.
An additional isolated NODELAY compatibility test passed on an Ubuntu **24.04**
host running kernel **6.8.0-149-generic**, also x86_64. Native ARM64 builds are
capability gated but were not live validated in this acceptance run.

- **39 unit tests pass.** New coverage includes page-size/RAM budgets, larger
  pre-existing values, independent revert, preservation of externally changed
  runtime values, sysctl/BPF failure rollback, missing ownership receipts,
  pending boot attachment, existing-socket repair, cached-helper architecture,
  unavailable capability fallback, 2.0.x default migration, persisted opt-out and
  refusing downgrade/stale-release selection while performance controls are active.
- The existing **10 real-packet namespace tests** pass on the Ubuntu 26 host.
  They leave production interfaces/routes/firewalls unchanged. Controlled tests
  of the installed panel TLS function accept HTTP/1.1 and h2 with TLS 1.3,
  while still rejecting TLS 1.2.
- On both kernels, an isolated owned cgroup demonstrates new active/passive TCP
  NODELAY values `0 -> 1 -> 0`, idempotent attach and complete detach/cleanup.
  Production rpxy is never moved into the diagnostic cgroup.
- The canary install enabled the four panel defaults plus all three performance
  defaults. TCP memory changed from `25600 51200 102400` pages to
  `123848 185772 247697` pages, calculated using actual RAM and 4096-byte pages.
  TIME_WAIT capacity changed from 5000 to 262144. The locally-built helper updated
  729 established rpxy sockets; a later complete scan found 691 on and zero off.
- In matched 20-second aggregate windows, `TCPTimeWaitOverflow` changed from
  **2349 to 0**. TCP receive/OFO/backlog/listen drops remained zero. These are
  bounded production observations, not peak-capacity guarantees.
- Authenticated REALITY downloads from an Iranian physical-interface vantage
  completed on both direct and relay paths using the existing configured port.
  For three 1 MiB downloads per path, direct median time was approximately
  **1.20 -> 1.11 s**, and relay median **2.05 -> 1.71 s**. The before relay samples
  included a 6.54-second outlier; changing user load and network conditions are
  confounders, so throughput gains are not attributed exclusively to tuning.
- For eight reused HTTP/2 requests per path, body-after-headers pauses above
  80 ms changed from **3/16 to 0/16**. Maximum observed body gaps changed from
  about 105/165 ms (direct/relay) to less than 1/4 ms. Overall median request time
  was 119 -> 109 ms direct and 172 -> 176 ms relay; the relay median did not improve.
- The native generated config hashes, domain-port records and stateless nftables
  ruleset were identical before/after installation. rpxy, Xray, HAProxy and
  hiddify-core PIDs were unchanged. The panel restarted once for source defaults.
- The enabled boot entry and an ordinary reassert completed successfully without
  proxy restarts. `systemd-analyze verify` accepted the boot, guard, timer and rpxy
  units. Effective systemd-sysctl ordering selected the owned performance values.

No reboot or production rpxy restart was forced to test future startup behavior.
Failure rollback is exercised with isolated state/runtime substitutes; no known
bad capacity limit was deliberately reintroduced on the live canary. NODELAY
detach/new-socket restoration is exercised with real sockets in private cgroups.
Existing connected sockets keep NODELAY until natural closure on revert.

The performance profile does not change qdisc, congestion control, MTU/MSS,
offloads, RPS/IRQ assignment, TCP timeouts, conntrack capacity or application ports.
The canary NIC had no observed queue drops, and its busiest sampled CPU was
approximately 37%, so no evidence justified those additional changes.
Current-kernel parameter semantics were checked against the
[Linux 7.0 IP sysctl documentation](https://github.com/torvalds/linux/blob/v7.0/Documentation/networking/ip-sysctl.rst).
