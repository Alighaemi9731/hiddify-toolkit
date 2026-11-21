# Hiddify Toolkit 2.1

Nine independently reversible features for **Hiddify Manager/Panel 14.2.x** (live validated on **14.2.0**).
Toolkit 2 does not support Hiddify 12. For those servers keep [v1.8.2](https://github.com/Alighaemi9731/hiddify-toolkit/releases/tag/v1.8.2).

## Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Alighaemi9731/hiddify-toolkit/main/install.sh)
```

The one-line command selects the newest published stable **v2.x.x** release for Hiddify 14.
It skips drafts, prereleases, v1 (Hiddify 12), and other major versions; it never silently falls back to unreleased main code.
The update command and menu use the same release selection. For an explicit rollback, `--ref v2.0.0` remains available.

Requires root, systemd, Python 3, curl, tar, iproute2 and nftables (the tested Hiddify installation includes them).
The installer verifies the panel version, interpreter, paths and all patch signatures **before replacing existing toolkit code**.
Legacy Toolkit 1 installations with enabled modules must be reverted/uninstalled using version 1 first.
Nothing is automatically changed on your other servers by publishing a release.

| Feature | ID | Installation default |
|---|---|---|
| Offer both h2 and http/1.1 for Reality's TLS check | `reality-alpn` | **On** |
| Choose an assigned secondary public IPv4 for outbound traffic | `outbound-ip` | Off |
| Accept a single trailing dot, e.g. `example.com.` | `fakedomain-dot` | **On** |
| Accept CDN domains resolving to the server IP | `cdn-same-ip` | **On** |
| Accept Direct domains resolving to a different IP | `direct-any-ip` | **On** |
| Keep legacy TCP client ports answering on the HTTP/TLS gateways | `port-alias` | Off |
| Raise aggregate TCP memory thresholds using the server's RAM | `tcp-memory` | On when compatible |
| Raise the small TIME_WAIT capacity limit | `tcp-timewait` | On when compatible |
| Set TCP_NODELAY on the rpxy service's TCP connections | `rpxy-nodelay` | On when compatible |

The four panel defaults are applied as a validated batch with at most one panel restart. Existing proxy cores are not restarted by toolkit patch operations.
A panel restart can briefly interrupt panel requests and subscription generation; Hiddify may run its own database migrations when it starts.
The three performance defaults are capability checked on Ubuntu **24.04 / 26.04** before activation. An unavailable performance option is skipped with its reason; it does not block the panel defaults.
There are no IPv6-control, log-cleanup, dashboard, fixed-ECH or WARP modules.

The domain patches remove only their specific restrictions. DNS must still resolve; other domain/proxy validations remain.
Allowing a name to be saved does not change its DNS, client destination, CDN service or certificate issuance.
The trailing-dot patch applies to the Admin V2 Domains API; the initial quick-setup wizard is outside this feature.

## Commands

```bash
hiddify-toolkit                         # interactive six-feature menu
hiddify-toolkit status
hiddify-toolkit revert cdn-same-ip       # restore only this check
hiddify-toolkit apply cdn-same-ip
hiddify-toolkit update                  # installs latest stable v2 release; preserves choices
hiddify-toolkit diagnose                # 5-second read-only aggregate TCP/queue snapshot
hiddify-toolkit uninstall               # revert all owned changes and remove toolkit
```

Reinstallation preserves explicit choices: if you revert a default feature, it stays off on the next installation.
A clean installation enables the four panel defaults and the compatible performance defaults. The first update from 2.0.x also adds the new compatible performance defaults once, preserving the existing panel choices.
`install.sh --no-menu` works non-interactively. Use `--no-performance-defaults` to opt out of newly introduced performance defaults; this choice persists and does not turn off already-enabled options.
For offline deployments use `--archive /path/to/release.tgz` with an archive containing the project files at its root.

### TCP capacity and rpxy latency

```bash
hiddify-toolkit apply tcp-memory
hiddify-toolkit apply tcp-timewait
hiddify-toolkit apply rpxy-nodelay
hiddify-toolkit revert rpxy-nodelay
hiddify-toolkit diagnose
```

`tcp-memory` raises the **aggregate** `net.ipv4.tcp_mem` low/pressure/high thresholds.
Its high threshold is one eighth of physical RAM, capped at 1 GiB; low is one half and pressure is three quarters of that budget. Values are converted to the host's actual page size. These are thresholds, not reserved memory or per-connection buffers.
`tcp-timewait` raises `net.ipv4.tcp_max_tw_buckets` to 262144 on hosts with at least 3 GiB RAM, or 65536 on smaller hosts.
Both capacity options require at least 1 GiB RAM and preserve values already larger than their profile when first enabled. The budget is saved on activation; after resizing RAM, re-enable the capacity options to choose a new budget. They never increase buffer sizes per socket or change TCP timeouts.

`rpxy-nodelay` attaches a small `CGROUP_SOCK_OPS` program **only** to `hiddify-rpxy-l4.service`, for active/passive established TCP callbacks. It also sets NODELAY on the service's already-connected TCP sockets using `pidfd_getfd`. No traffic payloads or client identifiers are stored, and no rpxy restart is performed.
It requires cgroup v2, permitted root BPF/pidfd access and Linux x86_64/aarch64. A C compiler and Linux development headers are needed to build or update the helper; an intact cached helper is reused afterward. The helper is built locally; no binary or dependency packages are downloaded.
Before enabling, a disposable cgroup test proves NODELAY on both directions, repeat-attach idempotence and detach restoration. A changed kernel is tested again before production attachment, using the cached helper when possible. A service-start drop-in reattaches before future rpxy starts. Its best-effort failure cannot prevent the proxy from starting; status reports drift.

The owned sysctl file is `/etc/sysctl.d/zzzz-hiddify-toolkit-performance.conf`. Original runtime values, receipts and the locally-built helper live under `/var/lib/hiddify-toolkit`. The guard repairs enabled runtime settings after native configuration changes.
Revert restores original sysctl values when they still match the last Toolkit value; it preserves externally changed runtime values. It removes only the owned BPF attachment and drop-in. Established sockets retain NODELAY until natural closure; new connections return to the application's normal behavior.
Existing independent tuning (including older manually deployed performance helpers) is preserved; reverting Toolkit does not disable another tool's settings.
Before downgrading to 2.0.x, revert all three performance options using 2.1 first, because older versions do not know how to remove them. The current installer rejects a downgrade while these options or their runtime receipts remain active, including a stale release-list response.

Ubuntu 24 and 26 can have different kernels and capabilities. Compatibility is checked on the running host rather than inferred from the Ubuntu name. The profile leaves congestion control, installed qdiscs, MTU/MSS, offloads, IRQ/RPS and conntrack settings unchanged. A provider bottleneck or a bad client route still needs separate diagnosis; these options do not promise zero latency.

### Legacy ports (optional)

```bash
hiddify-toolkit apply port-alias --aliases 8080:80,2052:80,2095:80,8443:443
hiddify-toolkit revert port-alias
```

TCP only. The target must be the standard gateway 80 or 443 and be listening when the feature is enabled.
Old ports must be unprivileged and cannot collide with a listening TCP service or the panel's per-domain gateway ports.
The module checks the current `generated/firewall.sh`; an unknown layout is rejected.
If a later panel change claims an old port, the guard releases the toolkit alias table and reports a conflict.
No domain or subscription entries are created, so the old ports are not advertised to new clients.
QUIC/UDP and redirecting to arbitrary custom services are outside this feature.

Independent `inet hiddify_toolkit_ports` NAT chains run after Hiddify's iptables NAT (native panel redirects take precedence), for IPv4 and IPv6.
Rules only match **local destinations**; forwarded VPN traffic to another server's port is untouched.
Loopback/local connections are covered as well. Filter policies and Hiddify's own rules are not changed.

### Outbound IP (optional)

```bash
hiddify-toolkit apply outbound-ip --ip YOUR_ASSIGNED_SECONDARY_IPV4
hiddify-toolkit revert outbound-ip
```

Only an already-assigned **different public IPv4 on the default-route interface** is accepted.
The toolkit does not invent, attach or route provider IPs. It verifies the IP using a bound external request before applying SNAT,
and an unbound request afterward; verification failure restores the previous choice.
A server with one public IPv4 cannot use this feature until its provider assigns another.

The independent `ip hiddify_toolkit_egress` table changes only new original-direction IPv4 connections whose source is the primary public IP.
LAN/local destinations and traffic sourced from VPN tunnel ranges are excluded. Inbound established connections keep their replies.
This feature does not select WARP exit addresses or change explicitly bound secondary sources, DNS, default routes or IPv6 egress.
A changed default route/address invalidates the saved choice and is reported rather than guessed.

## Persistence and ownership

- A marked systemd panel drop-in prepares enabled patches before **every panel start**, including Apply Config and package replacement followed by a restart.
- The preparer validates all affected documents before writing. Each file is compiled using the panel interpreter, then atomically replaced with its permissions/owner preserved.
- The guard checks every minute, skips a currently held Hiddify installation flock, and restarts an active panel only when it repaired a source change.
- An intact installation causes no panel restart on reassert or reinstall.
- The startup preparer is best-effort: an unknown future panel source logs an error and leaves files unchanged; it never prevents the panel from starting.
  The guard/CLI report failure. Compatibility with untested future versions is not guaranteed.
- Optional network tables survive Hiddify's iptables flush/restore. A boot unit restores enabled network rules and performance controls before HAProxy/rpxy without requiring the gateway to already be listening.
- Revert uses exact inverses for source patches, preserving unrelated edits. The toolkit removes only its own drop-ins, units, tables and state during uninstall; performance runtime restoration follows the ownership rules above.
- Local state and original source backups are in `/var/lib/hiddify-toolkit`. No user credentials or traffic payloads are collected.

## Validation

```bash
python3 -m unittest discover -s tests -v
shellcheck install.sh bin/hiddify-toolkit
# Linux root only: isolated network-namespace NAT tests, never the host ruleset
python3 tests/network_netns.py
```

See [VALIDATION.md](VALIDATION.md) for actual release acceptance results and limits.
