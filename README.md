# Hiddify Toolkit 2

Six focused features for **Hiddify Manager/Panel 14.2.x** (live validated on **14.2.0**).
Toolkit 2 does not support Hiddify 12. For those servers keep [v1.8.2](https://github.com/Alighaemi9731/hiddify-toolkit/releases/tag/v1.8.2).

## Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Alighaemi9731/hiddify-toolkit/main/install.sh) --ref v2.0.0
```

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

These are the only six features. Kernel tuning, IPv6 control, log cleanup, dashboard modifications, fixed ECH and WARP are not included.
The four defaults are applied as a validated batch with at most one panel restart. Existing proxy cores are not restarted by toolkit patch operations.
A panel restart can briefly interrupt panel requests and subscription generation; Hiddify may run its own database migrations when it starts.

The domain patches remove only their specific restrictions. DNS must still resolve; other domain/proxy validations remain.
Allowing a name to be saved does not change its DNS, client destination, CDN service or certificate issuance.
The trailing-dot patch applies to the Admin V2 Domains API; the initial quick-setup wizard is outside this feature.

## Commands

```bash
hiddify-toolkit                         # interactive six-feature menu
hiddify-toolkit status
hiddify-toolkit revert cdn-same-ip       # restore only this check
hiddify-toolkit apply cdn-same-ip
hiddify-toolkit update                  # updates from main; preserves saved choices
hiddify-toolkit uninstall               # revert all owned changes and remove toolkit
```

Reinstallation preserves explicit choices: if you revert a default feature, it stays off on the next installation.
A clean installation turns the four defaults on. `install.sh --no-menu` works non-interactively.
For offline deployments use `--archive /path/to/release.tgz` with an archive containing the project files at its root.

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
- Optional network tables survive Hiddify's iptables flush/restore. A boot unit restores enabled network rules before HAProxy without requiring the gateway to already be listening.
- Revert uses exact inverses, preserving unrelated edits. The toolkit removes only its own drop-in, units, tables and state during uninstall.
- Local state and original source backups are in `/var/lib/hiddify-toolkit`. No user credentials or traffic payloads are collected.

## Validation

```bash
python3 -m unittest discover -s tests -v
shellcheck install.sh bin/hiddify-toolkit
# Linux root only: isolated network-namespace NAT tests, never the host ruleset
python3 tests/network_netns.py
```

See [VALIDATION.md](VALIDATION.md) for actual release acceptance results and limits.
