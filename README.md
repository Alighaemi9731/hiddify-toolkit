# hiddify-toolkit

One menu for the fixes a Hiddify panel server needs after install — and, more importantly,
**a way to make those fixes stick**.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Alighaemi9731/hiddify-toolkit/main/install.sh)
```

Run it right after you install a panel. It installs to `/opt/hiddify-toolkit`, puts
`hiddify-toolkit` on your `PATH`, and opens the menu. Re-run the same line any time to upgrade —
your enabled modules, their settings and their backups are preserved.

---

## The problem this exists to solve

Every fix you apply by hand to a Hiddify box gets quietly undone.

`/opt/hiddify-manager/common/install.sh` runs on **every apply-config, every update, and every
reboot** (via `/etc/cron.d/hiddify_reinstall_on_reboot`). On each run it:

- re-links its own `sysctl.conf` into `/etc/sysctl.d/` and runs `sysctl --system`
- then **imperatively** runs `sysctl -w net.ipv6.conf.*.disable_ipv6=0`
- rebuilds the iptables ruleset from scratch
- re-renders every xray / sing-box config from its `.j2` templates

Two consequences that catch people out:

1. **A file in `/etc/sysctl.d/` alone can never hold a value that `install.sh` also sets with
   `sysctl -w`.** The file is applied, and then overwritten seconds later by the imperative
   write. Your config looks correct on disk while the live kernel value is the opposite.
2. **Any iptables rule you add is simply gone** after the next apply-config.

So this toolkit does two things. Files it owns are named `zz-*` so that when Hiddify *does* run
`sysctl --system`, ours sort last and win. And everything else is re-asserted by a single
systemd timer, `hiddify-toolkit-guard.timer`, which re-runs the `reassert` step of every enabled
module every 2 minutes.

That timer is the heart of the design. Measured healing times after a real apply-config are in
the 35–65 second range.

---

## Modules

| # | Module | id | What it does |
|---|--------|-----|--------------|
| 1 | Kernel & network tuning | `tuning` | Hiddify pins `sysctl` values for a small VM and they never scale when you resize. Re-computes `tcp_mem`, TIME_WAIT buckets, conntrack, `file-max`, backlogs and ephemeral ports from actual RAM/CPU; preloads `nf_conntrack` (Hiddify's `net.netfilter.*` lines silently fail without it); turns on RPS/RFS (a single-queue virtio NIC otherwise pins all packet work to one core); adds the logrotate Hiddify ships without; stops the `hiddify-cli` crash loop. |
| 2 | Disable IPv6 permanently | `ipv6` | For boxes with no working IPv6, where dual-stack services (Google/Gemini) break because clients push AAAA traffic the server cannot route. Beats Hiddify's `sysctl -w …=0`, which no config file can. |
| 3 | Reality domain ALPN fix | `reality-alpn` | Lets the panel accept Reality SNI domains that only speak `http/1.1`. Patches panel code, so a Hiddify **update** wipes it — the guard notices and re-applies. |
| 4 | Choose the outbound IP | `outbound-ip` | Detects every IPv4 on the box, lets you pick one, and sends all **outbound** traffic through it while **inbound stays on the existing address** — no DNS change, no client-config change. Use it when your main IP picks up a bad reputation and a service starts refusing it. |

Every module has **apply** and **revert to previous state**, and every apply is verified —
if verification fails, the change is rolled back automatically instead of being left half-live.

---

## Usage

```
hiddify-toolkit                 # the menu
hiddify-toolkit status          # state of every module
hiddify-toolkit apply  ipv6     # non-interactive, for your own scripts
hiddify-toolkit revert ipv6
hiddify-toolkit reassert        # what the guard timer calls
hiddify-toolkit update          # pull the newest version, keep state
hiddify-toolkit uninstall       # revert everything, then remove the toolkit
```

State lives in `/var/lib/hiddify-toolkit`:

```
enabled/<id>      marker: this module is on, so the guard re-asserts it
conf/<id>.conf    module settings (e.g. which outbound IP you chose)
backup/<id>/      pristine copies of every file the module touched, taken once
toolkit.log       what was applied/reverted, and when
```

`backup/` is written **once per file**. Re-applying never overwrites a pristine baseline with an
already-modified copy — that is exactly how a revert silently starts restoring the broken state.

---

## Adding a module

Drop a file in `modules/`, named `<NN>-<id>.sh`. `NN` orders it in the menu. It is a sourced
library — no shebang logic, no `main()`:

```bash
MOD_ID="example"
MOD_TITLE="Human readable title"
MOD_TITLE_FA="عنوان فارسی"
MOD_DESC="One sentence describing what this changes."
MOD_GUARD=yes                 # yes => mod_reassert runs every 2 min while enabled

mod_status()   { ... ; echo "APPLIED"; }   # last line's FIRST word: APPLIED|ABSENT|PARTIAL
mod_apply()    { ... }                     # 0 = success
mod_verify()   { ... }                     # 0 = success; non-zero makes the core auto-revert
mod_revert()   { ... }
mod_reassert() { ... }                     # quiet, idempotent, fast
mod_adopt()    { ... }                     # OPTIONAL, see below
```

`mod_adopt` is called when the toolkit finds a module already **APPLIED** on a box it never
applied it to (the standalone scripts that predate this toolkit, a rebuilt server) and adopts
it so the guard protects it. Adoption never runs `mod_apply`, so anything `mod_apply` would
have *recorded* — a rollback baseline above all — was never recorded, and a later revert then
silently leaves the change live. Implement `mod_adopt` to do that bookkeeping, and only that:
it must not change the box.

Helpers available from the core: `say ok warn err dim`, `ht_conf_get` / `ht_conf_set`,
`ht_backup` / `ht_backup_dir`, `ht_is_hiddify`, `ht_state_dir`.

Two rules worth internalising, both learned the hard way on production boxes:

- **`mod_reassert` must never restart a service unless it actually re-applied something.**
  It runs every 2 minutes; a naive implementation becomes a 2-minute restart loop.
- **Insert firewall rules, do not append them.** Hiddify's firewall carries a blanket
  `-A OUTPUT -p tcp -j ACCEPT`; anything appended after it never matches.

---

## Safety

- Every module is verified after apply and **auto-reverted** if the verification fails.
- The `outbound-ip` module additionally proves the live user tunnel still answers before it
  keeps a change, so a bad IP cannot silently black-hole your customers.
- Nothing here touches xray, HAProxy, nginx or the database. `reality-alpn` restarts
  `hiddify-panel` (admin UI + subscription serving blink for a few seconds; active VPN sessions
  go through HAProxy/xray and are unaffected) and only when it actually re-patched.
- Requires root, Ubuntu 22.04/24.04, systemd, `iptables`.

## License

MIT
