#!/usr/bin/env python3
"""Hiddify Toolkit 2: six opt-in/default features for the Hiddify 14.2 layout."""
import argparse
import ast
from contextlib import contextmanager
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
MANAGER = Path(os.environ.get('HT_MANAGER', '/opt/hiddify-manager'))
STATE = Path(os.environ.get('HT_STATE', '/var/lib/hiddify-toolkit'))
SYSTEMD = Path('/etc/systemd/system')
DEFAULTS = ('reality-alpn', 'fakedomain-dot', 'cdn-same-ip', 'direct-any-ip')
FEATURES = {
    'reality-alpn': 'Offer h2 and http/1.1 for Reality checks',
    'outbound-ip': 'Choose an already-assigned outbound IPv4 (optional)',
    'fakedomain-dot': 'Allow one trailing dot in domain names',
    'cdn-same-ip': 'Allow CDN domains resolving to this server',
    'direct-any-ip': 'Allow Direct domains resolving to another IP',
    'port-alias': 'Keep legacy client ports working (optional)',
}
# Exact replacements are constrained to the expected AST node and are independent.
PATCHES = {
    'reality-alpn': ('hutils/network/net.py', 'is_domain_support_h2_tls13',
        'context.set_alpn_protocols(["h2"])',
        'context.set_alpn_protocols(["h2", "http/1.1"])  # hiddify-toolkit:reality-alpn'),
    'fakedomain-dot': ('panel/commercial/restapi/v2/admin/domains_page_api.py', 'DOMAIN_RE',
        'DOMAIN_RE = re.compile(r"^(\\*\\.)?([A-Za-z0-9\\-\\.]+\\.[a-zA-Z]{2,})$")',
        'DOMAIN_RE = re.compile(r"^(\\*\\.)?([A-Za-z0-9\\-\\.]+\\.[a-zA-Z]{2,}\\.?)$")  # hiddify-toolkit:fakedomain-dot'),
    'cdn-same-ip': ('panel/domain_rules.py', '_check_domain_ips',
        'if domain_ip_matches_server and model.mode in [DomainType.cdn, DomainType.relay]:',
        'if domain_ip_matches_server and model.mode in [DomainType.relay]:  # hiddify-toolkit:cdn-same-ip'),
    'direct-any-ip': ('panel/domain_rules.py', '_check_domain_ips',
        'if not domain_ip_matches_server and model.mode in [DomainType.direct]:',
        'if False:  # hiddify-toolkit:direct-any-ip'),
}
class AliasConflict(ValueError):
    pass


GUARD = 'hiddify-toolkit-guard'
BOOT = 'hiddify-toolkit-network'
DROPIN = SYSTEMD/'hiddify-panel.service.d/90-hiddify-toolkit.conf'
TABLES = {'port-alias': ('inet', 'hiddify_toolkit_ports'), 'outbound-ip': ('ip', 'hiddify_toolkit_egress')}


def run(args, *, check=True, timeout=20, data=None):
    p = subprocess.run([str(a) for a in args], input=data, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f'{args[0]} failed: {p.stderr.strip()[:400] or p.stdout.strip()[:400]}')
    return p


def atomic(path, text, mode=0o600):
    path = Path(path)
    if path.exists() and path.read_text() == text:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    old = path.stat() if path.exists() else None
    fd, name = tempfile.mkstemp(prefix='.ht-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), old.st_mode & 0o777 if old else mode)
            if old:
                os.fchown(stream.fileno(), old.st_uid, old.st_gid)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)
    return True


def read_config():
    p = STATE/'settings.json'
    return json.loads(p.read_text()) if p.exists() else {'enabled': [], 'aliases': [], 'outbound': None}


def write_config(conf):
    atomic(STATE/'settings.json', json.dumps(conf, indent=2) + '\n')


@contextmanager
def lock(name):
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (STATE/(name+'.lock')).open('a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def supported():
    version = (MANAGER/'VERSION').read_text().strip()
    if not re.fullmatch(r'14\.2\.\d+', version):
        raise ValueError(f'Hiddify {version} is unsupported by Toolkit 2 (validated on 14.2.0; requires 14.2.x layout)')
    candidates = list(MANAGER.glob('.venv*/lib/python*/site-packages/hiddifypanel'))
    if len(candidates) != 1:
        raise ValueError('Expected exactly one installed hiddifypanel package')
    package = candidates[0].resolve()
    python = candidates[0].parents[3]/'bin/python'
    if not python.is_file() or not (package/'panel/domain_rules.py').is_file():
        raise ValueError('Unsupported panel interpreter or source layout')
    return package, python


def transform(feature, source, remove=False):
    _, scope, original, patched = PATCHES[feature]
    old, new = (patched, original) if remove else (original, patched)
    tree = ast.parse(source)
    nodes = [n for n in ast.walk(tree) if (
        isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == scope
        or isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == scope for t in n.targets))]
    if len(nodes) != 1:
        raise ValueError(f'{feature}: expected one {scope} definition')
    segment = '\n'.join(source.splitlines()[nodes[0].lineno - 1:nodes[0].end_lineno])
    if source.count(old) == 0 and source.count(new) == 1 and new in segment:
        return source
    if source.count(old) != 1 or source.count(new) or old not in segment:
        raise ValueError(f'{feature}: unknown/ambiguous source; no changes written')
    result = source.replace(old, new, 1)
    compile(result, '<patched-panel>', 'exec')
    return result


def patch_files(conf):
    """Validate the whole batch before writing; exact inverses preserve other edits."""
    package, python = supported()
    documents = {}
    for feature, (relative, _, _, _) in PATCHES.items():
        path = package/relative
        documents.setdefault(path, path.read_text())
        documents[path] = transform(feature, documents[path], feature not in conf['enabled'])
    originals = {p: p.read_text() for p in documents}
    # Use the running panel's interpreter to compile without pycache or imports.
    for path, content in documents.items():
        if content == originals[path]:
            continue
        run([python, '-c', 'import sys; compile(sys.stdin.read(), sys.argv[1], "exec")', path], data=content)
    written = []
    try:
        for path, content in documents.items():
            if content == originals[path]:
                continue
            relative = path.relative_to(package)
            backup = STATE/'backup'/relative
            if not backup.exists():
                atomic(backup, originals[path])
            atomic(path, content)
            written.append(path)
            for cached in (path.parent/'__pycache__').glob(path.stem+'.*.pyc'):
                cached.unlink()
    except Exception:
        for path in written:
            atomic(path, originals[path])
        raise
    return bool(written)


def panel_active():
    return run(['systemctl', 'is-active', '--quiet', 'hiddify-panel'], check=False).returncode == 0


def panel_ready():
    if not panel_active():
        return False
    return run(['curl', '-s', '--max-time', '2', '-o', '/dev/null', 'http://127.0.0.1:9000/'], check=False, timeout=4).returncode == 0


def restart_panel():
    run(['systemctl', 'restart', 'hiddify-panel'], timeout=180)
    for _ in range(30):
        if panel_ready():
            return
        time.sleep(1)
    raise RuntimeError('Panel did not respond after restart; inspect journalctl -u hiddify-panel')


def installation_busy(directory=Path('/run/hiddify/locks')):
    # Hiddify uses flock: file existence is not evidence of an active installation.
    for path in directory.glob('*install*.lock'):
        with path.open('r') as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(stream, fcntl.LOCK_UN)
            except BlockingIOError:
                return True
    return False


def parse_aliases(value):
    pairs = []
    used = set()
    for entry in value.split(','):
        if not re.fullmatch(r'[1-9]\d{0,4}:(80|443)', entry):
            raise ValueError('Use OLD:80 or OLD:443, comma-separated; only HTTP/TLS gateway targets are supported')
        old, target = map(int, entry.split(':'))
        if old > 65535 or old < 1024 or old in {3306, 6379, 9000} or old in used:
            raise ValueError('Old ports must be unique, unprivileged and not reserved panel/system ports')
        used.add(old)
        pairs.append([old, target])
    if not pairs:
        raise ValueError('Specify at least one alias')
    return sorted(pairs)


def validate_aliases(conf, require_listener=True):
    if 'port-alias' not in conf['enabled']:
        return
    # Only gateway targets avoid chains with Hiddify's per-domain redirects.
    for old, target in conf['aliases']:
        parse_aliases(f'{old}:{target}')
        listening = run(['ss', '-Hltn']).stdout
        if require_listener and not any(line.split()[3].endswith(':'+str(target)) for line in listening.splitlines()):
            raise ValueError(f'Target TCP/{target} is not listening')
        if any(line.split()[3].endswith(':'+str(old)) for line in listening.splitlines()):
            raise AliasConflict(f'TCP/{old} is already in use; refusing to intercept it')
    generated = MANAGER/'generated/firewall.sh'
    source = generated.read_text() if generated.exists() else ''
    # Known literal arguments in the panel-rendered firewall. Unknown format fails closed.
    matches = re.findall(r'^redirect_domain_ports\s+"([\d ]*)"\s+"([\d ]*)"', source, re.M)
    if len(matches) != 1:
        raise ValueError('Cannot prove current per-domain ports; apply panel configs first')
    domain_ports = {int(p) for group in matches[0] for p in group.split()}
    if domain_ports & {p[0] for p in conf['aliases']}:
        raise AliasConflict('An old port is owned by a domain in the panel; refusing to override it')


def route_info():
    route = json.loads(run(['ip', '-j', '-4', 'route', 'get', '1.1.1.1']).stdout)[0]
    iface, source = route['dev'], route.get('prefsrc', route.get('src'))
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', iface) or not source:
        raise ValueError('Unsupported default route/interface')
    addresses = json.loads(run(['ip', '-j', '-4', 'addr', 'show', 'dev', iface]).stdout)
    ips = [a['local'] for row in addresses for a in row['addr_info'] if a['family'] == 'inet']
    return iface, source, ips


def validate_outbound(conf):
    if 'outbound-ip' not in conf['enabled']:
        return
    chosen = conf['outbound']
    selected = ipaddress.IPv4Address(chosen['ip'])
    primary = ipaddress.IPv4Address(chosen['source'])
    iface, source, ips = route_info()
    if not selected.is_global or not primary.is_global or str(selected) == str(primary):
        raise ValueError('Outbound IP must be a different public IPv4 already assigned to the default-route interface')
    if str(selected) not in ips:
        raise ValueError('Selected outbound IP is not assigned to the default-route interface')
    if chosen['interface'] != iface or chosen['source'] != source:
        raise ValueError('Default route/address changed; refusing to apply a stale outbound-IP choice')


def network_script(feature, conf):
    family, table = TABLES[feature]
    if feature == 'port-alias':
        chains = []
        for name, hook in [('prerouting', 'prerouting'), ('output', 'output')]:
            rules = '\n'.join(f'fib daddr type local tcp dport {old} redirect to :{target} comment "hiddify-toolkit:port-alias"' for old, target in conf['aliases'])
            chains.append(f'chain {name} {{ type nat hook {hook} priority -99; policy accept;\n{rules}\n}}')
        return f'table {family} {table} {{\n'+'\n'.join(chains)+'\n}\n'
    c = conf['outbound']
    # Only original IPv4 flows originating at the default public IP; never LAN/local destinations.
    return f'''table {family} {table} {{
 chain postrouting {{ type nat hook postrouting priority 99; policy accept;
  ip saddr {c['source']} oifname "{c['interface']}" fib daddr type != local ip daddr != {{ 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4 }} ct direction original snat to {c['ip']} comment "hiddify-toolkit:outbound-ip"
 }}
}}
'''


def table_text(feature):
    family, table = TABLES[feature]
    p = run(['nft', '-s', 'list', 'table', family, table], check=False)
    return p.stdout if p.returncode == 0 else ''


def network_sync(conf, validate=True, boot=False):
    if validate:
        validate_aliases(conf, require_listener=not boot)
        validate_outbound(conf)
    for feature, (family, table) in TABLES.items():
        live = table_text(feature)
        receipt = STATE/(feature+'-receipt.json')
        if feature not in conf['enabled']:
            if live:
                run(['nft', 'delete', 'table', family, table])
            receipt.unlink(missing_ok=True)
            continue
        desired = network_script(feature, conf)
        previous = json.loads(receipt.read_text()) if receipt.exists() else {}
        if live and previous == {'desired': desired, 'live': live}:
            continue
        batch = (f'delete table {family} {table}\n' if live else '')+desired
        run(['nft', '-c', '-f', '-'], data=batch)
        run(['nft', '-f', '-'], data=batch)
        atomic(receipt, json.dumps({'desired': desired, 'live': table_text(feature)}))


def units(install=True):
    paths = [DROPIN, SYSTEMD/(GUARD+'.service'), SYSTEMD/(GUARD+'.timer'), SYSTEMD/(BOOT+'.service')]
    if not install:
        run(['systemctl', 'disable', '--now', GUARD+'.timer', BOOT+'.service'], check=False)
        run(['systemctl', 'stop', GUARD+'.service'], check=False)
        for path in paths:
            path.unlink(missing_ok=True)
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'reset-failed', GUARD+'.service', GUARD+'.timer', BOOT+'.service'], check=False)
        return
    helper = ROOT/'lib/toolkit.py'
    common = f'Environment=HT_STATE={STATE}\nEnvironment=HT_MANAGER={MANAGER}\n'
    payloads = [
        '[Service]\n'+common+f'ExecStartPre=-+/usr/bin/python3 {helper} prepare\n',
        '[Unit]\nDescription=Repair enabled Hiddify Toolkit 2 features\n[Service]\nType=oneshot\nTimeoutStartSec=240\n'+common+f'ExecStart=/usr/bin/python3 {helper} reassert\n',
        '[Unit]\nDescription=Check Hiddify Toolkit 2 features every minute\n[Timer]\nOnBootSec=30s\nOnUnitActiveSec=60s\nAccuracySec=5s\n[Install]\nWantedBy=timers.target\n',
        '[Unit]\nDescription=Restore Hiddify Toolkit optional network rules\nAfter=network-online.target\nWants=network-online.target\nBefore=hiddify-haproxy.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\n'+common+f'ExecStart=/usr/bin/python3 {helper} network-prepare\n[Install]\nWantedBy=multi-user.target\n',
    ]
    changed = False
    for path, payload in zip(paths, payloads):
        changed = atomic(path, payload, 0o644) or changed
    if changed:
        run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', GUARD+'.timer'])
    # A boot rule is needed only if an optional networking feature is enabled.
    conf = read_config()
    run(['systemctl', 'enable' if any(f in conf['enabled'] for f in TABLES) else 'disable', BOOT+'.service'], check=False)


def change(conf, old, install_units=True):
    # Invalid network inputs fail before any panel file or state is touched.
    validate_aliases(conf)
    validate_outbound(conf)
    active = panel_active()
    prepared = False
    try:
        with lock('files'):
            changed = patch_files(conf)
            prepared = True
            network_sync(conf, validate=False)
            write_config(conf)
        if install_units:
            units()
        if changed and active:
            restart_panel()
    except Exception:
        if prepared:
            with lock('files'):
                reverted = patch_files(old)
                network_sync(old, validate=False)
                write_config(old)
            if active and (changed or reverted):
                restart_panel()
        raise


def bootstrap():
    supported()
    if installation_busy():
        raise ValueError("Panel Apply/update is active; retry after it finishes")
    legacy = STATE/'enabled'
    if legacy.exists() and any(legacy.iterdir()):
        raise ValueError('Legacy Toolkit 1 state exists: revert/uninstall version 1 before installing Toolkit 2')
    old = read_config()
    conf = json.loads(json.dumps(old))
    if not conf.get('initialized'):
        conf['enabled'] = list(DEFAULTS)
        conf['initialized'] = True
    try:
        change(conf, old)
    except Exception:
        if not old.get('initialized'):
            units(False)
        raise
    print('Toolkit 2 installed: four built-in defaults; optional networking preserves its saved choices.')


def reassert(prepare=False, network_only=False):
    supported()
    if not prepare and not network_only and installation_busy():
        print('Panel installation is active; waiting for the next guard tick.')
        return
    conf = read_config()
    network_error = None
    with lock('files'):
        changed = False if network_only else patch_files(conf)
        if not prepare:
            try:
                network_sync(conf, boot=network_only)
            except AliasConflict as exc:
                # The panel owns a formerly unused port now: release our table.
                family, table = TABLES['port-alias']
                if table_text('port-alias'):
                    run(['nft', 'delete', 'table', family, table])
                (STATE/'port-alias-receipt.json').unlink(missing_ok=True)
                network_error = exc
    if changed and not prepare and panel_active():
        restart_panel()
    if network_error:
        raise network_error


def status():
    package, _ = supported()
    conf = read_config()
    for i, (feature, title) in enumerate(FEATURES.items(), 1):
        enabled = feature in conf['enabled']
        applied = False
        try:
            if feature in PATCHES:
                source = (package/PATCHES[feature][0]).read_text()
                applied = transform(feature, source) == source
            elif enabled:
                receipt = STATE/(feature+'-receipt.json')
                applied = receipt.exists() and json.loads(receipt.read_text()) == {'desired': network_script(feature, conf), 'live': table_text(feature)} and bool(table_text(feature))
        except (ValueError, OSError):
            pass
        state = 'APPLIED' if enabled and applied else 'DRIFTED' if enabled else 'OFF'
        print(f'{i}. {feature:18s} {state:8s} {title}')
    print('Panel:', 'responding' if panel_ready() else 'not responding')
    if conf['aliases']:
        print('Saved aliases:', conf['aliases'])
    if conf['outbound']:
        print('Saved outbound:', conf['outbound']['ip'])


def activate(feature, args):
    supported()
    if installation_busy():
        raise ValueError('Panel Apply/update is active; retry after it finishes')
    old = read_config()
    conf = json.loads(json.dumps(old))
    if feature == 'port-alias':
        conf['aliases'] = parse_aliases(args.aliases or os.environ.get('PORT_ALIASES', ''))
    elif feature == 'outbound-ip':
        iface, source, _ = route_info()
        selected = args.ip or os.environ.get('OUTBOUND_IP', '')
        conf['outbound'] = {'ip': selected, 'source': source, 'interface': iface}
        # Prove the provider routes the assigned IP before enabling any SNAT rule.
        validate_outbound(dict(conf, enabled=list(set(conf['enabled']) | {feature})))
        probe = run(['curl', '-4', '-fsS', '--max-time', '12', '--interface', selected, 'https://api.ipify.org'], timeout=15)
        if probe.stdout.strip() != selected:
            raise ValueError('Selected IP is not the observed public exit; refusing to change egress')
    conf['enabled'] = sorted(set(conf['enabled']) | {feature})
    change(conf, old)
    if feature == 'outbound-ip':
        try:
            probe = run(['curl', '-4', '-fsS', '--max-time', '12', 'https://api.ipify.org'], timeout=15)
            if probe.stdout.strip() != conf['outbound']['ip']:
                raise ValueError('SNAT exit verification failed')
        except Exception:
            change(old, conf)
            raise
    print(feature+': applied and verified')


def revert(feature):
    supported()
    if installation_busy():
        raise ValueError('Panel Apply/update is active; retry after it finishes')
    old = read_config()
    conf = json.loads(json.dumps(old))
    conf['enabled'] = [f for f in conf['enabled'] if f != feature]
    change(conf, old)
    print(feature+': reverted; stays disabled on reinstall')


def uninstall():
    supported()
    if installation_busy():
        raise ValueError('Panel Apply/update is active; retry after it finishes')
    old = read_config()
    conf = dict(old, enabled=[])
    change(conf, old, install_units=False)
    units(False)
    Path('/usr/local/bin/hiddify-toolkit').unlink(missing_ok=True)
    shutil.rmtree(STATE)
    shutil.rmtree(ROOT)
    print('All Toolkit 2 patches, units, owned network tables and local files removed.')


def menu():
    while True:
        status()
        choice = input('\nFeature number, u=update, x=uninstall, q=quit: ').strip()
        if choice == 'q':return
        if choice == 'u':
            run(['bash', ROOT/'install.sh', '--no-menu'], timeout=360)
            return
        if choice == 'x':
            if input('Type YES to uninstall: ') == 'YES':
                with lock('lifecycle'):uninstall()
                return
            continue
        if not choice.isdigit() or not 1 <= int(choice) <= len(FEATURES):continue
        feature = list(FEATURES)[int(choice)-1]
        action = input('a=apply, r=revert, Enter=back: ').strip()
        try:
            if action == 'r':
                with lock('lifecycle'):revert(feature)
            elif action == 'a':
                opts = argparse.Namespace(aliases=None, ip=None)
                if feature == 'port-alias':opts.aliases = input('Aliases OLD:80 or OLD:443 (comma separated): ').strip()
                if feature == 'outbound-ip':
                    print('Assigned addresses:', route_info())
                    opts.ip = input('Existing public IPv4 to use: ').strip()
                with lock('lifecycle'):activate(feature, opts)
        except Exception as exc:print('Error:', exc)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', nargs='?', default='menu', choices=['menu','status','apply','revert','bootstrap','prepare','reassert','network-prepare','uninstall','version','update','preflight'])
    parser.add_argument('feature', nargs='?', choices=list(FEATURES))
    parser.add_argument('--aliases')
    parser.add_argument('--ip')
    args = parser.parse_args()
    if args.command == 'version':
        print((ROOT/'VERSION').read_text().strip());return
    if args.command == 'preflight':
        package, _ = supported()
        for feature, (relative, _, _, _) in PATCHES.items():
            transform(feature, (package/relative).read_text())
        print('Hiddify 14.2 layout and all four patch signatures verified');return
    if os.geteuid() != 0:raise ValueError('Run as root')
    if args.command in ['apply','revert'] and not args.feature:parser.error('Specify a feature')
    if args.command == 'status':status();return
    if args.command == 'prepare':reassert(prepare=True);return
    # Panel ExecStartPre only takes the file lock, so a restart cannot deadlock this lock.
    if args.command == 'menu':
        menu();return
    with lock('lifecycle'):
        if args.command == 'bootstrap':bootstrap()
        elif args.command in ['reassert','network-prepare']:reassert(network_only=args.command=='network-prepare')
        elif args.command == 'apply':activate(args.feature,args)
        elif args.command == 'revert':revert(args.feature)
        elif args.command == 'uninstall':uninstall()
        elif args.command == 'menu':menu()
        elif args.command == 'update':
            raise ValueError('Run: bash /opt/hiddify-toolkit/install.sh --no-menu (installer handles its own lifecycle)')


if __name__ == '__main__':
    try:main()
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print('Error: '+str(exc),file=sys.stderr)
        sys.exit(1)
