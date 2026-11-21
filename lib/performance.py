"""Owned TCP capacity and rpxy latency controls for Ubuntu 24.04 / 26.04.

No global TCP_NODELAY switch exists: the tiny native SOCK_OPS helper is attached
only to hiddify-rpxy-l4.service. No packet payloads are inspected.
"""
import collections
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import tempfile
import time
import uuid

FEATURES = ('tcp-memory', 'tcp-timewait', 'rpxy-nodelay')
KEYS = {'tcp-memory': 'net.ipv4.tcp_mem', 'tcp-timewait': 'net.ipv4.tcp_max_tw_buckets'}
OBSERVE_KEYS = ('net.ipv4.tcp_rmem', 'net.ipv4.tcp_wmem', 'net.core.rmem_max', 'net.core.wmem_max',
                'net.ipv4.tcp_congestion_control', 'net.core.default_qdisc', 'net.ipv4.tcp_mtu_probing',
                'net.core.netdev_max_backlog', 'net.core.somaxconn', 'net.netfilter.nf_conntrack_count',
                'net.netfilter.nf_conntrack_max', 'net.ipv4.tcp_moderate_rcvbuf')
SYSCTL_FILE = Path('/etc/sysctl.d/zzzz-hiddify-toolkit-performance.conf')
DROPIN = Path('/etc/systemd/system/hiddify-rpxy-l4.service.d/91-hiddify-toolkit-performance.conf')
PROC = Path('/proc')
CGROUP = Path('/sys/fs/cgroup')
SERVICE = 'hiddify-rpxy-l4.service'
MARKER = '# Managed by Hiddify Toolkit: performance v1\n'
SOURCE = Path(__file__).with_name('nodelay.c')
_probe_cache = None


def run(args, *, check=True, timeout=20):
    p = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f'{args[0]}: {p.stderr.strip()[:800] or p.stdout.strip()[:400]}')
    return p


def atomic(path, text, mode=0o600):
    path = Path(path)
    data = text.encode() if isinstance(text, str) else text
    if path.is_symlink():
        raise ValueError(f'Refusing symlink at owned path: {path}')
    if path.exists() and path.read_bytes() == data:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.ht-performance-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def _owned(path):
    if path.is_symlink() or path.exists() and not path.read_text().startswith(MARKER):
        raise ValueError(f'Unowned performance file: {path}')


def read_value(key):
    text = (PROC/'sys'/key.replace('.', '/')).read_text()
    values = text.split()
    if not values or not all(v.isdigit() for v in values):
        raise ValueError(f'Unexpected numeric kernel parameter: {key}')
    return ' '.join(values)


def write_value(key, value):
    if key not in KEYS.values() or not all(x.isdigit() for x in value.split()):
        raise ValueError('Unknown performance parameter')
    run(['sysctl', '-w', key+'='+value])
    if read_value(key) != value:
        raise RuntimeError('Kernel parameter verification failed: '+key)


def memory_bytes():
    rows = dict(line.split(':', 1) for line in (PROC/'meminfo').read_text().splitlines())
    return int(rows['MemTotal'].split()[0])*1024


def capacity_floors(total, page_size):
    """Heuristic headroom, not reserved memory or a throughput guarantee."""
    if total < 1024**3 or page_size <= 0:
        raise ValueError('TCP capacity profile needs at least 1 GiB RAM')
    high = min(total//8, 1024**3)//page_size
    return {'tcp-memory': f'{high//2} {high*3//4} {high}',
            'tcp-timewait': '262144' if total >= 3*1024**3 else '65536'}


def host_check():
    if platform.system() != 'Linux':
        raise ValueError('Performance controls require Linux')
    release = platform.freedesktop_os_release()
    if release.get('ID') != 'ubuntu' or release.get('VERSION_ID') not in ('24.04', '26.04'):
        raise ValueError('Performance defaults are validated for Ubuntu 24.04 and 26.04')
    return capacity_floors(memory_bytes(), os.sysconf('SC_PAGE_SIZE'))


def service_info():
    p = run(['systemctl', 'show', SERVICE, '-p', 'MainPID', '-p', 'ControlGroup'])
    values = dict(line.split('=', 1) for line in p.stdout.splitlines() if '=' in line)
    group = values.get('ControlGroup', '')
    if group and group != '/system.slice/'+SERVICE:
        raise ValueError('Unexpected rpxy cgroup; refusing to attach')
    return int(values.get('MainPID', 0)), CGROUP/group.lstrip('/') if group else None


def socket_options(pid, *, apply=False, limit=None):
    """Duplicate connected rpxy TCP FDs; retain counts only, never endpoints."""
    if platform.machine() not in ('x86_64', 'aarch64') or not hasattr(os, 'pidfd_open'):
        raise ValueError('Live rpxy socket access needs Linux x86_64/aarch64 and pidfd_open')
    if (PROC/str(pid)/'comm').read_text().strip() != 'rpxy-l4':
        raise ValueError('MainPID is not rpxy-l4')
    if '/system.slice/'+SERVICE not in (PROC/str(pid)/'cgroup').read_text().splitlines()[0]:
        raise ValueError('rpxy MainPID cgroup does not match service')
    libc = ctypes.CDLL(None, use_errno=True)
    counts = collections.Counter()
    pidfd = os.pidfd_open(pid)
    try:
        for entry in list((PROC/str(pid)/'fd').iterdir()):
            try:
                if not os.readlink(entry).startswith('socket:'):
                    continue
                fd = libc.syscall(438, pidfd, int(entry.name), 0)
                if fd < 0:
                    error = ctypes.get_errno()
                    if error in (1, 38):
                        raise PermissionError(error, 'pidfd_getfd unavailable for rpxy')
                    continue
                with socket.socket(fileno=fd) as s:
                    if s.family not in (socket.AF_INET, socket.AF_INET6) or s.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
                        continue
                    try:
                        s.getpeername()
                    except OSError:
                        continue
                    value = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)
                    counts['sampled'] += 1
                    counts['before_on' if value else 'before_off'] += 1
                    if apply and not value:
                        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        counts['updated'] += 1
                    counts['on' if s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) else 'off'] += 1
                    if limit and counts['sampled'] >= limit:
                        break
            except PermissionError:
                raise
            except (FileNotFoundError, ProcessLookupError, OSError):
                counts['closed_during_scan'] += 1
    finally:
        os.close(pidfd)
    if apply and counts['off']:
        raise RuntimeError('rpxy NODELAY verification failed')
    return dict(counts)


def compile_helper(directory):
    compiler = shutil.which('cc') or shutil.which('gcc')
    if not compiler:
        raise ValueError('rpxy-nodelay needs a C compiler (cc/gcc)')
    binary = Path(directory)/'tcp-nodelay'
    run([compiler, '-O2', '-Wall', '-Wextra', '-Werror', SOURCE, '-o', binary], timeout=40)
    return binary


def helper(binary, action, group):
    return json.loads(run([binary, action, group]).stdout)


def probe_nodelay(binary=None):
    """Test actual socket behavior in a temporary, isolated owned cgroup."""
    global _probe_cache
    if _probe_cache:
        return _probe_cache
    if not (CGROUP/'cgroup.controllers').is_file():
        raise ValueError('rpxy-nodelay needs unified cgroup v2')
    pid, group = service_info()
    if pid:
        socket_options(pid, limit=1)  # Capability check, no option changes.
    if not group and not (Path('/etc/systemd/system')/SERVICE).exists():
        raise ValueError('hiddify-rpxy-l4 service is unavailable')
    group = CGROUP/('hiddify-toolkit-test-'+uuid.uuid4().hex)
    test = '''import socket,json,sys,os
from pathlib import Path
Path(sys.argv[1]+'/cgroup.procs').write_text(str(os.getpid()))
listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
client=socket.socket();client.connect(listener.getsockname());accepted,_=listener.accept()
print(json.dumps([client.getsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY),accepted.getsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY)]))
accepted.close();client.close();listener.close()
'''
    with tempfile.TemporaryDirectory(prefix='hiddify-toolkit-bpf-') as directory:
        binary = Path(binary) if binary else compile_helper(directory)
        group.mkdir()
        try:
            def sockets():
                return json.loads(run(['/usr/bin/python3', '-c', test, group]).stdout)
            if sockets() != [0, 0]:
                raise RuntimeError('Unexpected baseline socket behavior')
            helper(binary, 'attach', group)
            if sockets() != [1, 1]:
                raise RuntimeError('Kernel did not apply NODELAY to new sockets')
            if len(helper(binary, 'attach', group)['owned_program_ids']) != 1:
                raise RuntimeError('BPF attach was not idempotent')
            helper(binary, 'detach', group)
            if sockets() != [0, 0]:
                raise RuntimeError('BPF detach did not restore new-socket behavior')
        finally:
            try:
                run([binary, 'detach', group], check=False)
            finally:
                group.rmdir()
    _probe_cache = {'active_and_passive': True, 'idempotent': True, 'detached': True}
    return _probe_cache


def eligible_defaults():
    eligible, skipped = [], {}
    try:
        host_check()
    except (ValueError, OSError) as exc:
        return [], {feature: str(exc) for feature in FEATURES}
    for feature in FEATURES:
        try:
            if feature in KEYS:
                read_value(KEYS[feature])
            else:
                probe_nodelay()
            eligible.append(feature)
        except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
            skipped[feature] = str(exc)
    return eligible, skipped


def preflight(conf, state):
    enabled = set(conf['enabled']) & set(FEATURES)
    if not enabled:
        return
    host_check()
    _owned(SYSCTL_FILE)
    _owned(DROPIN)
    if (SYSCTL_FILE.exists() or DROPIN.exists()) and not (state/'performance.json').exists():
        raise ValueError('Performance sysctl receipt missing; cannot prove original values')
    for feature in enabled & KEYS.keys():
        value = list(map(int, read_value(KEYS[feature]).split()))
        if len(value) != (3 if feature == 'tcp-memory' else 1) or value != sorted(value):
            raise ValueError('Unexpected TCP capacity values')
    if 'rpxy-nodelay' in enabled:
        probe_nodelay(state/'bin/tcp-nodelay' if valid_helper(state) else None)


def valid_helper(state):
    binary, receipt = state/'bin/tcp-nodelay', state/'performance-helper.json'
    if not binary.is_file() or binary.is_symlink() or not receipt.is_file() or receipt.is_symlink():
        return False
    record = json.loads(receipt.read_text())
    return (hashlib.sha256(binary.read_bytes()).hexdigest() == record.get('binary_sha256') and
            hashlib.sha256(SOURCE.read_bytes()).hexdigest() == record.get('source_sha256') and
            record.get('machine') == platform.machine())


def ensure_helper(state):
    receipt = state/'performance-helper.json'
    binary = state/'bin/tcp-nodelay'
    source_hash = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    old = json.loads(receipt.read_text()) if receipt.exists() else {}
    if binary.is_symlink() or receipt.is_symlink():
        raise ValueError('Symlink at owned NODELAY helper path')
    if binary.exists():
        if not old or hashlib.sha256(binary.read_bytes()).hexdigest() != old.get('binary_sha256'):
            raise ValueError('Unowned or modified NODELAY helper')
        if old.get('source_sha256') == source_hash and old.get('machine') == platform.machine():
            return binary, False
    with tempfile.TemporaryDirectory(prefix='hiddify-toolkit-build-') as directory:
        compiled = compile_helper(directory)
        atomic(binary, compiled.read_bytes(), 0o700)
    atomic(receipt, json.dumps({'source_sha256': source_hash, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'machine': platform.machine()}))
    return binary, True


def _restore_file(path, previous, mode):
    if previous is None:
        path.unlink(missing_ok=True)
    else:
        atomic(path, previous, mode)


def sync(conf, state, toolkit):
    """Journal before writes; rollback runtime/file changes on any failure."""
    receipt = state/'performance.json'
    old_bytes = receipt.read_bytes() if receipt.exists() else None
    old = json.loads(old_bytes) if old_bytes else {'parameters': {}, 'nodelay': False}
    enabled = set(conf['enabled']) & set(FEATURES)
    if (SYSCTL_FILE.exists() or DROPIN.exists()) and old_bytes is None:
        raise ValueError('Performance receipt missing; original settings cannot be proved')
    if not enabled and not old['parameters'] and not old.get('nodelay'):
        return {}
    _owned(SYSCTL_FILE)
    _owned(DROPIN)
    floors = host_check() if enabled else {}
    parameters = json.loads(json.dumps(old['parameters']))
    before = {key: read_value(key) for key in set(parameters) | {KEYS[f] for f in enabled if f in KEYS}}
    for feature, key in KEYS.items():
        if feature in enabled and key not in parameters:
            baseline = before[key]
            desired = ' '.join(str(max(a, b)) for a, b in zip(map(int, baseline.split()), map(int, floors[feature].split())))
            parameters[key] = {'original': baseline, 'desired': desired}
    desired_keys = {KEYS[f] for f in enabled if f in KEYS}
    desired_params = {key: value for key, value in parameters.items() if key in desired_keys}
    nd = 'rpxy-nodelay' in enabled
    original_sysfile = SYSCTL_FILE.read_bytes() if SYSCTL_FILE.exists() else None
    original_dropin = DROPIN.read_bytes() if DROPIN.exists() else None
    binary, rebuilt = ensure_helper(state) if nd else (state/'bin/tcp-nodelay', False)
    if nd and old.get('kernel') != platform.release():
        probe_nodelay(binary)
    group = None
    result = {'parameters': desired_params, 'nodelay': nd}
    if nd:
        result['kernel'] = platform.release()
    try:
        state.mkdir(parents=True, exist_ok=True, mode=0o700)
        state.chmod(0o700)
        backup = state/'backup/performance-first.json'
        if not backup.exists():
            atomic(backup, json.dumps({'runtime': before, 'sysctl_file': None if original_sysfile is None else original_sysfile.decode(), 'dropin': None if original_dropin is None else original_dropin.decode()}))
        # Keep originals for disabled keys until runtime restoration has succeeded.
        atomic(receipt, json.dumps(dict(result, parameters=parameters), indent=2))
        if desired_params:
            atomic(SYSCTL_FILE, MARKER+''.join(f'{key} = {entry["desired"]}\n' for key, entry in sorted(desired_params.items())), 0o644)
        else:
            SYSCTL_FILE.unlink(missing_ok=True)
        if nd:
            text = MARKER+'[Service]\n'+f'Environment=HT_STATE={state}\nExecStartPre=-+/usr/bin/python3 {toolkit} performance-prepare\n'
            atomic(DROPIN, text, 0o644)
        else:
            DROPIN.unlink(missing_ok=True)
        if (DROPIN.read_bytes() if DROPIN.exists() else None) != original_dropin:
            run(['systemctl', 'daemon-reload'])
        for key, entry in parameters.items():
            if key in desired_keys:
                if read_value(key) != entry['desired']:
                    write_value(key, entry['desired'])
            elif read_value(key) == entry['desired']:
                write_value(key, entry['original'])
            else:
                print(f'{key}: retained externally changed runtime value')
        pid, group = service_info() if nd or old.get('nodelay') else (0, None)
        if nd and group and group.exists():
            attached = helper(binary, 'status', group)
            reattached = rebuilt or not attached['owned_attached']
            if reattached:
                attached = helper(binary, 'attach', group)
            result['attachment'] = attached
            if pid and (not old.get('nodelay') or old.get('pid') != pid or reattached or not old.get('attachment')):
                result['sockets'] = socket_options(pid, apply=True)
            elif pid:
                result['sockets'] = old.get('sockets', {})
            result['pid'] = pid
        elif nd:
            result['pending_rpxy_start'] = True
        elif old.get('nodelay') and group and group.exists():
            helper(binary, 'detach', group)
        atomic(receipt, json.dumps(result, indent=2))
        return result
    except Exception:
        if nd and not old.get('nodelay') and group and group.exists() and binary.exists():
            run([binary, 'detach', group], check=False)
        for key, value in before.items():
            if read_value(key) != value:
                write_value(key, value)
        _restore_file(SYSCTL_FILE, original_sysfile, 0o644)
        _restore_file(DROPIN, original_dropin, 0o644)
        _restore_file(receipt, old_bytes, 0o600)
        run(['systemctl', 'daemon-reload'], check=False)
        raise


def status(feature, state):
    path = state/'performance.json'
    if not path.exists():
        return False
    record = json.loads(path.read_text())
    try:
        _owned(SYSCTL_FILE)
        _owned(DROPIN)
    except ValueError:
        return False
    if feature in KEYS:
        entry = record['parameters'].get(KEYS[feature])
        return bool(entry and SYSCTL_FILE.exists() and read_value(KEYS[feature]) == entry['desired'] and
                    f'{KEYS[feature]} = {entry["desired"]}\n' in SYSCTL_FILE.read_text())
    binary = state/'bin/tcp-nodelay'
    if not valid_helper(state):
        return False
    pid, group = service_info()
    return bool(record.get('nodelay') and DROPIN.exists() and pid and group and group.exists() and binary.exists() and
                helper(binary, 'status', group)['owned_attached'])


def diagnose(seconds=5):
    """Read-only aggregate counters; no user identities, logs or traffic payloads."""
    def snap():
        lines = (PROC/'net/netstat').read_text().splitlines()+(PROC/'net/snmp').read_text().splitlines()
        counts = {}
        wanted = {'TCPRcvQDrop', 'TCPTimeWaitOverflow', 'TCPMemoryPressures', 'PruneCalled', 'TCPOFODrop', 'ListenDrops', 'ListenOverflows', 'RetransSegs', 'OutSegs'}
        for a, b in zip(lines[::2], lines[1::2]):
            counts.update({k: int(v) for k, v in zip(a.split()[1:], b.split()[1:]) if k in wanted})
        return counts
    a = snap()
    time.sleep(seconds)
    b = snap()
    return {'kernel': platform.release(), 'os': platform.freedesktop_os_release().get('PRETTY_NAME'),
            'mem_total_bytes': memory_bytes(), 'page_size': os.sysconf('SC_PAGE_SIZE'),
            'runtime': {key: (PROC/'sys'/key.replace('.', '/')).read_text().strip()
                        for key in (*KEYS.values(), *OBSERVE_KEYS) if (PROC/'sys'/key.replace('.', '/')).is_file()},
            'sockstat': (PROC/'net/sockstat').read_text(),
            'counter_window_seconds': seconds, 'counter_delta': {k: b[k]-v for k, v in a.items()},
            'qdisc': run(['tc', '-s', 'qdisc', 'show']).stdout, 'socket_summary': run(['ss', '-s']).stdout}
