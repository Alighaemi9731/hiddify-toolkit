#!/usr/bin/env python3
"""Narrow, reversible Hiddify 12 Direct domain-IP validation patch."""
import argparse
import ast
import os
from pathlib import Path
import stat
import tempfile

OLD = 'if not domain_ip_matches_server and model.mode in [DomainType.direct]:'
NEW = 'if False:  # hiddify-toolkit:direct-any-ip (allow a different origin IP)'


def transform(source, remove=False):
    ast.parse(source)
    old, new = (NEW, OLD) if remove else (OLD, NEW)
    if source.count(old) == 0 and source.count(new) == 1:
        return source
    if source.count(old) != 1 or source.count(new):
        raise ValueError('Unknown or ambiguous DomainAdmin validation; refusing to patch')
    tree = ast.parse(source)
    matches = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == '_validate_domain_ips']
    if len(matches) != 1:
        raise ValueError('Expected one _validate_domain_ips method')
    lines = source.splitlines()
    method = matches[0]
    if not any(old in line for line in lines[method.lineno - 1:method.end_lineno]):
        raise ValueError('Validation marker outside expected method')
    result = source.replace(old, new, 1)
    compile(result, 'DomainAdmin.py', 'exec')
    return result


def rewrite(path, remove=False):
    path = Path(path).resolve()
    source = path.read_text()
    result = transform(source, remove)
    if result == source:
        return False
    info = path.stat()
    fd, temporary = tempfile.mkstemp(prefix='.ht-direct-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            output.write(result)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), stat.S_IMODE(info.st_mode))
            os.fchown(output.fileno(), info.st_uid, info.st_gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    for cached in (path.parent / '__pycache__').glob('DomainAdmin.*.pyc'):
        cached.unlink()
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['apply', 'revert', 'check'])
    parser.add_argument('path')
    args = parser.parse_args()
    if args.action == 'check':
        source = Path(args.path).read_text()
        if transform(source) != source:
            raise SystemExit(1)
    else:
        print('changed' if rewrite(args.path, args.action == 'revert') else 'unchanged')
