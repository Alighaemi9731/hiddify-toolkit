from __future__ import annotations

import re, ipaddress, ssl, socket, time

DOMAIN_RE = re.compile(r"^(\*\.)?([A-Za-z0-9\-\.]+\.[a-zA-Z]{2,})$")

def clean_host(value: str) -> str:
    """A domain as typed (lowercased), or an IPv4 / IPv6 address in its standard form ("[2001:DB8:0::1]" → "2001:db8::1")."""
    name = (value or "").strip().lower()
    try:
        return str(ipaddress.ip_address(name.strip("[]")))
    except ValueError:
        return name

def is_host(name: str) -> bool:
    """A domain name, or any IPv4 / IPv6 address (the regex only took IPv6 written out in full)."""
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return bool(DOMAIN_RE.match(name))
