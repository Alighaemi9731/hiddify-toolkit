from __future__ import annotations

import re, ipaddress, ssl, socket, time

def _check_domain_ips(model: Domain, server_ips) -> None:
    if (model.domain.startswith("*") or not model.domain) and model.mode not in [DomainType.direct]:
        return
    if model.fake_mode in (FakeMode.fake, FakeMode.reality, FakeMode.dns):
        return
    if model.mode in [DomainType.relay]:
        return
    try:
        dips = hutils.network.get_domain_ips(model.domain)
    except Exception as e:
        logger.error(f"Error resolving domain {model.domain}: {str(e)}")
        raise DomainRuleError(_("Domain cannot be resolved! Please check DNS settings"))
    if not dips:
        raise DomainRuleError(_("Domain cannot be resolved! Please check DNS settings"))

    domain_ip_matches_server = any(ip in dips for ip in server_ips)
    server_ips_str = ", ".join(map(str, server_ips))
    dips_str = ", ".join(map(str, dips))
    if not domain_ip_matches_server and model.mode in [DomainType.direct]:
        raise DomainRuleError(_("Domain IP=%(domain_ip)s is not matched with your ip=%(server_ip)s which is required in direct mode", server_ip=server_ips_str, domain_ip=dips_str))
    if domain_ip_matches_server and model.mode in [DomainType.cdn, DomainType.relay]:
        raise DomainRuleError(_("In CDN mode, Domain IP=%(domain_ip)s should be different to your ip=%(server_ip)s", server_ip=server_ips_str, domain_ip=dips_str))
