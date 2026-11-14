from __future__ import annotations

import re, ipaddress, ssl, socket, time

def is_domain_support_h2_tls13(sni: str, server: str = "") -> bool:
    try:
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        context.options |= ssl.OP_NO_COMPRESSION
        context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")
        context.set_alpn_protocols(["h2"])
        start_time = time.monotonic()
        with socket.create_connection((server or sni, 443), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=sni) as ssock:
                elapsed_time = time.monotonic() - start_time
                valid = ssock.version() == "TLSv1.3"
                if valid:
                    if int(max(1, elapsed_time * 1000)):
                        return True
                return False
    except Exception as e:
        print(f"{sni} {e}")
        return False
