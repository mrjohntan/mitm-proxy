import datetime
import json
import os
import sys

# Ensure config directory is in python path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from matcher import DomainMatcher

try:
    from mitmproxy import ctx, http, tls
except ImportError:
    # Allow testing and execution without mitmproxy package installed
    ctx = None
    http = None
    tls = None


class EgressWhitelistAddon:
    def __init__(self, config_path: str = None):
        if not config_path:
            config_path = os.path.join(CURRENT_DIR, "whitelist.yaml")
        self.matcher = DomainMatcher(config_path)

    def _make_blocked_response(self, host: str):
        body = {
            "status": "error",
            "code": 403,
            "message": f"Egress proxy blocked: target host '{host}' is not in the approved egress whitelist.",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        raw_json = json.dumps(body, indent=2).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "X-Egress-Policy": "Blocked",
            "Connection": "close",
        }
        if http and hasattr(http, "Response") and hasattr(http.Response, "make"):
            return http.Response.make(403, raw_json, headers)
        else:
            # Fallback response object when running in pure python test environment
            resp = type("MockResponse", (), {})()
            resp.status_code = 403
            resp.content = raw_json
            resp.headers = headers
            return resp

    def http_connect(self, flow):
        """Intercepts HTTPS CONNECT tunnels."""
        host = flow.request.host
        port = flow.request.port
        target = f"{host}:{port}"

        if not self.matcher.is_allowed(host):
            if ctx:
                ctx.log.warn(f"[BLOCKED] CONNECT {target} - host not whitelisted")
            flow.response = self._make_blocked_response(host)
        else:
            if ctx:
                ctx.log.info(f"[ALLOWED] CONNECT {target} - whitelisted")

    def tls_clienthello(self, data):
        """Bypasses TLS decryption for whitelisted connections."""
        sni = getattr(data.context.client, "sni", None)
        server_addr = getattr(data.context.server, "address", None)
        host = sni or (server_addr[0] if server_addr else None)

        if host and self.matcher.is_allowed(host):
            # Instruct mitmproxy to pass through TLS raw without decrypting
            data.ignore_connection = True

    def request(self, flow):
        """Intercepts plain HTTP requests."""
        # CONNECT flows already handled in http_connect
        if flow.request.method.upper() == "CONNECT":
            return

        host = flow.request.pretty_host
        if not self.matcher.is_allowed(host):
            if ctx:
                ctx.log.warn(f"[BLOCKED] HTTP {flow.request.method} {host}{flow.request.path}")
            flow.response = self._make_blocked_response(host)
        else:
            if ctx:
                ctx.log.info(f"[ALLOWED] HTTP {flow.request.method} {host}{flow.request.path}")


addons = [EgressWhitelistAddon()]
