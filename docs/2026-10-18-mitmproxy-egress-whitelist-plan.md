# Local Egress Whitelist Proxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a local Dockerized mitmproxy setup that enforces an enterprise-simulated egress domain whitelist with TLS passthrough, 403 Forbidden blocking, hot-reloading configuration, web UI visibility, and automated test scripts.

**Architecture:** A containerized `mitmweb` instance runs an explicit forward proxy on port 8080 and dashboard on 8081. A custom Python addon matches destination hosts against `config/whitelist.yaml`. Whitelisted HTTPS connections bypass TLS decryption (`ignore_connection = True`), allowing end-to-end TLS without client CA installation; non-whitelisted destinations are rejected with HTTP 403 Forbidden and a diagnostic JSON payload.

**Tech Stack:** Docker, Docker Compose, `mitmproxy/mitmproxy:latest` (`mitmweb`), Python 3.10+ (PyYAML), Bash, `curl`, macOS Brave Browser.

**Spec:** [`docs/2026-10-18-mitmproxy-egress-whitelist-design.md`](file:///Users/johntan/Projects/mitm%20proxy/docs/2026-10-18-mitmproxy-egress-whitelist-design.md)

## Global Constraints

- All documentation and markdown files must reside in the [`docs/`](file:///Users/johntan/Projects/mitm%20proxy/docs) folder.
- Client applications must connect to HTTPS targets without installing or trusting custom root CA certificates.
- Whitelist rules must support exact domains and wildcards (e.g., `*-dot-asia-southeast1.notebooks.googleusercontent.com`).
- Rule updates in `config/whitelist.yaml` must take effect without restarting the Docker container.
- Non-whitelisted destinations must receive an HTTP 403 Forbidden response with `Content-Type: application/json` and `X-Egress-Policy: Blocked`.

## Review Focus

1. **Port in Host Header / CONNECT Authority:** Clients sending `host:port` (e.g., `cloud.google.com:443` or `example.com:8080`) must match rule `cloud.google.com` correctly after stripping the port.
2. **Case Insensitivity:** Egress targets like `CLOUD.GOOGLE.COM` or `Accounts.Google.Com` must match case-insensitively.
3. **Complex Glob Wildcards:** Prefixed glob wildcards like `*-dot-asia-southeast1.notebooks.googleusercontent.com` must correctly match valid subdomains while rejecting invalid variations.
4. **Invalid YAML Syntax during Hot Reload:** If an operator edits `config/whitelist.yaml` with invalid YAML or empty content, the proxy must catch the error, log a warning, and keep running with the last known valid rule set rather than crashing.
5. **Direct HTTP vs HTTPS CONNECT:** Both plain HTTP `GET http://example.com/` and HTTPS `CONNECT example.com:443` must enforce the identical whitelist and return 403 for blocked destinations.

---

### Task 1: Whitelist Configuration & Matcher Engine

**Files:**
- Create: `config/whitelist.yaml`
- Create: `config/matcher.py`
- Create: `tests/test_matcher.py`

**Interfaces:**
- Produces: `DomainMatcher(config_path: str)` class in `config/matcher.py`
  - `is_allowed(host: str) -> bool`
  - `reload_if_needed() -> bool`
  - `load_rules() -> list[str]`

- [ ] **Step 1: Write failing unit tests for DomainMatcher**

Write tests covering exact match, wildcard glob matching, port stripping, case insensitivity, and corrupt YAML resilience:

```python
# tests/test_matcher.py
import os
import tempfile
import time
import pytest
import yaml

from config.matcher import DomainMatcher

def test_exact_and_wildcard_matching(tmp_path):
    config_file = tmp_path / "whitelist.yaml"
    config_data = {
        "whitelist": [
            "*-dot-asia-southeast1.notebooks.googleusercontent.com",
            "cloudresourcemanager.googleapis.com",
            "compute.googleapis.com",
            "fonts.gstatic.com",
            "accounts.google.com",
            "analytics.google.com",
            "cloud.google.com",
            "cloudconsole-pa.clients6.google.com",
            "cloudusersettings-pa.clients6.google.com",
            "console.cloud.google.com",
            "notebooks.clients6.google.com",
            "www.gstatic.com",
        ],
        "settings": {"default_action": "block"}
    }
    config_file.write_text(yaml.dump(config_data))

    matcher = DomainMatcher(str(config_file))
    
    # Exact matches
    assert matcher.is_allowed("cloud.google.com") is True
    assert matcher.is_allowed("cloud.google.com:443") is True
    assert matcher.is_allowed("CLOUD.GOOGLE.COM:443") is True
    assert matcher.is_allowed("accounts.google.com") is True
    
    # Wildcard matches
    assert matcher.is_allowed("my-notebook-dot-asia-southeast1.notebooks.googleusercontent.com") is True
    assert matcher.is_allowed("test-dot-asia-southeast1.notebooks.googleusercontent.com:443") is True
    
    # Blocked hosts
    assert matcher.is_allowed("example.com") is False
    assert matcher.is_allowed("evil.com:443") is False
    assert matcher.is_allowed("malicious.googleusercontent.com") is False

def test_hot_reload(tmp_path):
    config_file = tmp_path / "whitelist.yaml"
    config_file.write_text(yaml.dump({"whitelist": ["cloud.google.com"]}))

    matcher = DomainMatcher(str(config_file), check_interval_seconds=0)
    assert matcher.is_allowed("cloud.google.com") is True
    assert matcher.is_allowed("added-later.com") is False

    # Simulate edit
    time.sleep(0.05)
    config_file.write_text(yaml.dump({"whitelist": ["cloud.google.com", "added-later.com"]}))
    
    assert matcher.is_allowed("added-later.com") is True

def test_resilience_to_malformed_yaml(tmp_path):
    config_file = tmp_path / "whitelist.yaml"
    config_file.write_text(yaml.dump({"whitelist": ["cloud.google.com"]}))

    matcher = DomainMatcher(str(config_file), check_interval_seconds=0)
    assert matcher.is_allowed("cloud.google.com") is True

    # Break YAML syntax
    time.sleep(0.05)
    config_file.write_text("whitelist: [unclosed list")

    # Should retain previous valid rules without raising unhandled exception
    assert matcher.is_allowed("cloud.google.com") is True
    assert matcher.is_allowed("evil.com") is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_matcher.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'config.matcher'`

- [ ] **Step 3: Create initial whitelist YAML and DomainMatcher implementation**

Create `config/whitelist.yaml`:
```yaml
# Enterprise Simulated Egress Whitelist
whitelist:
  - "*-dot-asia-southeast1.notebooks.googleusercontent.com"
  - "cloudresourcemanager.googleapis.com"
  - "compute.googleapis.com"
  - "fonts.gstatic.com"
  - "accounts.google.com"
  - "analytics.google.com"
  - "cloud.google.com"
  - "cloudconsole-pa.clients6.google.com"
  - "cloudusersettings-pa.clients6.google.com"
  - "console.cloud.google.com"
  - "notebooks.clients6.google.com"
  - "www.gstatic.com"

settings:
  default_action: "block"
  reload_check_seconds: 2
```

Create `config/matcher.py`:
```python
import fnmatch
import logging
import os
import time
import yaml

logger = logging.getLogger("egress_whitelist")

class DomainMatcher:
    def __init__(self, config_path: str, check_interval_seconds: float = 2.0):
        self.config_path = config_path
        self.check_interval_seconds = check_interval_seconds
        self.last_check_time = 0.0
        self.last_mtime = 0.0
        self.rules: list[str] = []
        self.default_action = "block"
        self._load_config(force=True)

    def _load_config(self, force: bool = False) -> bool:
        try:
            if not os.path.exists(self.config_path):
                logger.warning("Whitelist config file not found: %s", self.config_path)
                return False

            mtime = os.path.getmtime(self.config_path)
            if not force and mtime == self.last_mtime:
                return False

            with open(self.config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

            raw_rules = data.get("whitelist", [])
            normalized_rules = [r.strip().lower() for r in raw_rules if isinstance(r, str) and r.strip()]

            settings = data.get("settings", {})
            self.default_action = settings.get("default_action", "block")
            if "reload_check_seconds" in settings:
                try:
                    self.check_interval_seconds = float(settings["reload_check_seconds"])
                except (ValueError, TypeError):
                    pass

            self.rules = normalized_rules
            self.last_mtime = mtime
            logger.info("Loaded %d whitelist domain rule(s) from %s", len(self.rules), self.config_path)
            return True
        except Exception as e:
            logger.error("Error reading whitelist config %s: %s (keeping existing rules)", self.config_path, e)
            return False

    def reload_if_needed(self) -> bool:
        now = time.time()
        if now - self.last_check_time >= self.check_interval_seconds:
            self.last_check_time = now
            return self._load_config(force=False)
        return False

    @staticmethod
    def extract_hostname(target: str) -> str:
        if not target:
            return ""
        host = target.strip().lower()
        # Strip scheme if present
        if "://" in host:
            host = host.split("://", 1)[1]
        # Strip path or query if present
        if "/" in host:
            host = host.split("/", 1)[0]
        # Strip port (handle IPv4/domain:port or IPv6 [::1]:port)
        if host.startswith("[") and "]" in host:
            host = host[1:].split("]", 1)[0]
        elif ":" in host:
            host = host.split(":", 1)[0]
        return host

    def is_allowed(self, target: str) -> bool:
        self.reload_if_needed()
        hostname = self.extract_hostname(target)
        if not hostname:
            return False

        for pattern in self.rules:
            if pattern == hostname or fnmatch.fnmatch(hostname, pattern):
                return True
        return self.default_action == "allow"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_matcher.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add config/whitelist.yaml config/matcher.py tests/test_matcher.py
git commit -m "feat: implement whitelist matcher engine with dynamic reload and test suite"
```

---

### Task 2: mitmproxy Addon Script

**Files:**
- Create: `config/addon.py`
- Create: `tests/test_addon.py`

**Interfaces:**
- Consumes: `DomainMatcher` from `config/matcher.py`
- Produces: `EgressWhitelistAddon` for mitmproxy hook lifecycle:
  - `http_connect(flow: http.HTTPFlow)`
  - `tls_clienthello(data: tls.ClientHelloData)`
  - `request(flow: http.HTTPFlow)`

- [ ] **Step 1: Write unit tests for mitmproxy addon hooks using mock objects**

```python
# tests/test_addon.py
from unittest.mock import MagicMock
import json
import pytest

from config.addon import EgressWhitelistAddon

@pytest.fixture
def addon(tmp_path):
    config_file = tmp_path / "whitelist.yaml"
    config_file.write_text("whitelist:\n  - cloud.google.com\nsettings:\n  default_action: block\n")
    return EgressWhitelistAddon(config_path=str(config_file))

def test_http_connect_allowed(addon):
    flow = MagicMock()
    flow.request.host = "cloud.google.com"
    flow.request.port = 443
    flow.response = None

    addon.http_connect(flow)
    assert flow.response is None

def test_http_connect_blocked(addon):
    flow = MagicMock()
    flow.request.host = "unapproved.example.com"
    flow.request.port = 443
    flow.response = None

    addon.http_connect(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403
    payload = json.loads(flow.response.content.decode("utf-8"))
    assert payload["status"] == "error"
    assert "unapproved.example.com" in payload["message"]

def test_tls_clienthello_passthrough_when_allowed(addon):
    data = MagicMock()
    data.context.client.sni = "cloud.google.com"
    data.context.server.address = ("cloud.google.com", 443)
    data.ignore_connection = False

    addon.tls_clienthello(data)
    assert data.ignore_connection is True

def test_plain_http_request_blocked(addon):
    flow = MagicMock()
    flow.request.pretty_host = "evil.com"
    flow.response = None

    addon.request(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_addon.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'config.addon'`

- [ ] **Step 3: Implement `config/addon.py`**

```python
# config/addon.py
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
    # Allow testing without mitmproxy package installed
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
        if http:
            return http.Response.make(403, raw_json, headers)
        else:
            # Fallback mock container for tests
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_addon.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add config/addon.py tests/test_addon.py
git commit -m "feat: implement mitmproxy addon hooks for TLS passthrough and 403 blocking"
```

---

### Task 3: Docker Compose Environment

**Files:**
- Create: `docker-compose.yml`

- [ ] **Step 1: Write `docker-compose.yml`**

```yaml
version: "3.8"

services:
  mitmproxy:
    image: mitmproxy/mitmproxy:latest
    container_name: local-egress-proxy
    restart: unless-stopped
    command: >
      mitmweb
      --web-host 0.0.0.0
      --web-port 8081
      --listen-host 0.0.0.0
      --listen-port 8080
      -s /home/mitmproxy/config/addon.py
      --set block_global=false
    ports:
      - "8080:8080" # Forward proxy
      - "8081:8081" # mitmweb dashboard
    volumes:
      - ./config:/home/mitmproxy/config:ro
```

- [ ] **Step 2: Test starting Docker container and verify ports**

Run: `docker compose up -d`
Check container status: `docker compose ps`
Check logs: `docker compose logs mitmproxy`
Expected: Container is running, listening on port 8080 (proxy) and 8081 (web UI), addon loaded.

- [ ] **Step 3: Commit**

```bash
git add docker-compose.yml
git commit -m "feat: configure docker compose for mitmweb with volume-mounted addon"
```

---

### Task 4: Automated Egress Verification Script

**Files:**
- Create: `scripts/test-egress.sh`

- [ ] **Step 1: Write `scripts/test-egress.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

PROXY="http://localhost:8080"
WEB_UI="http://localhost:8081"

echo "=== 1. Checking Proxy Container & Dashboard ==="
curl -s -f -o /dev/null "$WEB_UI" && echo "✓ mitmweb dashboard is responsive on $WEB_UI" || {
  echo "✗ Error: Dashboard not reachable at $WEB_UI. Is docker compose up -d running?"
  exit 1
}

echo ""
echo "=== 2. Testing Whitelisted Domains (Expected: 200/301/302, valid TLS) ==="
WHITELISTED=(
  "https://cloud.google.com"
  "https://accounts.google.com"
  "https://fonts.gstatic.com"
  "https://www.gstatic.com"
)

for url in "${WHITELISTED[@]}"; do
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -x "$PROXY" "$url")
  if [[ "$HTTP_CODE" =~ ^(200|301|302|304)$ ]]; then
    echo "✓ Allowed: $url -> HTTP $HTTP_CODE"
  else
    echo "✗ Failed: $url returned unexpected code $HTTP_CODE"
    exit 1
  fi
done

echo ""
echo "=== 3. Testing Wildcard Matching ==="
WILDCARD_URL="https://test-instance-dot-asia-southeast1.notebooks.googleusercontent.com"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -x "$PROXY" "$WILDCARD_URL" || true)
if [[ "$HTTP_CODE" == "403" ]]; then
  echo "✗ Failed: Wildcard host was blocked with 403"
  exit 1
else
  echo "✓ Allowed by wildcard pattern: $WILDCARD_URL (Code: $HTTP_CODE)"
fi

echo ""
echo "=== 4. Testing Blocked Domains (Expected: 403 Forbidden with JSON error) ==="
BLOCKED=(
  "https://example.com"
  "https://api.openai.com"
  "https://github.com"
)

for url in "${BLOCKED[@]}"; do
  RESPONSE=$(curl -s -w "\n%{http_code}" -x "$PROXY" "$url" || true)
  HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
  BODY=$(echo "$RESPONSE" | head -n -1)
  
  if [[ "$HTTP_CODE" == "403" ]]; then
    echo "✓ Blocked as expected: $url -> HTTP 403"
    echo "  Response body: $BODY" | head -n 3
  else
    echo "✗ Security leak: $url was NOT blocked! (HTTP $HTTP_CODE)"
    exit 1
  fi
done

echo ""
echo "=== 5. Testing Hot Reloading of whitelist.yaml ==="
CONFIG_FILE="config/whitelist.yaml"
BACKUP_FILE="config/whitelist.yaml.bak"
cp "$CONFIG_FILE" "$BACKUP_FILE"

# Dynamically add example.com
echo "  - \"example.com\"" >> "$CONFIG_FILE"
sleep 2.5

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -x "$PROXY" "https://example.com")
if [[ "$HTTP_CODE" =~ ^(200|301|302|304)$ ]]; then
  echo "✓ Hot reload verified: example.com is now allowed (HTTP $HTTP_CODE)"
else
  echo "✗ Hot reload failed: example.com still returned $HTTP_CODE"
  cp "$BACKUP_FILE" "$CONFIG_FILE"
  rm "$BACKUP_FILE"
  exit 1
fi

# Restore original whitelist
cp "$BACKUP_FILE" "$CONFIG_FILE"
rm "$BACKUP_FILE"
sleep 2.5

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -x "$PROXY" "https://example.com" || true)
if [[ "$HTTP_CODE" == "403" ]]; then
  echo "✓ Hot reload verified: example.com is blocked again after restoring config"
else
  echo "✗ Restore failed: expected 403, got $HTTP_CODE"
  exit 1
fi

echo ""
echo "=== ALL EGRESS VERIFICATION TESTS PASSED ==="
```

- [ ] **Step 2: Make executable and execute test script against running container**

Run: `chmod +x scripts/test-egress.sh && ./scripts/test-egress.sh`
Expected: Output shows all 5 test phases passing.

- [ ] **Step 3: Commit**

```bash
git add scripts/test-egress.sh
git commit -m "test: add automated end-to-end egress proxy verification script"
```

---

### Task 5: Brave Browser Terminal Launcher Script

**Files:**
- Create: `scripts/launch-brave.sh`

- [ ] **Step 1: Write `scripts/launch-brave.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

PROXY_HOST="127.0.0.1:8080"
TEMP_PROFILE="/tmp/brave-proxy-session"

mkdir -p "$TEMP_PROFILE"

BRAVE_APP="/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"

if [[ ! -f "$BRAVE_APP" ]]; then
  echo "Error: Brave Browser not found at '$BRAVE_APP'"
  echo "If installed in another location, set BRAVE_PATH environment variable."
  exit 1
fi

echo "Launching Brave Browser with proxy set to $PROXY_HOST..."
echo "Isolated user profile directory: $TEMP_PROFILE"

"$BRAVE_APP" \
  --proxy-server="http://$PROXY_HOST" \
  --user-data-dir="$TEMP_PROFILE" \
  --no-first-run \
  --no-default-browser-check \
  "$@" >/dev/null 2>&1 &

echo "Brave started in background. Inspect traffic at http://localhost:8081"
```

- [ ] **Step 2: Make script executable and verify syntax**

Run: `chmod +x scripts/launch-brave.sh && bash -n scripts/launch-brave.sh`
Expected: Syntax check passes with exit code 0.

- [ ] **Step 3: Commit**

```bash
git add scripts/launch-brave.sh
git commit -m "feat: add brave browser terminal launcher script with isolated proxy profile"
```

---

### Task 6: Documentation (`docs/README.md`)

**Files:**
- Create: `docs/README.md`

- [ ] **Step 1: Write `docs/README.md`**

Write complete user guide covering:
- Prerequisites (Docker & Docker Compose, optional Brave Browser).
- Starting the proxy (`docker compose up -d`).
- Dashboard inspection (`http://localhost:8081`).
- Running the automated test suite (`./scripts/test-egress.sh`).
- Launching Brave Browser with proxy (`./scripts/launch-brave.sh`).
- Configuring terminal sessions, Python, and Docker to use the proxy.
- Editing whitelist rules in `config/whitelist.yaml` with live auto-reload.
- Stopping the proxy (`docker compose down`).

- [ ] **Step 2: Verify all markdown files are in `docs/` and links are valid**

Run: `ls -la docs/`
Expected: Contains `2026-10-18-mitmproxy-egress-whitelist-design.md`, `2026-10-18-mitmproxy-egress-whitelist-plan.md`, and `README.md`.

- [ ] **Step 3: Commit**

```bash
git add docs/README.md
git commit -m "docs: add comprehensive egress proxy guide in docs folder"
```
