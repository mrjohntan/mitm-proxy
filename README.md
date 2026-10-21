# Local Enterprise Egress Whitelist Proxy

This project implements a local simulation of enterprise egress proxy controls using `mitmproxy` (`mitmweb`). It acts as a preventative control to mitigate data exfiltration risks by only permitting outbound HTTP and HTTPS traffic to explicit, pre-approved destination hostnames and wildcard patterns.

---

## Key Features

1. **Zero Client Root CA Setup (TLS Passthrough):** Whitelisted HTTPS connections use TLS passthrough (`ignore_connection = True`). Clients complete end-to-end TLS verification directly with the real upstream servers without needing custom root certificates.
2. **Explicit 403 Forbidden Egress Policy:** Blocked requests receive an immediate HTTP 403 Forbidden with a clear diagnostic JSON payload explaining that the host was blocked by egress policy.
3. **Live Hot-Reloading:** Whitelist rules in `config/whitelist.yaml` can be modified on-the-fly and take effect within 2 seconds without restarting the Docker container.
4. **Real-Time Web Dashboard:** `mitmweb` provides an interactive browser inspection interface at `http://localhost:8081` to observe all flows, headers, and blocked vs allowed events.
5. **Turnkey Brave Browser Integration:** A pre-configured shell script launches Brave Browser in an isolated profile routed entirely through the proxy.

---

## Directory Structure

```text
mitm proxy/
├── docker-compose.yml         # Container definition for mitmweb service
├── config/
│   ├── whitelist.yaml         # Editable domain whitelist (exact hosts & wildcards)
│   ├── matcher.py             # Domain pattern matcher & dynamic hot-reload engine
│   └── addon.py               # mitmproxy addon hooks (CONNECT, TLS bypass, HTTP)
├── scripts/
│   ├── test-egress.sh         # Automated test suite verifying allowed vs blocked flows
│   └── launch-brave.sh        # Starts Brave Browser in an isolated proxy session
└── docs/
    ├── 2026-10-18-mitmproxy-egress-whitelist-design.md
    ├── 2026-10-18-mitmproxy-egress-whitelist-plan.md
    └── README.md
```

---

## Quick Start

### 1. Start the Proxy Container

```bash
docker compose up -d
```

Verify that the container is running and healthy:
```bash
docker compose ps
docker compose logs mitmproxy
```

* **Proxy Listener:** `http://localhost:8080`
* **Web UI Dashboard:** `http://localhost:8081` (Password: `admin`)

### 2. Open the Web Dashboard

Open `http://localhost:8081` in your browser. Enter password **`admin`** when prompted. You will see live traffic flows as requests pass through or get blocked by the proxy.

---

## Launching Brave Browser from Terminal

To launch Brave Browser with all traffic routed through the local proxy in an isolated temporary profile (preventing any interference with your existing browser tabs or cookies), run:

```bash
./scripts/launch-brave.sh
```

You can also pass specific URLs to open immediately:
```bash
./scripts/launch-brave.sh https://cloud.google.com https://example.com
```

### Direct Terminal Command Alternative
If you prefer running the command directly in your terminal:
```bash
"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" \
  --proxy-server="http://127.0.0.1:8080" \
  --user-data-dir="/tmp/brave-proxy-session" \
  --ignore-certificate-errors \
  --no-first-run \
  --no-default-browser-check \
  https://cloud.google.com &
```

---

## Configuring Other Clients

### 1. Terminal Shell Session (`curl`, `git`, CLI tools)
To route CLI commands in your current shell session through the proxy:
```bash
export HTTP_PROXY="http://localhost:8080"
export HTTPS_PROXY="http://localhost:8080"
export http_proxy="http://localhost:8080"
export https_proxy="http://localhost:8080"

# Test whitelisted destination (passes)
curl -i https://cloud.google.com

# Test non-whitelisted destination (returns HTTP 403)
curl -i https://example.com
```

To deactivate in the terminal session:
```bash
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy
```

### 2. Python (`requests`, `httpx`, `urllib`)
Python HTTP libraries automatically respect the `HTTP_PROXY` and `HTTPS_PROXY` environment variables when set. Alternatively, configure in code:

```python
import requests

proxies = {
    "http": "http://localhost:8080",
    "https": "http://localhost:8080",
}

# Whitelisted host succeeds
r = requests.get("https://cloud.google.com", proxies=proxies)
print(r.status_code) # 200

# Blocked host receives 403
r = requests.get("https://example.com", proxies=proxies)
print(r.status_code, r.json()) # 403 {'status': 'error', 'message': ...}
```

### 3. Other Docker Containers
To route traffic from another Docker container through the proxy, point to host gateway:
```bash
docker run --rm \
  --env HTTP_PROXY="http://host.docker.internal:8080" \
  --env HTTPS_PROXY="http://host.docker.internal:8080" \
  curlimages/curl:latest https://cloud.google.com
```

---

## Whitelist Configuration (`config/whitelist.yaml`)

Edit `config/whitelist.yaml` to update the list of permitted domains:

```yaml
# Enterprise Simulated Egress Whitelist
whitelist:
  # Wildcard subdomain pattern
  - "*-dot-asia-southeast1.notebooks.googleusercontent.com"
  
  # Google Cloud & Services APIs
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
  default_action: "block" # "block" returns 403; "log_only" logs without blocking
  reload_check_seconds: 2 # Hot reload polling frequency in seconds
```

### Hot-Reload Behavior
You do **not** need to restart Docker when updating `whitelist.yaml`. The proxy addon detects file modifications and dynamically updates its active in-memory rules within 2 seconds.

---

## Running the Automated Test Suite

A comprehensive test script validates whitelisted domains, wildcard matching, blocked destinations, and dynamic hot-reloading:

```bash
./scripts/test-egress.sh
```

You can also run the offline unit test suite:
```bash
python3 -m unittest discover tests
```

---

## Stopping the Proxy

To stop the proxy and release ports:
```bash
docker compose down
```
