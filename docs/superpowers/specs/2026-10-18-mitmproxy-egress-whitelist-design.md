# Architecture Design: Local Egress Whitelist Proxy using mitmproxy

## 1. Overview & Objectives

This project provides a local containerized proxy environment to simulate enterprise network egress restrictions. The primary objective is to enforce an egress control whitelist that only allows outbound HTTP and HTTPS traffic to approved destinations, reducing data exfiltration risks.

Key design attributes:
- **Zero Client CA Setup:** Uses TLS passthrough (`ignore_connection = True` on `CONNECT`) for whitelisted HTTPS traffic so client applications and browsers validate upstream public certificates directly without needing to install or trust a local self-signed root CA.
- **Strict 403 Blocking:** Disallowed HTTP/HTTPS connections are terminated with an explicit HTTP 403 Forbidden status code and structured JSON diagnostic payload.
- **Dynamic Hot-Reloading:** Whitelist domains and wildcard rules are maintained in a YAML configuration file mounted into the container. Rules reload automatically upon file modification without restarting the container.
- **Real-Time Visibility:** Runs `mitmweb` with an integrated web dashboard on port `8081` alongside the proxy listener on port `8080`.

---

## 2. Directory Structure

```text
mitm proxy/
├── docker-compose.yml
├── config/
│   ├── whitelist.yaml
│   └── addon.py
├── scripts/
│   ├── test-egress.sh
│   └── launch-brave.sh
├── docs/
│   └── superpowers/
│       └── specs/
│           └── 2026-10-18-mitmproxy-egress-whitelist-design.md
└── README.md
```

---

## 3. Whitelist Configuration Schema

`config/whitelist.yaml` supports exact domain matches and wildcard patterns (using standard glob matching such as `*`):

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
  default_action: "block" # "block" returns 403; "log_only" logs without blocking
  reload_check_seconds: 2
```

---

## 4. Component Design & Interception Hooks

### 4.1 mitmproxy Addon (`config/addon.py`)

The addon implements three mitmproxy event hooks:

1. **`http_connect(flow: http.HTTPFlow)`**:
   - Triggers on incoming HTTPS `CONNECT` requests (e.g., `CONNECT cloud.google.com:443 HTTP/1.1`).
   - Extracts the target hostname and strips the port number.
   - Evaluates the host against the active whitelist rules:
     - **Allowed:** Lets the flow proceed to establish the tunnel.
     - **Blocked:** Responds immediately with HTTP 403 Forbidden:
       ```http
       HTTP/1.1 403 Forbidden
       Content-Type: application/json
       X-Egress-Policy: Blocked

       {
         "status": "error",
         "code": 403,
         "message": "Egress proxy blocked: target host '<host>' is not in the approved egress whitelist.",
         "timestamp": "<iso8601>"
       }
       ```
2. **`tls_clienthello(data: tls.ClientHelloData)`**:
   - For whitelisted hosts that establish a TLS connection, `data.ignore_connection = True` is executed.
   - This bypasses mitmproxy's TLS interception engine, passing raw TCP/TLS bytes between the client and the upstream server. The client's TLS handshake verifies the real server's certificate directly.
3. **`request(flow: http.HTTPFlow)`**:
   - Evaluates plain HTTP (non-CONNECT) egress requests.
   - If the host is not whitelisted, interrupts with HTTP 403 Forbidden.

### 4.2 Hot-Reload Engine
- Stores the last modified timestamp (`os.path.getmtime`) of `whitelist.yaml`.
- On connection events, if `current_time - last_check > reload_check_seconds`, checks the file's mtime.
- If changed, re-parses the YAML file and updates the in-memory rule set atomically, logging rule additions or syntax errors to the mitmweb console.

---

## 5. Container & Service Architecture

### 5.1 Docker Compose Specification (`docker-compose.yml`)
- **Service Name:** `mitmproxy`
- **Base Image:** `mitmproxy/mitmproxy:latest`
- **Command:**
  ```bash
  mitmweb --web-host 0.0.0.0 --web-port 8081 \
          --listen-host 0.0.0.0 --listen-port 8080 \
          -s /home/mitmproxy/config/addon.py \
          --set block_global=false
  ```
- **Ports:**
  - `8080:8080` (HTTP/HTTPS Proxy)
  - `8081:8081` (mitmweb Web Dashboard)
- **Volumes:**
  - `./config:/home/mitmproxy/config:ro`
- **Restart Policy:** `unless-stopped`

---

## 6. Verification & Client Integration

### 6.1 Automated Verification Script (`scripts/test-egress.sh`)
Executes `curl` test scenarios with exit code validations:
- Whitelisted domains (e.g., `https://cloud.google.com`, `https://accounts.google.com`): Expected HTTP 200/301/302, successful TLS handshake.
- Wildcard domains (e.g., `https://sample-dot-asia-southeast1.notebooks.googleusercontent.com`): Expected proxy connection permitted.
- Disallowed domains (e.g., `https://example.com`, `https://openai.com`): Expected HTTP 403 Forbidden with custom JSON payload.
- Dynamic reload test: Appends a temporary domain to `whitelist.yaml`, verifies traffic immediately succeeds, then restores the file.

### 6.2 Brave Browser Launch Script (`scripts/launch-brave.sh`)
Launches Brave Browser configured to route all traffic through the proxy in an isolated temporary user profile so existing Brave windows are unaffected:
```bash
#!/usr/bin/env bash
USER_DATA_DIR="/tmp/brave-proxy-profile"
mkdir -p "$USER_DATA_DIR"

/Applications/Brave\ Browser.app/Contents/MacOS/Brave\ Browser \
  --proxy-server="http://localhost:8080" \
  --user-data-dir="$USER_DATA_DIR" \
  --no-first-run \
  "$@" &
```

---

## 7. Operational Workflow

1. Start proxy: `docker compose up -d`
2. Open dashboard: Visit `http://localhost:8081`
3. Launch client: Run `scripts/launch-brave.sh` or configure terminal `export HTTP_PROXY="http://localhost:8080" HTTPS_PROXY="http://localhost:8080"`
4. Test: Run `bash scripts/test-egress.sh`
5. Modify rules: Edit `config/whitelist.yaml` at any time; changes take effect immediately.
