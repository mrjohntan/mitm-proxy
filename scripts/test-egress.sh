#!/usr/bin/env bash
set -euo pipefail

PROXY="http://localhost:8080"
WEB_UI="http://localhost:8081"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=========================================================="
echo "   Enterprise Egress Whitelist Proxy Verification Suite   "
echo "=========================================================="

echo ""
echo "=== Phase 1: Checking Proxy Container & Web Dashboard ==="
if curl -s -f -o /dev/null --connect-timeout 3 "$WEB_UI"; then
  echo "✓ mitmweb dashboard is responsive at $WEB_UI"
else
  echo "✗ Error: Dashboard not reachable at $WEB_UI."
  echo "  Please ensure the container is running: docker compose up -d"
  exit 1
fi

echo ""
echo "=== Phase 2: Testing Whitelisted Domains (Expected: 200/301/302, Valid TLS) ==="
WHITELISTED=(
  "https://cloud.google.com"
  "https://accounts.google.com"
  "https://fonts.gstatic.com"
  "https://www.gstatic.com"
)

for url in "${WHITELISTED[@]}"; do
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 -x "$PROXY" "$url" || echo "ERR")
  if [[ "$HTTP_CODE" =~ ^(200|301|302|304|307|308)$ ]]; then
    echo "✓ Allowed: $url -> HTTP $HTTP_CODE"
  else
    echo "✗ Failed: $url returned unexpected code '$HTTP_CODE'"
    exit 1
  fi
done

echo ""
echo "=== Phase 3: Testing Wildcard Subdomain Matching ==="
WILDCARD_URL="https://test-instance-dot-asia-southeast1.notebooks.googleusercontent.com"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 -x "$PROXY" "$WILDCARD_URL" || true)
if [[ "$HTTP_CODE" == "403" ]]; then
  echo "✗ Failed: Wildcard host was blocked with 403"
  exit 1
else
  echo "✓ Allowed by wildcard pattern (*-dot-asia-southeast1...): $WILDCARD_URL (Status: $HTTP_CODE)"
fi

echo ""
echo "=== Phase 4: Testing Blocked Domains (Expected: 403 Forbidden with Policy Payload) ==="
BLOCKED=(
  "https://example.com"
  "https://api.openai.com"
  "https://github.com"
)

for url in "${BLOCKED[@]}"; do
  RESPONSE=$(curl -s -w "\n%{http_code}" --connect-timeout 5 -x "$PROXY" "$url" || true)
  HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
  BODY=$(echo "$RESPONSE" | head -n -1)

  if [[ "$HTTP_CODE" == "403" ]]; then
    echo "✓ Blocked as expected: $url -> HTTP 403"
    echo "  Diagnostic response:"
    echo "$BODY" | sed 's/^/    /'
  else
    echo "✗ Security leak: $url was NOT blocked! (Got HTTP $HTTP_CODE)"
    exit 1
  fi
done

echo ""
echo "=== Phase 5: Testing Hot Reloading of config/whitelist.yaml ==="
CONFIG_FILE="$ROOT_DIR/config/whitelist.yaml"
BACKUP_FILE="$ROOT_DIR/config/whitelist.yaml.bak"

cp "$CONFIG_FILE" "$BACKUP_FILE"

# Dynamically add example.com to the whitelist
echo "  - \"example.com\"" >> "$CONFIG_FILE"
echo "Added 'example.com' to whitelist.yaml. Waiting for hot reload..."
sleep 2.5

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 -x "$PROXY" "https://example.com" || echo "ERR")
if [[ "$HTTP_CODE" =~ ^(200|301|302|304|307|308)$ ]]; then
  echo "✓ Hot reload verified: example.com is now permitted (HTTP $HTTP_CODE)"
else
  echo "✗ Hot reload failed: example.com returned $HTTP_CODE"
  cp "$BACKUP_FILE" "$CONFIG_FILE"
  rm -f "$BACKUP_FILE"
  exit 1
fi

# Restore original whitelist
cp "$BACKUP_FILE" "$CONFIG_FILE"
rm -f "$BACKUP_FILE"
echo "Restored original whitelist.yaml. Waiting for hot reload..."
sleep 2.5

RESPONSE=$(curl -s -w "\n%{http_code}" --connect-timeout 5 -x "$PROXY" "https://example.com" || true)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
if [[ "$HTTP_CODE" == "403" ]]; then
  echo "✓ Hot reload verified: example.com is blocked again after restoring config (HTTP 403)"
else
  echo "✗ Restore failed: expected 403, got $HTTP_CODE"
  exit 1
fi

echo ""
echo "=========================================================="
echo "    ALL EGRESS VERIFICATION TESTS PASSED SUCCESSFULLY!    "
echo "=========================================================="
