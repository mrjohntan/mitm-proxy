#!/usr/bin/env bash
set -euo pipefail

PROXY_URL="http://127.0.0.1:8080"
DASHBOARD_URL="http://127.0.0.1:8081"
TEMP_PROFILE="/tmp/brave-proxy-session"

DEFAULT_BRAVE_APP="/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"
BRAVE_BIN="${BRAVE_PATH:-$DEFAULT_BRAVE_APP}"

if [[ ! -x "$BRAVE_BIN" ]]; then
  echo "Error: Brave Browser executable not found at: '$BRAVE_BIN'"
  echo "If Brave is installed in a custom location, specify BRAVE_PATH, e.g.:"
  echo "  BRAVE_PATH=\"/path/to/Brave Browser\" ./scripts/launch-brave.sh"
  exit 1
fi

mkdir -p "$TEMP_PROFILE"

echo "=========================================================="
echo "    Starting Brave Browser with Egress Proxy Configured   "
echo "=========================================================="
echo "  Proxy Server:   $PROXY_URL"
echo "  Web Dashboard:  $DASHBOARD_URL"
echo "  User Profile:   $TEMP_PROFILE (Isolated test session)"
echo "=========================================================="

# Default initial URLs if none passed as arguments
INITIAL_URLS=(
  "https://cloud.google.com"
  "https://example.com"
)

if [[ $# -gt 0 ]]; then
  TARGET_ARGS=("$@")
else
  TARGET_ARGS=("${INITIAL_URLS[@]}")
fi

echo "Launching Brave in background..."
"$BRAVE_BIN" \
  --proxy-server="$PROXY_URL" \
  --user-data-dir="$TEMP_PROFILE" \
  --no-first-run \
  --no-default-browser-check \
  "${TARGET_ARGS[@]}" >/dev/null 2>&1 &

echo "✓ Brave Browser started successfully."
echo "Visit $DASHBOARD_URL in any browser to inspect proxy flows in real-time."
