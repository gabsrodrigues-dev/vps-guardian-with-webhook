#!/bin/bash
# VPS Guardian - Blocklist Updater
# Run via cron daily to keep blocklists updated

set -e

BLOCKLIST_DIR="/opt/vps-guardian/firewall/blocklists"
LOG_FILE="/var/log/guardian-blocklist-update.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting blocklist update..."

# Update TOR exit nodes
log "Downloading TOR exit nodes..."
curl -sf "https://check.torproject.org/exit-addresses" | \
    grep "ExitAddress" | \
    awk '{print $2}' > "$BLOCKLIST_DIR/tor-exit-nodes.txt.tmp" && \
    mv "$BLOCKLIST_DIR/tor-exit-nodes.txt.tmp" "$BLOCKLIST_DIR/tor-exit-nodes.txt"

TOR_COUNT=$(wc -l < "$BLOCKLIST_DIR/tor-exit-nodes.txt")
log "TOR exit nodes updated: $TOR_COUNT IPs"

# Update mining pools from CoinBlockerLists
log "Downloading mining pool blocklist..."
curl -sf "https://zerodot1.gitlab.io/CoinBlockerLists/hosts" | \
    grep -v "^#" | \
    grep -v "^$" | \
    awk '{print $2}' | \
    sort -u > "$BLOCKLIST_DIR/mining-pools.txt.tmp" && \
    mv "$BLOCKLIST_DIR/mining-pools.txt.tmp" "$BLOCKLIST_DIR/mining-pools.txt"

POOL_COUNT=$(wc -l < "$BLOCKLIST_DIR/mining-pools.txt")
log "Mining pools updated: $POOL_COUNT domains"

# Reload ipset if available
if command -v ipset &> /dev/null; then
    log "Reloading ipset rules..."
    /opt/vps-guardian/firewall/rules.sh reload 2>/dev/null || true
fi

log "Blocklist update complete!"
