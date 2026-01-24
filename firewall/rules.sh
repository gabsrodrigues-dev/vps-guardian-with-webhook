#!/bin/bash
# VPS Guardian - Firewall Rules
# Configures iptables with mining pool and TOR blocking

set -e

BLOCKLIST_DIR="/opt/vps-guardian/firewall/blocklists"
IPSET_MINING="guardian_mining_pools"
IPSET_TOR="guardian_tor_nodes"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[Guardian Firewall]${NC} $1"
}

error() {
    echo -e "${RED}[Guardian Firewall ERROR]${NC} $1" >&2
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

# Install ipset if not present
if ! command -v ipset &> /dev/null; then
    log "Installing ipset..."
    apt-get update -qq && apt-get install -y -qq ipset
fi

setup_ipsets() {
    log "Setting up ipsets..."

    # Create ipsets if they don't exist
    ipset list "$IPSET_TOR" &>/dev/null || \
        ipset create "$IPSET_TOR" hash:ip hashsize 65536 maxelem 100000

    # Flush existing entries
    ipset flush "$IPSET_TOR"

    # Load TOR exit nodes with IP validation (prevents command injection)
    if [[ -f "$BLOCKLIST_DIR/tor-exit-nodes.txt" ]]; then
        local valid_count=0
        local invalid_count=0
        while IFS= read -r ip; do
            # Skip empty lines and comments
            [[ -z "$ip" || "$ip" == \#* ]] && continue

            # Validate IPv4 format (strict regex to prevent injection)
            if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                # Additional validation: each octet must be 0-255
                IFS='.' read -ra octets <<< "$ip"
                valid=true
                for octet in "${octets[@]}"; do
                    if (( octet > 255 )); then
                        valid=false
                        break
                    fi
                done
                if $valid; then
                    ipset add "$IPSET_TOR" "$ip" 2>/dev/null && ((valid_count++)) || true
                else
                    ((invalid_count++))
                fi
            else
                ((invalid_count++))
            fi
        done < "$BLOCKLIST_DIR/tor-exit-nodes.txt"
        log "Loaded $valid_count TOR exit nodes ($invalid_count invalid entries skipped)"
    fi
}

setup_iptables() {
    log "Configuring iptables rules..."

    # Block common mining ports (outbound)
    MINING_PORTS="3333 4444 5555 7777 8888 9999 14433 14444 45700"
    for port in $MINING_PORTS; do
        iptables -C OUTPUT -p tcp --dport "$port" -j DROP 2>/dev/null || \
            iptables -A OUTPUT -p tcp --dport "$port" -j DROP
    done
    log "Blocked outbound mining ports: $MINING_PORTS"

    # Block TOR exit nodes (inbound and outbound)
    iptables -C INPUT -m set --match-set "$IPSET_TOR" src -j DROP 2>/dev/null || \
        iptables -A INPUT -m set --match-set "$IPSET_TOR" src -j DROP

    iptables -C OUTPUT -m set --match-set "$IPSET_TOR" dst -j DROP 2>/dev/null || \
        iptables -A OUTPUT -m set --match-set "$IPSET_TOR" dst -j DROP

    log "Blocked TOR exit nodes (inbound + outbound)"
}

save_rules() {
    log "Saving iptables rules..."
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save
    elif [[ -f /etc/iptables/rules.v4 ]]; then
        iptables-save > /etc/iptables/rules.v4
    fi

    # Save ipset
    ipset save > /etc/ipset.conf
    log "Rules saved for persistence"
}

case "${1:-install}" in
    install)
        setup_ipsets
        setup_iptables
        save_rules
        log "Firewall setup complete!"
        ;;
    reload)
        setup_ipsets
        log "Ipsets reloaded"
        ;;
    status)
        echo "=== IPSET: TOR Nodes ==="
        ipset list "$IPSET_TOR" | head -20
        echo ""
        echo "=== IPTABLES: Guardian Rules ==="
        iptables -L -n | grep -E "(DROP|guardian)" || echo "No guardian rules found"
        ;;
    *)
        echo "Usage: $0 {install|reload|status}"
        exit 1
        ;;
esac
