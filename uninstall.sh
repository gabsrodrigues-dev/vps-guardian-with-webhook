#!/bin/bash
# VPS Guardian - Uninstaller
# Removes all Guardian components

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${RED}[!]${NC} $1"; }

[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }

echo ""
warn "This will remove VPS Guardian and all its configurations."
read -p "Are you sure? (y/N) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

log "Stopping Guardian service..."
systemctl stop guardian 2>/dev/null || true
systemctl disable guardian 2>/dev/null || true
rm -f /etc/systemd/system/guardian.service
systemctl daemon-reload

log "Removing cron jobs..."
crontab -l 2>/dev/null | grep -v "vps-guardian" | crontab - 2>/dev/null || true

log "Removing configurations..."
rm -f /etc/ssh/sshd_config.d/90-guardian.conf
rm -f /etc/fail2ban/jail.d/guardian.local
systemctl restart fail2ban 2>/dev/null || true
systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true

log "Removing ipset rules..."
ipset destroy guardian_tor_nodes 2>/dev/null || true

log "Removing installation directory..."
rm -rf /opt/vps-guardian

log "Removing runtime data..."
rm -rf /var/lib/guardian
# Keep quarantine for manual review
warn "Quarantine directory (/var/quarantine) preserved for review"

log "VPS Guardian has been uninstalled."
log "Note: Firewall rules may need manual cleanup (iptables -L)"
