#!/bin/bash
# VPS Guardian - Security Audit Script
# Runs chkrootkit and rkhunter for rootkit detection

set -e

LOG_DIR="/var/log"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
AUDIT_LOG="$LOG_DIR/guardian-audit-$TIMESTAMP.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$AUDIT_LOG"
}

log "=========================================="
log "VPS Guardian Security Audit Starting"
log "=========================================="

# Run chkrootkit
if command -v chkrootkit &> /dev/null; then
    log "Running chkrootkit..."
    chkrootkit 2>&1 | tee -a "$AUDIT_LOG"
else
    log "chkrootkit not installed, skipping"
fi

echo "" | tee -a "$AUDIT_LOG"

# Run rkhunter
if command -v rkhunter &> /dev/null; then
    log "Running rkhunter..."
    # Update database first
    rkhunter --update --nocolors 2>&1 | tee -a "$AUDIT_LOG" || true
    # Run check
    rkhunter --check --skip-keypress --nocolors 2>&1 | tee -a "$AUDIT_LOG" || true
else
    log "rkhunter not installed, skipping"
fi

log "=========================================="
log "Audit complete. Log saved to: $AUDIT_LOG"
log "=========================================="

# Check for warnings in the log
if grep -qiE "(warning|infected|rootkit|suspicious)" "$AUDIT_LOG"; then
    log "⚠️  WARNINGS FOUND - Review the audit log!"
    exit 1
fi

log "✅ No issues detected"
exit 0
