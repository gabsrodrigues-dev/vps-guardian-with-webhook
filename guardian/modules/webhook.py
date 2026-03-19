"""Webhook notifier for VPS Guardian.

Sends threat notifications to external HTTP endpoints via POST requests.
Provides configurable Authorization header for secure integration.
"""

import json
import logging
import secrets
import socket
from datetime import datetime
from typing import Dict, Any, Optional, List
import requests


class WebhookNotifier:
    """HTTP Webhook notifier for external integrations.

    Sends JSON POST requests to configured webhook URLs with Bearer token auth.
    Compatible with Slack, Discord, custom dashboards, SIEM systems, etc.
    """

    BODY_SCHEMA = {
        "event": "threat_detected | container_warning | process_warning | test",
        "timestamp": "ISO 8601 datetime string",
        "hostname": "VPS hostname",
        "severity": "critical | warning | info",
        "process": {
            "pid": "int - Process ID",
            "name": "str - Process name"
        },
        "reason": "str - Description of why this event was triggered",
        "action_taken": "str - Action taken (killed, notified, quarantined, etc.)",
        "details": "dict - Additional context (cpu_percent, memory_percent, etc.)",
        "forensics_path": "str | null - Path to forensics evidence if collected"
    }

    def __init__(self, config: dict):
        webhook_config = config.get('response', {}).get('webhook', {})

        self.enabled = webhook_config.get('enabled', False)
        self.webhook_url = webhook_config.get('url')
        self.auth_token = webhook_config.get('auth_token')
        self.timeout = webhook_config.get('timeout_seconds', 10)
        self.retry_count = webhook_config.get('retry_count', 2)
        self.hostname = socket.gethostname()

        self.logger = logging.getLogger('guardian.webhook')

        if self.enabled and not self.auth_token:
            self.auth_token = secrets.token_hex(32)
            self.logger.warning(
                "No auth_token configured for webhook. "
                f"Auto-generated token: {self.auth_token}"
            )
            self._log_integration_info()

        if self.enabled and not self.webhook_url:
            self.logger.error("Webhook enabled but no URL configured. Disabling.")
            self.enabled = False

        if self.enabled:
            self.logger.info(f"Webhook notifier enabled -> {self.webhook_url}")

    def _log_integration_info(self):
        """Log integration instructions for the user."""
        info = self.get_integration_info()
        self.logger.info(
            "\n"
            "╔══════════════════════════════════════════════════════╗\n"
            "║         WEBHOOK INTEGRATION INSTRUCTIONS            ║\n"
            "╠══════════════════════════════════════════════════════╣\n"
            f"║ URL: {self.webhook_url or 'NOT SET'}\n"
            "║\n"
            "║ Your endpoint must accept POST requests with:\n"
            "║\n"
            "║ HEADER:\n"
            f"║   Authorization: Bearer {info['authorization_token']}\n"
            "║\n"
            "║ BODY (application/json):\n"
            f"║   {json.dumps(info['body_schema'], indent=2).replace(chr(10), chr(10) + '║   ')}\n"
            "║\n"
            "╚══════════════════════════════════════════════════════╝"
        )

    def get_integration_info(self) -> Dict[str, Any]:
        """Return integration details for the user."""
        return {
            "webhook_url": self.webhook_url,
            "method": "POST",
            "content_type": "application/json",
            "authorization_header": f"Bearer {self.auth_token}",
            "authorization_token": self.auth_token,
            "body_schema": self.BODY_SCHEMA,
            "example_body": {
                "event": "threat_detected",
                "timestamp": "2026-01-24T12:00:00",
                "hostname": self.hostname,
                "severity": "critical",
                "process": {"pid": 1234, "name": "xmrig"},
                "reason": "Suspicious process: mining detected",
                "action_taken": "killed+quarantined",
                "details": {"cpu_percent": 95.5, "memory_percent": 12.3},
                "forensics_path": "/var/lib/guardian/forensics/20260124_120000_1234"
            }
        }

    def _build_payload(self, event: str, severity: str, pid: int, name: str,
                       reason: str, action_taken: str, details: Dict[str, Any] = None,
                       forensics_path: Optional[str] = None) -> Dict[str, Any]:
        """Build standardized JSON payload."""
        return {
            "event": event,
            "timestamp": datetime.now().isoformat(),
            "hostname": self.hostname,
            "severity": severity,
            "process": {"pid": pid, "name": name},
            "reason": reason,
            "action_taken": action_taken,
            "details": details or {},
            "forensics_path": forensics_path
        }

    def _post(self, payload: Dict[str, Any]) -> bool:
        """Send POST request to webhook URL with retry logic."""
        if not self.enabled or not self.webhook_url:
            return False

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.auth_token}",
            "User-Agent": "VPS-Guardian/1.1.0"
        }

        for attempt in range(1, self.retry_count + 1):
            try:
                response = requests.post(
                    self.webhook_url,
                    json=payload,
                    headers=headers,
                    timeout=self.timeout
                )

                if response.status_code < 400:
                    self.logger.debug(f"Webhook sent successfully (status {response.status_code})")
                    return True

                self.logger.warning(
                    f"Webhook returned {response.status_code} "
                    f"(attempt {attempt}/{self.retry_count})"
                )

            except requests.exceptions.Timeout:
                self.logger.warning(
                    f"Webhook timeout (attempt {attempt}/{self.retry_count})"
                )
            except requests.exceptions.ConnectionError:
                self.logger.warning(
                    f"Webhook connection error (attempt {attempt}/{self.retry_count})"
                )
            except Exception as e:
                self.logger.error(f"Webhook error: {e}")
                return False

        self.logger.error(f"Webhook failed after {self.retry_count} attempts")
        return False

    def send_incident(self, pid: int, name: str, reason: str,
                      is_kill: bool, details: Dict[str, Any] = None,
                      forensics_path: Optional[str] = None,
                      forensics_summary: Optional[str] = None) -> bool:
        """Send incident notification via webhook."""
        severity = "critical" if is_kill else "warning"
        action = "killed" if is_kill else "monitoring"

        enriched_details = dict(details) if details else {}
        if forensics_summary:
            enriched_details["forensics_summary"] = forensics_summary

        payload = self._build_payload(
            event="threat_detected",
            severity=severity,
            pid=pid,
            name=name,
            reason=reason,
            action_taken=action,
            details=enriched_details,
            forensics_path=forensics_path
        )

        return self._post(payload)

    def send_container_warning(self, container_name: str, container_id: str,
                               cpu_percent: float, duration_minutes: float,
                               image: str, labels: Dict[str, str]) -> bool:
        """Send container CPU warning via webhook."""
        payload = self._build_payload(
            event="container_warning",
            severity="warning",
            pid=0,
            name=f"container:{container_name}",
            reason=f"Container {container_name} high CPU ({cpu_percent:.1f}%) for {duration_minutes:.1f} min",
            action_taken="monitoring",
            details={
                "container_id": container_id,
                "container_name": container_name,
                "image": image,
                "cpu_percent": cpu_percent,
                "duration_minutes": duration_minutes,
                "labels": labels
            }
        )

        return self._post(payload)

    def send_process_warning(self, pid: int, process_name: str,
                             cpu_percent: float, reason: str,
                             details: Dict[str, Any] = None) -> bool:
        """Send process threat warning via webhook."""
        payload = self._build_payload(
            event="process_warning",
            severity="critical",
            pid=pid,
            name=process_name,
            reason=reason,
            action_taken="detected",
            details={
                "cpu_percent": cpu_percent,
                **(details or {})
            }
        )

        return self._post(payload)

    def send_test(self) -> bool:
        """Send a test notification to verify webhook connectivity."""
        payload = self._build_payload(
            event="test",
            severity="info",
            pid=0,
            name="guardian",
            reason="Webhook connectivity test",
            action_taken="none",
            details={"message": "VPS Guardian webhook is working correctly"}
        )

        return self._post(payload)
