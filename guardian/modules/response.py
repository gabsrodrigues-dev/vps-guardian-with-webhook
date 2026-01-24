#!/usr/bin/env python3
"""
VPS Guardian - Response Module
Handles threat response: kill processes, quarantine files, send notifications.
"""

import os
import shutil
import json
import signal
import psutil
import requests
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import logging

logger = logging.getLogger('guardian.response')

class ResponseLevel(Enum):
    """Response severity levels."""
    NOTIFY = 1      # Just notify (10min resource usage)
    KILL = 2        # Notify + Kill (20min resource usage OR explicit trigger)

@dataclass
class Incident:
    """Represents a security incident."""
    timestamp: str
    pid: int
    process_name: str
    threat_type: str
    reason: str
    action_taken: str
    details: Dict[str, Any]

class ResponseHandler:
    """Handles responses to detected threats."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.quarantine_dir = Path(config['response']['quarantine_dir'])
        self.log_file = Path(config['response']['log_file'])

        # Telegram config
        telegram_config = config['response']['telegram']
        self.telegram_enabled = telegram_config.get('enabled', False)
        self.telegram_webhook = telegram_config.get('webhook_url')
        self.telegram_chat_id = telegram_config.get('chat_id')

        # Ensure directories exist (gracefully handle permission errors)
        try:
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            logger.warning(f"No permission to create {self.quarantine_dir}, will attempt on first use")

        try:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            logger.warning(f"No permission to create {self.log_file.parent}, will attempt on first use")

    def handle_threat(self, pid: int, name: str, reason: str,
                      level: ResponseLevel, exe_path: str = None,
                      extra_details: Dict = None) -> Incident:
        """Handle a detected threat based on severity level."""

        details = extra_details or {}
        action = 'none'

        if level == ResponseLevel.NOTIFY:
            action = 'notified'
            self._send_notification(pid, name, reason, is_kill=False, details=details)

        elif level == ResponseLevel.KILL:
            # Kill the process
            killed = self._kill_process(pid)
            action = 'killed' if killed else 'kill_failed'

            # Quarantine the binary if exists
            if exe_path and os.path.exists(exe_path):
                quarantined = self._quarantine_file(exe_path)
                if quarantined:
                    action += '+quarantined'

            # Send notification
            self._send_notification(pid, name, reason, is_kill=True, details=details)

        # Log the incident
        incident = Incident(
            timestamp=datetime.now().isoformat(),
            pid=pid,
            process_name=name,
            threat_type=reason.split(':')[0] if ':' in reason else 'unknown',
            reason=reason,
            action_taken=action,
            details=details
        )

        self._log_incident(incident)
        return incident

    def _kill_process(self, pid: int) -> bool:
        """Kill a process and its children."""
        try:
            proc = psutil.Process(pid)

            # Kill children first
            children = proc.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                except psutil.NoSuchProcess:
                    pass

            # Kill main process
            proc.kill()
            proc.wait(timeout=5)

            logger.info(f"Killed process {pid} and {len(children)} children")
            return True

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired) as e:
            logger.error(f"Failed to kill PID {pid}: {e}")
            return False

    def _quarantine_file(self, file_path: str) -> bool:
        """Move a file to quarantine directory."""
        try:
            src = Path(file_path)
            if not src.exists():
                return False

            # Create unique quarantine name
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            dst = self.quarantine_dir / f"{timestamp}_{src.name}"

            shutil.move(str(src), str(dst))
            os.chmod(str(dst), 0o000)  # Remove all permissions

            logger.info(f"Quarantined: {file_path} -> {dst}")
            return True

        except (IOError, OSError) as e:
            logger.error(f"Failed to quarantine {file_path}: {e}")
            return False

    def _send_notification(self, pid: int, name: str, reason: str,
                           is_kill: bool, details: Dict):
        """Send notification via Telegram."""
        if not self.telegram_enabled or not self.telegram_webhook:
            return

        emoji = "☠️" if is_kill else "🔔"
        action_text = "PROCESSO ELIMINADO" if is_kill else "Monitorando"
        title = "[KILL]" if is_kill else "[ALERTA]"

        # Format details
        detail_lines = []
        if 'cpu_percent' in details:
            detail_lines.append(f"CPU: {details['cpu_percent']:.1f}%")
        if 'memory_percent' in details:
            detail_lines.append(f"RAM: {details['memory_percent']:.1f}%")
        if 'duration_minutes' in details:
            detail_lines.append(f"Duração: {details['duration_minutes']:.1f} min")
        if 'time_until_kill' in details and not is_kill:
            detail_lines.append(f"Kill em: {details['time_until_kill']:.1f} min")

        message = f"""
{emoji} {title} VPS Guardian
━━━━━━━━━━━━━━━━━━━
Processo: {name} (PID {pid})
{chr(10).join(detail_lines)}
Motivo: {reason}
Ação: {action_text}
━━━━━━━━━━━━━━━━━━━
        """.strip()

        try:
            # For Telegram Bot API
            if 'api.telegram.org' in self.telegram_webhook:
                requests.post(
                    self.telegram_webhook,
                    json={'chat_id': self.telegram_chat_id, 'text': message},
                    timeout=5
                )
            else:
                # Generic webhook
                requests.post(self.telegram_webhook, json={'text': message}, timeout=5)

        except Exception as e:
            logger.error(f"Failed to send notification: {e}")

    def _log_incident(self, incident: Incident):
        """Log incident to JSON file."""
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(asdict(incident)) + '\n')
        except IOError as e:
            logger.error(f"Failed to log incident: {e}")
