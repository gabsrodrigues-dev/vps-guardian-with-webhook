#!/usr/bin/env python3
"""
VPS Guardian - Resource Monitor Module
Monitors CPU/RAM usage with temporal tracking.
SIMPLIFIED LOGIC: 10min = notify, 20min = kill (no exceptions)
"""

import os
import time
import psutil
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta

@dataclass
class ResourceAlert:
    """Represents a resource usage alert."""
    pid: int
    name: str
    cpu_percent: float
    memory_percent: float
    duration_minutes: float
    should_notify: bool
    should_kill: bool
    time_until_kill: float  # minutes

@dataclass
class ProcessTracker:
    """Tracks a process's resource usage over time."""
    pid: int
    name: str
    first_seen: datetime
    last_high_usage: datetime
    cpu_samples: List[float] = field(default_factory=list)
    memory_samples: List[float] = field(default_factory=list)

class ResourceMonitor:
    """Monitors system resources with temporal awareness."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        res_config = config['resources']

        self.cpu_threshold = res_config['cpu_threshold_percent']
        self.memory_threshold = res_config['memory_threshold_percent']
        self.notify_after_minutes = res_config['notify_after_minutes']
        self.kill_after_minutes = res_config['kill_after_minutes']
        self.whitelist = res_config['whitelist']

        # Track processes: {pid: ProcessTracker}
        self.tracked: Dict[int, ProcessTracker] = {}

        # Track which PIDs we've already notified about
        self.notified_pids: set = set()

        self.my_pid = os.getpid()

    def check(self) -> List[ResourceAlert]:
        """Check all processes for high resource usage."""
        alerts = []
        now = datetime.now()
        current_pids = set()

        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                pid = proc.info['pid']
                name = proc.info['name'] or ''

                # Skip self and whitelisted
                if pid == self.my_pid:
                    continue
                if self._is_whitelisted(name):
                    continue

                current_pids.add(pid)

                cpu = proc.info['cpu_percent'] or 0
                mem = proc.info['memory_percent'] or 0

                # Check if over threshold
                if cpu >= self.cpu_threshold or mem >= self.memory_threshold:
                    alert = self._track_high_usage(pid, name, cpu, mem, now)
                    if alert:
                        alerts.append(alert)
                else:
                    # Process is now under threshold, remove from tracking
                    self._remove_tracking(pid)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Clean up dead processes
        dead_pids = set(self.tracked.keys()) - current_pids
        for pid in dead_pids:
            self._remove_tracking(pid)

        return alerts

    def _is_whitelisted(self, name: str) -> bool:
        """Check if process is in whitelist."""
        name_lower = name.lower()
        return any(w.lower() in name_lower for w in self.whitelist)

    def _track_high_usage(self, pid: int, name: str, cpu: float, mem: float, now: datetime) -> Optional[ResourceAlert]:
        """Track process with high resource usage."""

        if pid not in self.tracked:
            # First time seeing this process with high usage
            self.tracked[pid] = ProcessTracker(
                pid=pid,
                name=name,
                first_seen=now,
                last_high_usage=now,
                cpu_samples=[cpu],
                memory_samples=[mem]
            )
            return None  # Not enough data yet

        tracker = self.tracked[pid]
        tracker.last_high_usage = now
        tracker.cpu_samples.append(cpu)
        tracker.memory_samples.append(mem)

        # Keep only last 60 samples (5 min at 5s intervals)
        tracker.cpu_samples = tracker.cpu_samples[-60:]
        tracker.memory_samples = tracker.memory_samples[-60:]

        # Calculate duration
        duration = (now - tracker.first_seen).total_seconds() / 60.0

        # Determine actions
        should_notify = duration >= self.notify_after_minutes and pid not in self.notified_pids
        should_kill = duration >= self.kill_after_minutes
        time_until_kill = max(0, self.kill_after_minutes - duration)

        if should_notify:
            self.notified_pids.add(pid)

        # Only return alert if we need to notify or kill
        if should_notify or should_kill or duration >= self.notify_after_minutes:
            return ResourceAlert(
                pid=pid,
                name=name,
                cpu_percent=sum(tracker.cpu_samples[-5:]) / min(5, len(tracker.cpu_samples)),
                memory_percent=sum(tracker.memory_samples[-5:]) / min(5, len(tracker.memory_samples)),
                duration_minutes=duration,
                should_notify=should_notify,
                should_kill=should_kill,
                time_until_kill=time_until_kill
            )

        return None

    def _remove_tracking(self, pid: int):
        """Stop tracking a process."""
        self.tracked.pop(pid, None)
        self.notified_pids.discard(pid)

    def get_tracking_status(self) -> Dict[int, float]:
        """Get current tracking status for all monitored processes."""
        now = datetime.now()
        return {
            pid: (now - tracker.first_seen).total_seconds() / 60.0
            for pid, tracker in self.tracked.items()
        }
