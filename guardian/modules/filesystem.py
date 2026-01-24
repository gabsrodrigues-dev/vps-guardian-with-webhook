#!/usr/bin/env python3
"""
VPS Guardian - Filesystem Monitor Module
Watches /tmp, /dev/shm, /var/tmp for suspicious files.
"""

import os
import stat
import time
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass

@dataclass
class SuspiciousFile:
    """Represents a suspicious file found in watched directories."""
    path: str
    reason: str
    age_minutes: float
    is_executable: bool
    size_bytes: int

class FilesystemMonitor:
    """Monitors filesystem for suspicious files."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.watch_dirs = config['filesystem']['watch_dirs']
        self.max_age_minutes = config['filesystem']['max_file_age_minutes']

    def scan(self) -> List[SuspiciousFile]:
        """Scan watched directories for suspicious files."""
        suspicious = []
        now = time.time()

        for dir_path in self.watch_dirs:
            if not os.path.exists(dir_path):
                continue

            suspicious.extend(self._scan_directory(dir_path, now))

        return suspicious

    def _scan_directory(self, dir_path: str, now: float) -> List[SuspiciousFile]:
        """Scan a single directory."""
        suspicious = []

        try:
            for entry in os.scandir(dir_path):
                try:
                    if entry.is_dir(follow_symlinks=False):
                        # Recursively scan subdirs (but not too deep)
                        if dir_path.count('/') < 5:
                            suspicious.extend(self._scan_directory(entry.path, now))
                        continue

                    if not entry.is_file(follow_symlinks=False):
                        continue

                    stat_info = entry.stat(follow_symlinks=False)
                    age_minutes = (now - stat_info.st_mtime) / 60.0
                    is_executable = bool(stat_info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                    size = stat_info.st_size

                    # Check if file is suspicious
                    reasons = []

                    # New executable in temp directory
                    if is_executable and age_minutes <= self.max_age_minutes:
                        reasons.append(f"New executable (created {age_minutes:.1f}min ago)")

                    # Hidden executable
                    if is_executable and entry.name.startswith('.'):
                        reasons.append("Hidden executable file")

                    # ELF binary in temp
                    if is_executable and size > 1024:  # Skip tiny scripts
                        try:
                            with open(entry.path, 'rb') as f:
                                magic = f.read(4)
                                if magic == b'\x7fELF':
                                    reasons.append("ELF binary in temp directory")
                        except (IOError, OSError):
                            pass

                    if reasons:
                        suspicious.append(SuspiciousFile(
                            path=entry.path,
                            reason='; '.join(reasons),
                            age_minutes=age_minutes,
                            is_executable=is_executable,
                            size_bytes=size
                        ))

                except (OSError, IOError):
                    continue

        except (OSError, IOError):
            pass

        return suspicious
