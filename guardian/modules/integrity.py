#!/usr/bin/env python3
"""
VPS Guardian - Integrity Checker Module
Verifies SHA256 hashes of critical system binaries.
Detects rootkits that replace system tools.
"""

import hashlib
import json
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass

@dataclass
class IntegrityViolation:
    """Represents a binary integrity violation (possible rootkit)."""
    path: str
    expected_hash: str
    actual_hash: str
    severity: str = 'critical'

class IntegrityChecker:
    """Checks integrity of critical system binaries."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.binaries = config['integrity']['critical_binaries']
        self.hash_db_path = Path(config['integrity']['hash_db'])
        self.hashes: Dict[str, str] = {}

        self._load_hashes()

    def _load_hashes(self):
        """Load known hashes from database."""
        if self.hash_db_path.exists():
            with open(self.hash_db_path) as f:
                self.hashes = json.load(f)

    def _calculate_hash(self, path: str) -> str | None:
        """Calculate SHA256 hash of a file."""
        try:
            sha256 = hashlib.sha256()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (IOError, OSError):
            return None

    def initialize(self) -> bool:
        """Initialize hash database with current binary hashes."""
        self.hashes = {}

        for binary in self.binaries:
            if Path(binary).exists():
                hash_val = self._calculate_hash(binary)
                if hash_val:
                    self.hashes[binary] = hash_val

        # Save to database
        self.hash_db_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.hash_db_path, 'w') as f:
            json.dump(self.hashes, f, indent=2)

        return True

    def check(self) -> List[IntegrityViolation]:
        """Check all binaries against known hashes."""
        violations = []

        if not self.hashes:
            # No baseline - can't check
            return violations

        for binary, expected_hash in self.hashes.items():
            if not Path(binary).exists():
                violations.append(IntegrityViolation(
                    path=binary,
                    expected_hash=expected_hash,
                    actual_hash='FILE_MISSING',
                    severity='critical'
                ))
                continue

            actual_hash = self._calculate_hash(binary)
            if actual_hash and actual_hash != expected_hash:
                violations.append(IntegrityViolation(
                    path=binary,
                    expected_hash=expected_hash,
                    actual_hash=actual_hash,
                    severity='critical'
                ))

        return violations
