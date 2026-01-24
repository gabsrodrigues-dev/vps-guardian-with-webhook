#!/usr/bin/env python3
"""
VPS Guardian - Integrity Checker Tests
Tests binary hash verification and rootkit detection.
"""

import pytest
import json
from pathlib import Path
from guardian.modules.integrity import IntegrityChecker, IntegrityViolation


class TestIntegrityChecker:
    """Test suite for the IntegrityChecker module."""

    @pytest.fixture
    def integrity_config(self, tmp_path):
        """Integrity checker configuration with test files."""
        # Create test binaries
        bin1 = tmp_path / 'bin1'
        bin1.write_text('original binary 1')

        bin2 = tmp_path / 'bin2'
        bin2.write_text('original binary 2')

        hash_db = tmp_path / 'hashes.json'

        return {
            'integrity': {
                'critical_binaries': [str(bin1), str(bin2)],
                'hash_db': str(hash_db)
            }
        }

    def test_initialize_hash_database(self, integrity_config, tmp_path):
        """Should initialize hash database with current binary hashes."""
        checker = IntegrityChecker(integrity_config)

        result = checker.initialize()

        assert result is True
        hash_db = Path(integrity_config['integrity']['hash_db'])
        assert hash_db.exists()

        with open(hash_db) as f:
            hashes = json.load(f)

        assert len(hashes) == 2
        for binary in integrity_config['integrity']['critical_binaries']:
            assert binary in hashes

    def test_detect_modified_binary(self, integrity_config, tmp_path):
        """Should detect when binary hash changes (rootkit)."""
        checker = IntegrityChecker(integrity_config)
        checker.initialize()

        # Modify one of the binaries
        bin1 = Path(integrity_config['integrity']['critical_binaries'][0])
        bin1.write_text('MALICIOUS ROOTKIT CODE')

        violations = checker.check()

        assert len(violations) == 1
        assert violations[0].path == str(bin1)
        assert violations[0].severity == 'critical'
        assert violations[0].actual_hash != violations[0].expected_hash

    def test_detect_missing_binary(self, integrity_config, tmp_path):
        """Should detect when critical binary is deleted."""
        checker = IntegrityChecker(integrity_config)
        checker.initialize()

        # Delete one binary
        bin1 = Path(integrity_config['integrity']['critical_binaries'][0])
        bin1.unlink()

        violations = checker.check()

        assert len(violations) == 1
        assert violations[0].path == str(bin1)
        assert violations[0].actual_hash == 'FILE_MISSING'

    def test_no_violations_when_unchanged(self, integrity_config, tmp_path):
        """Should return no violations when binaries are unchanged."""
        checker = IntegrityChecker(integrity_config)
        checker.initialize()

        violations = checker.check()

        assert len(violations) == 0

    def test_no_baseline_returns_empty(self, integrity_config, tmp_path):
        """Should return empty list when no baseline exists."""
        # Don't initialize, just check
        checker = IntegrityChecker(integrity_config)

        violations = checker.check()

        assert len(violations) == 0

    def test_hash_calculation_consistency(self, integrity_config, tmp_path):
        """Should calculate same hash for same file content."""
        checker = IntegrityChecker(integrity_config)

        bin1 = Path(integrity_config['integrity']['critical_binaries'][0])
        hash1 = checker._calculate_hash(str(bin1))
        hash2 = checker._calculate_hash(str(bin1))

        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex digest

    def test_handle_nonexistent_file_hash(self, integrity_config):
        """Should return None for nonexistent file."""
        checker = IntegrityChecker(integrity_config)

        hash_val = checker._calculate_hash('/tmp/does_not_exist_12345')

        assert hash_val is None

    def test_load_existing_hash_database(self, integrity_config, tmp_path):
        """Should load existing hash database on initialization."""
        # Create hash database manually
        hash_db = Path(integrity_config['integrity']['hash_db'])
        hash_db.parent.mkdir(parents=True, exist_ok=True)

        test_hashes = {
            '/usr/bin/test1': 'abc123',
            '/usr/bin/test2': 'def456'
        }

        with open(hash_db, 'w') as f:
            json.dump(test_hashes, f)

        checker = IntegrityChecker(integrity_config)

        assert checker.hashes == test_hashes

    def test_multiple_modifications_detected(self, integrity_config, tmp_path):
        """Should detect multiple modified binaries."""
        checker = IntegrityChecker(integrity_config)
        checker.initialize()

        # Modify both binaries
        for binary_path in integrity_config['integrity']['critical_binaries']:
            Path(binary_path).write_text('COMPROMISED')

        violations = checker.check()

        assert len(violations) == 2
        for violation in violations:
            assert violation.severity == 'critical'
