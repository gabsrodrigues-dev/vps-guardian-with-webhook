#!/usr/bin/env python3
"""
VPS Guardian - Resource Monitor Tests
Tests temporal tracking of CPU/RAM usage with alert thresholds.
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta
from guardian.modules.resources import ResourceMonitor, ResourceAlert


class TestResourceMonitor:
    """Test suite for the ResourceMonitor module."""

    def test_track_high_cpu_process(self, mock_config):
        """Should track process with CPU above threshold."""
        monitor = ResourceMonitor(mock_config)

        with patch('psutil.process_iter') as mock_iter:
            mock_proc = Mock()
            mock_proc.info = {
                'pid': 1234,
                'name': 'cpu_hog',
                'cpu_percent': 90.0,
                'memory_percent': 10.0
            }
            mock_iter.return_value = [mock_proc]

            alerts = monitor.check()

            # First check should start tracking, but not alert yet
            assert len(alerts) == 0
            assert 1234 in monitor.tracked

    def test_alert_after_10_minutes(self, mock_config):
        """Should notify after 10 minutes of high usage."""
        monitor = ResourceMonitor(mock_config)
        now = datetime.now()

        # Manually inject a tracker that's been running for 10+ minutes
        from guardian.modules.resources import ProcessTracker
        tracker = ProcessTracker(
            pid=1234,
            name='long_runner',
            first_seen=now - timedelta(minutes=10, seconds=5),
            last_high_usage=now,
            cpu_samples=[90.0] * 5,
            memory_samples=[30.0] * 5
        )
        monitor.tracked[1234] = tracker

        with patch('psutil.process_iter') as mock_iter:
            mock_proc = Mock()
            mock_proc.info = {
                'pid': 1234,
                'name': 'long_runner',
                'cpu_percent': 90.0,
                'memory_percent': 30.0
            }
            mock_iter.return_value = [mock_proc]

            alerts = monitor.check()

            assert len(alerts) == 1
            alert = alerts[0]
            assert alert.pid == 1234
            assert alert.should_notify is True
            assert alert.should_kill is False
            assert alert.duration_minutes >= 10.0

    def test_kill_after_20_minutes(self, mock_config):
        """Should mark for kill after 20 minutes of high usage."""
        monitor = ResourceMonitor(mock_config)
        now = datetime.now()

        # Inject tracker running for 20+ minutes
        from guardian.modules.resources import ProcessTracker
        tracker = ProcessTracker(
            pid=5678,
            name='persistent_hog',
            first_seen=now - timedelta(minutes=20, seconds=10),
            last_high_usage=now,
            cpu_samples=[85.0] * 10,
            memory_samples=[60.0] * 10
        )
        monitor.tracked[5678] = tracker

        with patch('psutil.process_iter') as mock_iter:
            mock_proc = Mock()
            mock_proc.info = {
                'pid': 5678,
                'name': 'persistent_hog',
                'cpu_percent': 85.0,
                'memory_percent': 60.0
            }
            mock_iter.return_value = [mock_proc]

            alerts = monitor.check()

            assert len(alerts) == 1
            alert = alerts[0]
            assert alert.should_kill is True
            assert alert.duration_minutes >= 20.0
            assert alert.time_until_kill == 0.0

    def test_not_track_whitelisted_process(self, mock_config):
        """Should NOT track whitelisted processes (python, systemd)."""
        monitor = ResourceMonitor(mock_config)

        with patch('psutil.process_iter') as mock_iter:
            mock_proc = Mock()
            mock_proc.info = {
                'pid': 9999,
                'name': 'python3',
                'cpu_percent': 95.0,
                'memory_percent': 70.0
            }
            mock_iter.return_value = [mock_proc]

            alerts = monitor.check()

            assert len(alerts) == 0
            assert 9999 not in monitor.tracked

    def test_clear_tracking_when_normalized(self, mock_config):
        """Should remove tracking when process goes below threshold."""
        monitor = ResourceMonitor(mock_config)
        now = datetime.now()

        # Start with tracked process
        from guardian.modules.resources import ProcessTracker
        tracker = ProcessTracker(
            pid=1111,
            name='normalized_proc',
            first_seen=now - timedelta(minutes=5),
            last_high_usage=now,
            cpu_samples=[90.0] * 5,
            memory_samples=[55.0] * 5
        )
        monitor.tracked[1111] = tracker

        # Now process drops below threshold
        with patch('psutil.process_iter') as mock_iter:
            mock_proc = Mock()
            mock_proc.info = {
                'pid': 1111,
                'name': 'normalized_proc',
                'cpu_percent': 20.0,  # Below threshold
                'memory_percent': 10.0
            }
            mock_iter.return_value = [mock_proc]

            alerts = monitor.check()

            assert len(alerts) == 0
            assert 1111 not in monitor.tracked

    def test_cleanup_dead_processes(self, mock_config):
        """Should cleanup tracking for dead processes."""
        monitor = ResourceMonitor(mock_config)
        now = datetime.now()

        # Add tracked process
        from guardian.modules.resources import ProcessTracker
        tracker = ProcessTracker(
            pid=2222,
            name='dead_proc',
            first_seen=now - timedelta(minutes=5),
            last_high_usage=now,
            cpu_samples=[90.0],
            memory_samples=[60.0]
        )
        monitor.tracked[2222] = tracker

        # Process is no longer in process list (died)
        with patch('psutil.process_iter') as mock_iter:
            mock_iter.return_value = []  # Empty list

            alerts = monitor.check()

            assert 2222 not in monitor.tracked

    def test_skip_self_process(self, mock_config):
        """Should skip monitoring its own PID."""
        monitor = ResourceMonitor(mock_config)

        with patch('psutil.process_iter') as mock_iter:
            mock_proc = Mock()
            mock_proc.info = {
                'pid': monitor.my_pid,
                'name': 'guardian.py',
                'cpu_percent': 99.0,
                'memory_percent': 80.0
            }
            mock_iter.return_value = [mock_proc]

            alerts = monitor.check()

            assert len(alerts) == 0
            assert monitor.my_pid not in monitor.tracked

    def test_notify_only_once(self, mock_config):
        """Should notify only once at 10min, not again at 11min."""
        monitor = ResourceMonitor(mock_config)
        now = datetime.now()

        from guardian.modules.resources import ProcessTracker
        tracker = ProcessTracker(
            pid=3333,
            name='test_proc',
            first_seen=now - timedelta(minutes=10, seconds=5),
            last_high_usage=now,
            cpu_samples=[85.0] * 5,
            memory_samples=[55.0] * 5
        )
        monitor.tracked[3333] = tracker

        with patch('psutil.process_iter') as mock_iter:
            mock_proc = Mock()
            mock_proc.info = {
                'pid': 3333,
                'name': 'test_proc',
                'cpu_percent': 85.0,
                'memory_percent': 55.0
            }
            mock_iter.return_value = [mock_proc]

            # First check - should notify
            alerts = monitor.check()
            assert len(alerts) == 1
            assert alerts[0].should_notify is True

            # Second check (11 minutes) - should NOT notify again
            tracker.first_seen = now - timedelta(minutes=11)
            alerts = monitor.check()
            assert len(alerts) == 1
            assert alerts[0].should_notify is False  # Already notified

    def test_time_until_kill_calculation(self, mock_config):
        """Should correctly calculate time remaining until kill."""
        monitor = ResourceMonitor(mock_config)
        now = datetime.now()

        from guardian.modules.resources import ProcessTracker
        tracker = ProcessTracker(
            pid=4444,
            name='test_proc',
            first_seen=now - timedelta(minutes=15),
            last_high_usage=now,
            cpu_samples=[90.0] * 5,
            memory_samples=[60.0] * 5
        )
        monitor.tracked[4444] = tracker
        monitor.notified_pids.add(4444)  # Already notified

        with patch('psutil.process_iter') as mock_iter:
            mock_proc = Mock()
            mock_proc.info = {
                'pid': 4444,
                'name': 'test_proc',
                'cpu_percent': 90.0,
                'memory_percent': 60.0
            }
            mock_iter.return_value = [mock_proc]

            alerts = monitor.check()

            assert len(alerts) == 1
            alert = alerts[0]
            assert 4.0 <= alert.time_until_kill <= 5.5  # Approximately 5 minutes left
