#!/usr/bin/env python3
"""
VPS Guardian - Integration Tests
Tests complete workflows from detection to response.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from guardian.modules.detector import Detector
from guardian.modules.response import ResponseHandler, ResponseLevel


class TestIntegration:
    """Integration tests for complete Guardian workflows."""

    def test_full_flow_suspicious_process_detected_killed_quarantined_logged(self, mock_config, tmp_path):
        """
        Complete flow: Detect suspicious process → Kill it → Quarantine binary → Log incident
        """
        # Setup
        quarantine_dir = tmp_path / 'quarantine'
        quarantine_dir.mkdir()
        log_file = tmp_path / 'incidents.jsonl'

        mock_config['response']['quarantine_dir'] = str(quarantine_dir)
        mock_config['response']['log_file'] = str(log_file)

        # Create fake malicious binary
        malicious_binary = tmp_path / 'xmrig'
        malicious_binary.write_text('FAKE MINING MALWARE')

        # Initialize modules
        detector = Detector(mock_config)
        response_handler = ResponseHandler(mock_config)

        # Step 1: Process detection
        with patch('psutil.process_iter') as mock_iter:
            mock_proc = Mock()
            mock_proc.info = {
                'pid': 6666,
                'name': 'xmrig',
                'exe': str(malicious_binary),
                'cmdline': ['xmrig', '-o', 'pool.minexmr.com:4444']
            }
            mock_iter.return_value = [mock_proc]

            threats = detector.scan()

        # Verify detection
        assert len(threats) == 1
        threat = threats[0]
        assert threat.pid == 6666
        assert threat.name == 'xmrig'
        assert threat.severity == 'high'

        # Step 2: Kill process and quarantine
        with patch('psutil.Process') as mock_process_class:
            mock_proc_instance = Mock()
            mock_proc_instance.children.return_value = []
            mock_proc_instance.terminate = Mock()
            mock_proc_instance.wait = Mock()
            mock_process_class.return_value = mock_proc_instance

            incident = response_handler.handle_threat(
                pid=threat.pid,
                name=threat.name,
                reason=threat.reason,
                level=ResponseLevel.KILL,
                exe_path=str(malicious_binary)
            )

        # Verify kill happened
        mock_proc_instance.terminate.assert_called_once()

        # Verify quarantine
        assert not malicious_binary.exists()
        quarantined_files = list(quarantine_dir.glob('*xmrig'))
        assert len(quarantined_files) == 1

        # Verify logging
        assert log_file.exists()
        import json
        with open(log_file) as f:
            logged_incident = json.loads(f.read())
            assert logged_incident['pid'] == 6666
            assert logged_incident['process_name'] == 'xmrig'
            assert 'killed' in logged_incident['action_taken']

    def test_resource_monitoring_escalation_flow(self, mock_config, tmp_path):
        """
        Resource monitoring flow: Track CPU → Notify at 10min → Kill at 20min
        """
        from guardian.modules.resources import ResourceMonitor
        from datetime import datetime, timedelta

        mock_config['response']['quarantine_dir'] = str(tmp_path / 'quarantine')
        mock_config['response']['log_file'] = str(tmp_path / 'incidents.jsonl')

        monitor = ResourceMonitor(mock_config)
        response_handler = ResponseHandler(mock_config)

        # Simulate tracking over time
        with patch('psutil.process_iter') as mock_iter:
            mock_proc = Mock()
            mock_proc.info = {
                'pid': 7777,
                'name': 'cpu_hog',
                'cpu_percent': 95.0,
                'memory_percent': 60.0
            }
            mock_iter.return_value = [mock_proc]

            # First check - start tracking
            alerts = monitor.check()
            assert len(alerts) == 0  # No alert yet

            # Simulate 10+ minutes passing
            from guardian.modules.resources import ProcessTracker
            now = datetime.now()
            tracker = ProcessTracker(
                pid=7777,
                name='cpu_hog',
                first_seen=now - timedelta(minutes=10, seconds=5),
                last_high_usage=now,
                cpu_samples=[95.0] * 10,
                memory_samples=[60.0] * 10
            )
            monitor.tracked[7777] = tracker

            # Second check - should notify
            alerts = monitor.check()
            assert len(alerts) == 1
            assert alerts[0].should_notify is True
            assert alerts[0].should_kill is False

            # Handle notification
            with patch('requests.post'):
                incident = response_handler.handle_threat(
                    pid=7777,
                    name='cpu_hog',
                    reason='High CPU usage for 10 minutes',
                    level=ResponseLevel.NOTIFY,
                    extra_details={'cpu_percent': 95.0, 'duration_minutes': 10.5}
                )
            assert incident.action_taken == 'notified'

            # Simulate 20+ minutes passing
            tracker.first_seen = now - timedelta(minutes=20, seconds=10)

            # Third check - should kill
            alerts = monitor.check()
            assert len(alerts) == 1
            assert alerts[0].should_kill is True

            # Handle kill
            with patch('psutil.Process') as mock_proc_class:
                mock_proc_instance = Mock()
                mock_proc_instance.children.return_value = []
                mock_proc_instance.terminate = Mock()
                mock_proc_instance.wait = Mock()
                mock_proc_class.return_value = mock_proc_instance

                incident = response_handler.handle_threat(
                    pid=7777,
                    name='cpu_hog',
                    reason='High CPU usage for 20 minutes',
                    level=ResponseLevel.KILL
                )

            assert 'killed' in incident.action_taken

    def test_network_threat_immediate_response(self, mock_config, tmp_path):
        """
        Network threat flow: Detect mining pool connection → Immediate kill
        """
        from guardian.modules.network import NetworkMonitor
        from collections import namedtuple

        # Setup network config
        mining_pools_file = tmp_path / 'mining-pools.txt'
        mining_pools_file.write_text('pool.minexmr.com\n')

        tor_nodes_file = tmp_path / 'tor-nodes.txt'
        tor_nodes_file.write_text('185.220.101.1\n')

        network_config = {
            'network': {
                'mining_pools_list': str(mining_pools_file),
                'tor_nodes_list': str(tor_nodes_file),
                'suspicious_ports': [3333, 4444]
            },
            'response': {
                'quarantine_dir': str(tmp_path / 'quarantine'),
                'log_file': str(tmp_path / 'incidents.jsonl'),
                'telegram': {'enabled': False}
            }
        }

        monitor = NetworkMonitor(network_config)
        response_handler = ResponseHandler(network_config)

        # Detect connection to mining port
        MockConnection = namedtuple('Connection', ['pid', 'status', 'laddr', 'raddr'])
        MockAddr = namedtuple('Addr', ['ip', 'port'])

        with patch('psutil.net_connections') as mock_net_conn:
            with patch('psutil.Process') as mock_proc_class:
                mock_proc = Mock()
                mock_proc.name.return_value = 'suspicious_app'
                mock_proc_class.return_value = mock_proc

                mock_net_conn.return_value = [
                    MockConnection(
                        pid=8888,
                        status='ESTABLISHED',
                        laddr=MockAddr('192.168.1.100', 50000),
                        raddr=MockAddr('45.76.230.12', 3333)  # Mining port
                    )
                ]

                threats = monitor.scan()

        assert len(threats) == 1
        assert threats[0].remote_port == 3333

        # Immediate kill response
        with patch('psutil.Process') as mock_proc_class:
            mock_proc_instance = Mock()
            mock_proc_instance.children.return_value = []
            mock_proc_instance.terminate = Mock()
            mock_proc_instance.wait = Mock()
            mock_proc_class.return_value = mock_proc_instance

            incident = response_handler.handle_threat(
                pid=8888,
                name='suspicious_app',
                reason='Connection to mining port: 3333',
                level=ResponseLevel.KILL
            )

        assert 'killed' in incident.action_taken

    def test_whitelisted_process_not_affected(self, mock_config):
        """
        Whitelist flow: Ensure whitelisted processes are never flagged
        """
        detector = Detector(mock_config)

        from guardian.modules.resources import ResourceMonitor
        resource_monitor = ResourceMonitor(mock_config)

        # Check detector ignores whitelisted
        with patch('psutil.process_iter') as mock_iter:
            mock_proc = Mock()
            mock_proc.info = {
                'pid': 9999,
                'name': 'tracker-miner-fs',
                'exe': '/usr/libexec/tracker-miner-fs',
                'cmdline': ['/usr/libexec/tracker-miner-fs']
            }
            mock_iter.return_value = [mock_proc]

            threats = detector.scan()
            assert len(threats) == 0

        # Check resource monitor ignores whitelisted
        with patch('psutil.process_iter') as mock_iter:
            mock_proc = Mock()
            mock_proc.info = {
                'pid': 10000,
                'name': 'python3',
                'cpu_percent': 99.0,
                'memory_percent': 80.0
            }
            mock_iter.return_value = [mock_proc]

            alerts = resource_monitor.check()
            assert len(alerts) == 0
