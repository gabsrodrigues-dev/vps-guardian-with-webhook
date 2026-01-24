#!/usr/bin/env python3
"""
VPS Guardian - Anti-Cryptojacking Protection System
Main orchestrator that coordinates all detection modules.
"""

import os
import sys
import time
import yaml
import logging
from pathlib import Path

# Setup logging
def setup_logging():
    """Configure logging with fallback for non-root execution."""
    handlers = [logging.StreamHandler(sys.stdout)]

    # Try to write to /var/log, fallback to local log if not root
    try:
        handlers.append(logging.FileHandler('/var/log/guardian.log'))
    except PermissionError:
        log_dir = Path(__file__).parent / 'logs'
        log_dir.mkdir(exist_ok=True)
        handlers.append(logging.FileHandler(log_dir / 'guardian.log'))

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=handlers
    )

setup_logging()
logger = logging.getLogger('guardian')

# Paths
GUARDIAN_DIR = Path(__file__).parent
CONFIG_PATH = GUARDIAN_DIR / 'config.yaml'

def load_config():
    """Load configuration from YAML file."""
    try:
        with open(CONFIG_PATH, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {CONFIG_PATH}")
        sys.exit(1)
    except yaml.YAMLError as e:
        logger.error(f"Invalid YAML configuration: {e}")
        sys.exit(1)

def clean_zombies():
    """Clean zombie processes by killing their parents."""
    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'status', 'ppid', 'name']):
            try:
                if proc.info['status'] == psutil.STATUS_ZOMBIE:
                    ppid = proc.info['ppid']
                    if ppid > 1:
                        logger.warning(f"Zombie detected (PID {proc.info['pid']}). Killing parent (PID {ppid})...")
                        parent = psutil.Process(ppid)
                        parent.kill()
                        logger.info(f"Parent {ppid} eliminated.")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except ImportError:
        logger.warning("psutil not installed. Zombie cleanup disabled.")

def main():
    """Main loop - orchestrates all detection modules."""
    my_pid = os.getpid()
    logger.info(f"VPS Guardian started (PID {my_pid})")

    try:
        config = load_config()
        logger.info("Configuration loaded successfully")
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        sys.exit(1)

    # Import detection modules
    try:
        from modules import (
            Detector, ResourceMonitor, NetworkMonitor,
            IntegrityChecker, FilesystemMonitor,
            ResponseHandler, ResponseLevel
        )
        logger.info("Detection modules loaded successfully")
    except ImportError as e:
        logger.error(f"Failed to import detection modules: {e}")
        sys.exit(1)

    # Initialize modules
    try:
        detector = Detector(config)
        resource_monitor = ResourceMonitor(config)
        network_monitor = NetworkMonitor(config)
        integrity_checker = IntegrityChecker(config)
        filesystem_monitor = FilesystemMonitor(config)
        response_handler = ResponseHandler(config)
        logger.info("All modules initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize modules: {e}", exc_info=True)
        sys.exit(1)

    scan_interval = config['detection']['scan_interval_seconds']
    logger.info(f"Starting monitoring loop (scan interval: {scan_interval}s)")

    while True:
        try:
            clean_zombies()

            # PRIORITY 1: Detector - Suspicious process names/terms (HARD_KILL)
            try:
                threats = detector.scan()
                for threat in threats:
                    logger.warning(f"Threat detected: {threat.reason} - PID {threat.pid} ({threat.name})")
                    response_handler.handle_threat(
                        pid=threat.pid,
                        name=threat.name,
                        reason=threat.reason,
                        level=ResponseLevel.KILL,
                        exe_path=threat.exe,
                        extra_details={'severity': threat.severity, 'cmdline': threat.cmdline}
                    )
            except Exception as e:
                logger.error(f"Error in detector.scan(): {e}", exc_info=True)

            # PRIORITY 2: Network - Mining pool connections (HARD_KILL)
            try:
                network_threats = network_monitor.scan()
                for threat in network_threats:
                    logger.warning(f"Network threat: {threat.reason} - PID {threat.pid} ({threat.name})")
                    try:
                        import psutil
                        proc = psutil.Process(threat.pid)
                        exe_path = proc.exe()
                    except:
                        exe_path = None

                    response_handler.handle_threat(
                        pid=threat.pid,
                        name=threat.name,
                        reason=threat.reason,
                        level=ResponseLevel.KILL,
                        exe_path=exe_path,
                        extra_details={
                            'remote_ip': threat.remote_ip,
                            'remote_port': threat.remote_port
                        }
                    )
            except Exception as e:
                logger.error(f"Error in network_monitor.scan(): {e}", exc_info=True)

            # PRIORITY 3: Integrity - Binary tampering (HARD_KILL + CRITICAL ALERT)
            try:
                violations = integrity_checker.check()
                for violation in violations:
                    logger.critical(f"INTEGRITY VIOLATION: {violation.path} - Expected: {violation.expected_hash[:16]}... Got: {violation.actual_hash[:16] if violation.actual_hash != 'FILE_MISSING' else 'MISSING'}")
                    # For integrity violations, we can't kill a specific PID
                    # Just log as critical incident
                    response_handler._log_incident(response_handler.Incident(
                        timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
                        pid=0,
                        process_name='N/A',
                        threat_type='integrity_violation',
                        reason=f"Binary tampered: {violation.path}",
                        action_taken='critical_alert',
                        details={
                            'expected_hash': violation.expected_hash,
                            'actual_hash': violation.actual_hash,
                            'severity': violation.severity
                        }
                    ))
            except Exception as e:
                logger.error(f"Error in integrity_checker.check(): {e}", exc_info=True)

            # PRIORITY 4: Filesystem - Executables in temp dirs (KILL)
            try:
                suspicious_files = filesystem_monitor.scan()
                for sus_file in suspicious_files:
                    logger.warning(f"Suspicious file: {sus_file.path} - {sus_file.reason}")
                    # Try to find which process is using this file
                    import psutil
                    file_deleted = False
                    for proc in psutil.process_iter(['pid', 'name', 'exe']):
                        try:
                            if proc.info['exe'] == sus_file.path:
                                response_handler.handle_threat(
                                    pid=proc.info['pid'],
                                    name=proc.info['name'],
                                    reason=f"Suspicious executable: {sus_file.reason}",
                                    level=ResponseLevel.KILL,
                                    exe_path=sus_file.path,
                                    extra_details={
                                        'file_age_minutes': sus_file.age_minutes,
                                        'file_size': sus_file.size_bytes
                                    }
                                )
                                file_deleted = True
                                break
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue

                    # If no process found, just quarantine the file
                    if not file_deleted and os.path.exists(sus_file.path):
                        try:
                            response_handler._quarantine_file(sus_file.path)
                            logger.info(f"Quarantined orphan file: {sus_file.path}")
                        except Exception as qe:
                            logger.error(f"Failed to quarantine {sus_file.path}: {qe}")
            except Exception as e:
                logger.error(f"Error in filesystem_monitor.scan(): {e}", exc_info=True)

            # PRIORITY 5: Resources - Sustained CPU/RAM (NOTIFY or KILL)
            try:
                resource_alerts = resource_monitor.check()
                for alert in resource_alerts:
                    if alert.should_kill:
                        logger.warning(f"Resource KILL: {alert.name} (PID {alert.pid}) - {alert.duration_minutes:.1f}min sustained usage")
                        try:
                            import psutil
                            proc = psutil.Process(alert.pid)
                            exe_path = proc.exe()
                        except:
                            exe_path = None

                        response_handler.handle_threat(
                            pid=alert.pid,
                            name=alert.name,
                            reason=f"Sustained high resource usage for {alert.duration_minutes:.1f} minutes",
                            level=ResponseLevel.KILL,
                            exe_path=exe_path,
                            extra_details={
                                'cpu_percent': alert.cpu_percent,
                                'memory_percent': alert.memory_percent,
                                'duration_minutes': alert.duration_minutes
                            }
                        )
                    elif alert.should_notify:
                        logger.info(f"Resource NOTIFY: {alert.name} (PID {alert.pid}) - {alert.duration_minutes:.1f}min, kill in {alert.time_until_kill:.1f}min")
                        response_handler.handle_threat(
                            pid=alert.pid,
                            name=alert.name,
                            reason=f"High resource usage for {alert.duration_minutes:.1f} minutes",
                            level=ResponseLevel.NOTIFY,
                            exe_path=None,
                            extra_details={
                                'cpu_percent': alert.cpu_percent,
                                'memory_percent': alert.memory_percent,
                                'duration_minutes': alert.duration_minutes,
                                'time_until_kill': alert.time_until_kill
                            }
                        )
            except Exception as e:
                logger.error(f"Error in resource_monitor.check(): {e}", exc_info=True)

            time.sleep(scan_interval)

        except KeyboardInterrupt:
            logger.info("Guardian stopped by user")
            break
        except Exception as e:
            logger.error(f"Error in main loop: {e}", exc_info=True)
            time.sleep(scan_interval)

if __name__ == "__main__":
    main()
