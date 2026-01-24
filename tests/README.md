# VPS Guardian Test Suite

Comprehensive test suite for VPS Guardian with 100% coverage of critical paths.

## Test Structure

```
tests/
├── conftest.py           # Shared fixtures and configuration
├── test_detector.py      # Process detector tests (11 tests)
├── test_resources.py     # Resource monitor tests (10 tests)
├── test_network.py       # Network monitor tests (11 tests)
├── test_integrity.py     # Integrity checker tests (9 tests)
├── test_filesystem.py    # Filesystem monitor tests (12 tests)
├── test_response.py      # Response handler tests (14 tests)
└── test_integration.py   # Integration tests (4 tests)
```

## Installation

Install test dependencies:

```bash
pip install -r requirements-dev.txt
```

Or use system packages:

```bash
sudo apt install python3-pytest python3-pytest-mock python3-pytest-cov
```

## Running Tests

### All tests
```bash
make test
```

### With coverage
```bash
make test-cov
```

### Verbose mode
```bash
make test-verbose
```

### Specific test file
```bash
python3 -m pytest tests/test_detector.py -v
```

### Specific test function
```bash
python3 -m pytest tests/test_detector.py::TestDetector::test_detect_suspicious_term_xmrig -v
```

## Test Coverage

### test_detector.py (11 tests)
- ✅ Detect suspicious terms (xmrig, monero)
- ✅ Detect processes in /tmp
- ✅ Detect fake kernel processes
- ✅ NOT detect legitimate processes
- ✅ NOT detect whitelisted paths
- ✅ Detect random name patterns
- ✅ Skip real kernel threads
- ✅ Scan multiple processes
- ✅ Skip self process

### test_resources.py (10 tests)
- ✅ Track high CPU processes
- ✅ Alert after 10 minutes
- ✅ Kill after 20 minutes
- ✅ NOT track whitelisted
- ✅ Clear tracking when normalized
- ✅ Cleanup dead processes
- ✅ Skip self process
- ✅ Notify only once
- ✅ Calculate time until kill

### test_network.py (11 tests)
- ✅ Detect mining port connections
- ✅ Detect TOR node connections
- ✅ NOT detect normal connections
- ✅ Skip non-established connections
- ✅ Skip self connections
- ✅ Detect mining pool domains
- ✅ Handle process access denied
- ✅ Reload blocklists
- ✅ Skip connections without remote addr
- ✅ Multiple threats in single scan

### test_response.py (14 tests - CRITICAL)
- ✅ Kill simple process
- ✅ Kill process with children (no zombies)
- ✅ Kill already dead process
- ✅ Handle permission denied
- ✅ Quarantine file
- ✅ Block path traversal
- ✅ Handle nonexistent file
- ✅ Send Telegram notification
- ✅ Disabled notification
- ✅ Handle notification failure
- ✅ Log incidents
- ✅ Handle NOTIFY level
- ✅ Handle KILL level

### test_integrity.py (9 tests)
- ✅ Initialize hash database
- ✅ Detect modified binary
- ✅ Detect missing binary
- ✅ No violations when unchanged
- ✅ No baseline returns empty
- ✅ Hash calculation consistency
- ✅ Handle nonexistent file
- ✅ Load existing database
- ✅ Multiple modifications detected

### test_filesystem.py (12 tests)
- ✅ Detect new executable
- ✅ Detect hidden executable
- ✅ Detect ELF binary
- ✅ NOT detect old files
- ✅ NOT detect non-executable
- ✅ Scan multiple directories
- ✅ Handle nonexistent directory
- ✅ Recursive scan subdirectories
- ✅ Skip tiny executables
- ✅ Multiple suspicious reasons
- ✅ File metadata accuracy

### test_integration.py (4 tests)
- ✅ Full flow: detect → kill → quarantine → log
- ✅ Resource monitoring escalation
- ✅ Network threat immediate response
- ✅ Whitelisted process not affected

## Edge Cases Tested

- Process already dead
- Permission denied errors
- Path traversal attempts
- Network timeouts
- Missing files
- Zombie process prevention
- Self-process detection
- Whitelist bypass attempts

## Mock Usage

Tests use `pytest-mock` to simulate:
- `psutil.process_iter()` - Process enumeration
- `psutil.Process()` - Process operations
- `psutil.net_connections()` - Network connections
- `requests.post()` - Telegram notifications
- `socket.gethostbyaddr()` - Reverse DNS

No real processes are created during testing.

## Coverage Target

Target: 90%+ coverage on critical modules
- detector.py: 95%+
- response.py: 100% (CRITICAL)
- resources.py: 95%+
- network.py: 90%+

Run `make test-cov` to see detailed coverage report.
