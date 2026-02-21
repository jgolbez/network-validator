# Network Validator

A Python-based CLI tool that SSHes into Cisco IOS-XE devices, runs predefined show commands, evaluates the output against configurable criteria, and generates a self-contained HTML pass/fail report. **Runs on Windows and Linux. No AI/LLM involved — pure deterministic evaluation against regex/substring patterns.**

## Features

- **Multi-device testing**: Define multiple devices per network
- **Flexible test criteria**: Supports `contains`, `not_contains`, `regex`, `not_regex`, and `exact` match types
- **Graceful degradation**: One unreachable device doesn't crash the entire run; partial results are still generated
- **Self-contained HTML reports**: Single file with inline CSS, works offline
- **Multi-network support**: Manage separate configs for `network1`, `network2`, etc.; each has its own output file
- **YAML-based configuration**: Easy to read and edit for operators

## Architecture

### Libraries

- **Netmiko** (4.4.0): Handles IOS-XE SSH, pagination, and prompts automatically
- **PyYAML** (6.0.2): Configuration parsing
- **Jinja2** (3.1.4): HTML report templating

### Files

```
claude-nw-validator/
├── validator.py              # Main script (single shared tool)
├── templates/
│   └── report.html.j2        # Jinja2 HTML template
├── config/
│   ├── network1/
│   │   ├── devices.yaml      # Devices for network 1
│   │   └── tests.yaml        # Tests for network 1
│   └── network2/
│       ├── devices.yaml      # Devices for network 2
│       └── tests.yaml        # Tests for network 2
├── network1_report.html      # Output: report for network1 (overwritten each run)
├── network2_report.html      # Output: report for network2
├── requirements.txt
└── README.md
```

## Setup

### Windows

1. **Install Python 3.10+** from python.org or `winget install Python.Python.3.12`

2. **Create a virtual environment**:
   ```cmd
   python -m venv .venv
   .venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```cmd
   pip install -r requirements.txt
   ```

4. **Configure your devices and tests** in `config/network1/` (see Configuration below)

5. **Run the validator**:
   ```cmd
   python validator.py config/network1
   ```

6. **View the report**:
   Open `network1_report.html` in your browser (or copy to a file share and open from Windows Explorer)

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python validator.py config/network1
```

## Configuration

### `config/network1/devices.yaml`

Define SSH connection details for each device:

```yaml
devices:
  - name: "Core Router - DC1"
    host: "10.0.1.1"
    username: "admin"
    password: "s3cr3t"
    device_type: "cisco_ios"  # Must be "cisco_ios" for IOS-XE
    port: 22
    timeout: 30  # seconds; increase for slow devices

  - name: "Access Switch - Building A"
    host: "10.0.2.1"
    username: "admin"
    password: "s3cr3t"
    device_type: "cisco_ios"
    port: 22
    timeout: 30
```

**Required fields**: `name`, `host`, `username`, `password`, `device_type` (cisco_ios)
**Optional fields**: `port` (default 22), `timeout` (default 30)

### `config/network1/tests.yaml`

Define test cases that run against all devices:

```yaml
tests:
  - name: "Default Route Present"
    description: "Verify 0.0.0.0/0 exists in routing table"
    command: "show ip route 0.0.0.0"
    match_type: "contains"       # contains | not_contains | regex | not_regex | exact
    expected: "0.0.0.0/0"

  - name: "WAN Interface Up"
    description: "Check GigabitEthernet0/0 is up"
    command: "show interface GigabitEthernet0/0"
    match_type: "regex"
    expected: "GigabitEthernet0/0 is up, line protocol is up"

  - name: "Approved IOS-XE Version"
    description: "Validate running IOS version"
    command: "show version"
    match_type: "contains"
    expected: "Version 17.09.04a"

  - name: "No Critical Errors"
    description: "Verify no CRITICAL log entries"
    command: "show log | include CRITICAL"
    match_type: "not_contains"
    expected: "CRITICAL"
```

**Match types**:
- `contains`: String contains substring
- `not_contains`: String does NOT contain substring
- `regex`: Python regex match (case-sensitive, full pattern search)
- `not_regex`: Regex does NOT match
- `exact`: Full output (whitespace-trimmed) equals expected value exactly

**Required fields**: `name`, `command`, `match_type`, `expected`
**Optional field**: `description` (defaults to empty string)

## Usage

### Single Network

```bash
python validator.py config/network1
```

Output: `network1_report.html` in the project root

### Multiple Networks

Create separate config directories for each network:

```bash
python validator.py config/network1
python validator.py config/network2
python validator.py config/network3
```

Each run generates its own output file (`network1_report.html`, `network2_report.html`, `network3_report.html`), always overwriting the previous result so the file is always current.

### Automation / Scheduling

#### Windows Task Scheduler

Create a batch file `run_validator.bat`:
```batch
@echo off
cd C:\path\to\claude-nw-validator
.venv\Scripts\activate && python validator.py config/network1
```

Schedule via Task Scheduler to run daily/hourly.

#### Linux / macOS Cron

```bash
0 */6 * * * cd /home/user/claude-nw-validator && source .venv/bin/activate && python validator.py config/network1
```

## Report

The HTML report is **self-contained** (inline CSS, no external CDN) and includes:

- **Header**: Tool name, run timestamp, summary badges (PASS/FAIL/ERROR counts)
- **Device sections**: Collapsible per-device details
  - Device name, IP address, mini summary
  - Connection error banner (if device unreachable)
  - Results table: Test Name | Description | Command | Match Type | Expected | Output | Status
- **Row colors**: Green (PASS), Red (FAIL), Orange (ERROR)
- **Scrollable output**: Device command output capped at 2000 chars, displayed in a scrollable box
- **Footer**: Total counts

Open `network1_report.html` in any modern browser (Chrome, Firefox, Safari, Edge). Works offline; safe to email or place on a file share.

## Troubleshooting

### "Connection timed out"

- **Device is down/unreachable**: The tool marks all tests as ERROR for that device and continues (graceful degradation).
- **SSH port is not 22**: Update `port` in `devices.yaml`.
- **Firewall blocking SSH**: Verify connectivity with `ssh -v admin@10.0.1.1` from the same machine.

### "Authentication failed"

- **Wrong username/password**: Verify credentials in `devices.yaml`.
- **Device requires SSH key instead of password**: Not currently supported; Netmiko can be extended for key-based auth. File an issue if needed.

### "Command timed out"

- **Device is slow or command takes >30 seconds**: Increase `timeout` in `devices.yaml` (e.g., 60).
- **Command hangs on interactive prompt**: Ensure the command is non-interactive (e.g., use filters: `show log | include ERROR`).

### Python module not found

```bash
pip install --upgrade -r requirements.txt
```

### On Windows: "Script is disabled" when running

Allow script execution:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Performance Notes

- **Large device count** (50+): Runs serially (one device at a time). Consider batching into smaller networks or parallelizing in a wrapper script if needed.
- **Large test count** (100+): Each test SSH commands sequentially on each device. ~2–5 seconds per test per device is typical.
- **Command output size**: Output is truncated to 2000 chars in the report to keep HTML reasonable.

## Security Notes

- **Credentials in YAML**: `devices.yaml` contains plaintext passwords. **Protect this file!** Use file permissions (`chmod 600 config/network1/devices.yaml` on Linux, file ACLs on Windows) and version-control `.gitignore`.
- **SSH host key verification**: Set to `False` for lab environments (in `validator.py`, already configured as `"ssh_strict": False`). For production, remove or set to `True` and pre-populate known_hosts.

## Future Enhancements

- Device-specific test targeting (run subset of tests on certain devices)
- Parallel device execution for faster runs
- SSH key-based authentication
- Pre/post-test commands (enable privilege mode, save config, etc.)
- Result diffing (compare current run to previous)
- Time-series storage of results

## Questions or Issues?

If something doesn't work as expected, verify:
1. Python 3.10+ is installed: `python --version`
2. Dependencies are installed: `pip list | grep netmiko`
3. Config YAML parses: `python -c "import yaml; print(yaml.safe_load(open('config/network1/devices.yaml')))"`
4. Device is reachable: `ssh admin@10.0.1.1` (or your device IP)

Good luck!
