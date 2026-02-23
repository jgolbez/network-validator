#!/usr/bin/env python3
"""
Network Validator - SSH into Cisco IOS-XE devices, run tests, generate HTML report.
"""

import sys
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable
import yaml
from jinja2 import Template
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException


@dataclass
class DeviceConfig:
    """SSH connection details for a network device."""
    name: str
    host: str
    username: str
    password: str
    device_type: str = "cisco_ios"
    port: int = 22
    timeout: int = 30


@dataclass
class TestDefinition:
    """A single test: command + match criteria."""
    name: str
    command: str
    match_type: str
    expected: str
    description: str = ""
    extract_var: str = ""  # Variable name to extract from output
    extract_pattern: str = ""  # Regex pattern with capture group for extraction
    devices: list[str] = field(default_factory=list)  # Devices to run test on; empty = all devices
    ssh_password: str = ""  # Password for nested SSH commands (when command contains 'ssh')


@dataclass
class TestResult:
    """Outcome of running a single test on a device."""
    device_name: str
    test_name: str
    command: str
    match_type: str
    expected: str
    description: str
    status: str  # PASS, FAIL, ERROR
    output: str = ""
    error_message: str = ""


@dataclass
class DeviceReport:
    """All test results for one device."""
    device_name: str
    host: str
    test_results: list[TestResult] = field(default_factory=list)
    connection_error: str = ""

    @property
    def pass_count(self) -> int:
        return sum(1 for r in self.test_results if r.status == "PASS")

    @property
    def fail_count(self) -> int:
        return sum(1 for r in self.test_results if r.status == "FAIL")

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.test_results if r.status == "ERROR")

    @property
    def total_tests(self) -> int:
        return len(self.test_results)


class TestEvaluator:
    """Dispatcher for match type evaluations."""

    @staticmethod
    def contains(output: str, expected: str) -> bool:
        """String contains check."""
        return expected in output

    @staticmethod
    def not_contains(output: str, expected: str) -> bool:
        """String NOT contains check."""
        return expected not in output

    @staticmethod
    def regex(output: str, expected: str) -> bool:
        """Regex match check."""
        return bool(re.search(expected, output))

    @staticmethod
    def not_regex(output: str, expected: str) -> bool:
        """Regex NOT match check."""
        return not bool(re.search(expected, output))

    @staticmethod
    def exact(output: str, expected: str) -> bool:
        """Exact match (whitespace stripped)."""
        return output.strip() == expected.strip()

    EVALUATORS: dict[str, Callable[[str, str], bool]] = {
        "contains": contains,
        "not_contains": not_contains,
        "regex": regex,
        "not_regex": not_regex,
        "exact": exact,
    }

    @classmethod
    def evaluate(cls, match_type: str, output: str, expected: str) -> bool:
        """Evaluate output against criteria. Returns True if test passes."""
        evaluator = cls.EVALUATORS.get(match_type)
        if not evaluator:
            raise ValueError(f"Unknown match_type: {match_type}")
        return evaluator(output, expected)


def load_devices_config(config_dir: str) -> list[DeviceConfig]:
    """Load devices.yaml from config directory."""
    devices_path = Path(config_dir) / "devices.yaml"
    if not devices_path.exists():
        raise FileNotFoundError(f"devices.yaml not found at {devices_path}")

    with open(devices_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    devices = []
    for dev in data.get("devices", []):
        devices.append(DeviceConfig(**dev))
    return devices


def load_tests_config(config_dir: str) -> list[TestDefinition]:
    """Load tests.yaml from config directory."""
    tests_path = Path(config_dir) / "tests.yaml"
    if not tests_path.exists():
        raise FileNotFoundError(f"tests.yaml not found at {tests_path}")

    with open(tests_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    tests = []
    for test in data.get("tests", []):
        tests.append(TestDefinition(**test))
    return tests


def substitute_variables(text: str, variables: dict[str, str]) -> str:
    """Replace {var_name} placeholders with actual values."""
    result = text
    for var_name, var_value in variables.items():
        result = result.replace(f"{{{var_name}}}", var_value)
    return result


def extract_variable(output: str, pattern: str) -> str | None:
    """Extract a value from output using regex capture group."""
    try:
        match = re.search(pattern, output, re.MULTILINE | re.DOTALL)
        if match and match.groups():
            return match.group(1)
    except Exception:
        pass
    return None


def send_ssh_command_with_password(conn, command: str, password: str) -> str:
    """
    Send an SSH command that prompts for a password (nested SSH scenario).
    Uses expect_string to detect the password prompt, then sends password via write_channel.
    """
    try:
        # Send the SSH command and wait for "Password:" prompt
        output = conn.send_command(
            command,
            expect_string=r"Password:",
            read_timeout=10
        )

        # Send the password as raw text (not a command) and wait for output
        conn.write_channel(password + "\n")

        # Read the command output - wait for either the command to complete or device prompt
        # Use send_command_timing to wait for the output after password is sent
        import time
        time.sleep(1)  # Give the SSH connection time to establish and command to run

        # Read any available output
        remaining_output = conn.read_channel()
        output += remaining_output

        return output
    except Exception as e:
        # Fallback: try sending without special handling
        try:
            return conn.send_command(command, read_timeout=30)
        except Exception:
            raise e


def run_device_tests(
    device: DeviceConfig, tests: list[TestDefinition], global_variables: dict[str, str] | None = None
) -> DeviceReport:
    """
    SSH into device, run all tests, collect results.
    Gracefully degrade on connection failure.
    Supports variable extraction and substitution.
    global_variables: variables extracted from other devices, available to all tests
    """
    report = DeviceReport(device_name=device.name, host=device.host)
    # Start with global variables, then add device-specific extractions
    variables: dict[str, str] = dict(global_variables) if global_variables else {}

    # Attempt connection
    try:
        connection_params = {
            "device_type": device.device_type,
            "host": device.host,
            "username": device.username,
            "password": device.password,
            "port": device.port,
            "timeout": device.timeout,
            "ssh_strict": False,  # Lab-friendly; disable for production if desired
        }
        conn = ConnectHandler(**connection_params)
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        report.connection_error = str(e)
        # Mark all applicable tests as ERROR
        for test in tests:
            # Skip tests not meant for this device
            if test.devices and device.name not in test.devices:
                continue
            report.test_results.append(
                TestResult(
                    device_name=device.name,
                    test_name=test.name,
                    command=test.command,
                    match_type=test.match_type,
                    expected=test.expected,
                    description=test.description,
                    status="ERROR",
                    error_message=f"Connection failed: {e}",
                )
            )
        return report
    except Exception as e:
        report.connection_error = f"Unexpected error: {e}"
        for test in tests:
            # Skip tests not meant for this device
            if test.devices and device.name not in test.devices:
                continue
            report.test_results.append(
                TestResult(
                    device_name=device.name,
                    test_name=test.name,
                    command=test.command,
                    match_type=test.match_type,
                    expected=test.expected,
                    description=test.description,
                    status="ERROR",
                    error_message=f"Connection failed: {e}",
                )
            )
        return report

    # Run tests
    try:
        for test in tests:
            try:
                # Skip test if not meant for this device
                if test.devices and device.name not in test.devices:
                    continue

                # Substitute variables in command and expected pattern
                command = substitute_variables(test.command, variables)
                expected = substitute_variables(test.expected, variables)

                # Send command - use special handling for nested SSH with password
                if "ssh" in command.lower() and test.ssh_password:
                    output = send_ssh_command_with_password(conn, command, test.ssh_password)
                else:
                    output = conn.send_command(command)
                # Truncate output to 2000 chars for report
                truncated_output = output[:2000]

                # Extract variable if pattern is defined
                if test.extract_pattern:
                    extracted_value = extract_variable(output, test.extract_pattern)
                    if extracted_value and test.extract_var:
                        variables[test.extract_var] = extracted_value

                passed = TestEvaluator.evaluate(
                    test.match_type, output, expected
                )
                status = "PASS" if passed else "FAIL"

                report.test_results.append(
                    TestResult(
                        device_name=device.name,
                        test_name=test.name,
                        command=command,
                        match_type=test.match_type,
                        expected=expected,
                        description=test.description,
                        status=status,
                        output=truncated_output,
                    )
                )
            except Exception as e:
                # Test execution error (not connection, but command send failed)
                report.test_results.append(
                    TestResult(
                        device_name=device.name,
                        test_name=test.name,
                        command=test.command,
                        match_type=test.match_type,
                        expected=test.expected,
                        description=test.description,
                        status="ERROR",
                        error_message=str(e),
                    )
                )
    finally:
        conn.disconnect()

    return report


def extract_variables_from_device(
    device: DeviceConfig, tests: list[TestDefinition]
) -> dict[str, str]:
    """
    Extract variables from a device by running extraction tests only.
    Returns a dict of extracted variables.
    """
    variables: dict[str, str] = {}

    # Only extract from tests meant for this device
    extraction_tests = [t for t in tests if (not t.devices or device.name in t.devices) and t.extract_var]

    if not extraction_tests:
        return variables

    try:
        connection_params = {
            "device_type": device.device_type,
            "host": device.host,
            "username": device.username,
            "password": device.password,
            "port": device.port,
            "timeout": device.timeout,
            "ssh_strict": False,
        }
        conn = ConnectHandler(**connection_params)

        for test in extraction_tests:
            try:
                output = conn.send_command(test.command)
                if test.extract_pattern:
                    extracted_value = extract_variable(output, test.extract_pattern)
                    if extracted_value and test.extract_var:
                        variables[test.extract_var] = extracted_value
            except Exception:
                pass

        conn.disconnect()
    except Exception:
        pass

    return variables


def render_report(device_reports: list[DeviceReport], run_timestamp: str) -> str:
    """
    Render list of DeviceReport objects using Jinja2 template.
    Returns HTML string.
    """
    template_path = Path(__file__).parent / "templates" / "report.html.j2"
    if not template_path.exists():
        raise FileNotFoundError(f"Template not found at {template_path}")

    with open(template_path, "r", encoding="utf-8") as f:
        template_content = f.read()

    template = Template(template_content)

    # Compute summary stats
    total_pass = sum(r.pass_count for r in device_reports)
    total_fail = sum(r.fail_count for r in device_reports)
    total_error = sum(r.error_count for r in device_reports)

    html = template.render(
        device_reports=device_reports,
        run_timestamp=run_timestamp,
        total_pass=total_pass,
        total_fail=total_fail,
        total_error=total_error,
    )
    return html


def main():
    """Main entry point."""
    if len(sys.argv) != 2:
        print("Usage: python validator.py <config_directory>")
        print("Example: python validator.py config/network1")
        sys.exit(1)

    config_dir = sys.argv[1]

    # Validate config directory exists
    config_path = Path(config_dir)
    if not config_path.is_dir():
        print(f"Error: {config_dir} is not a valid directory")
        sys.exit(1)

    # Load configs
    try:
        devices = load_devices_config(config_dir)
        tests = load_tests_config(config_dir)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)

    if not devices:
        print("Error: No devices configured")
        sys.exit(1)

    if not tests:
        print("Error: No tests configured")
        sys.exit(1)

    print(f"Loaded {len(devices)} device(s) and {len(tests)} test(s)")
    print(f"Starting test run...")

    # Extract variables from all devices first (these become global/shared)
    print("Extracting variables...")
    global_variables: dict[str, str] = {}
    for device in devices:
        extracted = extract_variables_from_device(device, tests)
        global_variables.update(extracted)
        if extracted:
            print(f"  {device.name}: extracted {len(extracted)} variable(s)")

    # Run tests on all devices with extracted variables available globally
    device_reports = []
    for device in devices:
        print(f"  Testing {device.name} ({device.host})...")
        report = run_device_tests(device, tests, global_variables)
        device_reports.append(report)

    # Generate report
    run_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html_content = render_report(device_reports, run_timestamp)

    # Derive output filename from config directory name
    # e.g., "config/network1" -> "network1_report.html"
    config_dir_name = Path(config_dir).name
    output_file = Path.cwd() / f"{config_dir_name}_report.html"

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"Report written to: {output_file}")
    print("Done!")


if __name__ == "__main__":
    main()
