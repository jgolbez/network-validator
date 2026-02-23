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


def ip_to_int(ip_str: str) -> int:
    """Convert IP address string to integer."""
    parts = ip_str.split('.')
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])


def int_to_ip(ip_int: int) -> str:
    """Convert integer to IP address string."""
    return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"


def is_ip_in_network(ip_str: str, network_str: str, wildcard_str: str) -> bool:
    """
    Check if an IP address falls within a network/wildcard range.

    Args:
        ip_str: IP address to check (e.g., "10.10.10.50")
        network_str: Network address (e.g., "10.0.0.0")
        wildcard_str: Wildcard mask (e.g., "0.255.255.255")

    Returns:
        True if IP is within the network, False otherwise
    """
    try:
        ip_int = ip_to_int(ip_str)
        network_int = ip_to_int(network_str)
        wildcard_int = ip_to_int(wildcard_str)

        # IP is in network if: (IP ^ network) & ~wildcard == 0
        # Or equivalently: (IP ^ network) is a subset of wildcard
        return (ip_int ^ network_int) & ~wildcard_int == 0
    except Exception:
        return False


def check_ip_blocked_by_acl(acl_output: str, target_ip: str, target_subnet_mask: str) -> bool:
    """
    Check if a target IP is blocked by any deny rule in ACL output.
    Handles both standard and extended ACL formats, including broader denies.

    Args:
        acl_output: Output from "show access-lists" command
        target_ip: IP address to check (e.g., "10.10.10.50")
        target_subnet_mask: Subnet mask (e.g., "255.255.255.0")

    Returns:
        True if target IP is blocked by any deny rule, False otherwise
    """
    import re

    # Pattern 1: deny with IP and wildcard/mask
    deny_pattern_with_mask = r'deny\s+(?:ip\s+)?(?:host\s+)?(\d+\.\d+\.\d+\.\d+)\s+([\d\.]+)'

    # Pattern 2: deny with just IP (host)
    deny_pattern_host_only = r'deny\s+(?:ip\s+)?(?:host\s+)?(\d+\.\d+\.\d+\.\d+)(?:\s+any)?(?:\n|$)'

    # Pattern 3: wildcard bits notation
    deny_pattern_wildcard_bits = r'deny\s+(?:ip\s+)?(\d+\.\d+\.\d+\.\d+),?\s+wildcard\s+bits\s+([\d\.]+)'

    # Check deny rules with mask/wildcard
    for denied_ip, denied_mask_or_wildcard in re.findall(deny_pattern_with_mask, acl_output):
        try:
            denied_mask_int = ip_to_int(denied_mask_or_wildcard)

            # If most high bits are 255, it's a subnet mask; convert to wildcard
            if denied_mask_int > 0xFF000000:
                wildcard_int = denied_mask_int ^ 0xFFFFFFFF
            else:
                wildcard_int = denied_mask_int

            wildcard_str = int_to_ip(wildcard_int)

            if is_ip_in_network(target_ip, denied_ip, wildcard_str):
                return True
        except Exception:
            pass

    # Check deny rules with just host IP
    for denied_ip in re.findall(deny_pattern_host_only, acl_output, re.MULTILINE):
        if denied_ip == target_ip:
            return True

    # Check deny rules with wildcard bits notation
    for denied_ip, wildcard_str in re.findall(deny_pattern_wildcard_bits, acl_output):
        try:
            if is_ip_in_network(target_ip, denied_ip, wildcard_str):
                return True
        except Exception:
            pass

    return False


def calculate_network_and_wildcard(ip_str: str, subnet_mask_str: str) -> tuple[str, str]:
    """
    Calculate network address and wildcard mask from IP and subnet mask.

    Args:
        ip_str: IP address (e.g., "10.10.10.50")
        subnet_mask_str: Subnet mask (e.g., "255.255.255.0")

    Returns:
        Tuple of (network_address, wildcard_mask)
        Example: ("10.10.10.0", "0.0.0.255")
    """
    ip_int = ip_to_int(ip_str)
    mask_int = ip_to_int(subnet_mask_str)

    # Network address = IP & Subnet Mask
    network_int = ip_int & mask_int
    network_addr = int_to_ip(network_int)

    # Wildcard mask = inverted subnet mask (NOT of subnet mask)
    wildcard_int = mask_int ^ 0xFFFFFFFF  # XOR with all 1s to invert
    wildcard_addr = int_to_ip(wildcard_int)

    return (network_addr, wildcard_addr)


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


@dataclass
class Constraint:
    """High-level constraint/restriction for attendee report (groups multiple tests)."""
    name: str  # e.g., "Checking for Access-Lists"
    description: str  # What this constraint validates
    test_names: list[str]  # Names of tests that must all PASS for this constraint to PASS
    invert_result: bool = False  # If True, constraint passes when tests FAIL (useful for negative tests)
    status: str = ""  # PASS, FAIL, ERROR (filled in during evaluation)

    def evaluate(self, test_results: list[TestResult]) -> str:
        """
        Evaluate constraint based on test results.
        Returns 'PASS', 'FAIL', or 'ERROR'.
        """
        matching_tests = [t for t in test_results if t.test_name in self.test_names]

        if not matching_tests:
            return "ERROR"  # No tests matched this constraint

        statuses = [t.status for t in matching_tests]

        # If any test is ERROR, constraint is ERROR
        if "ERROR" in statuses:
            return "ERROR"

        # Check if all tests passed (or all failed if inverted)
        all_passed = all(status == "PASS" for status in statuses)

        if self.invert_result:
            # For inverted constraints (like "Connectivity should FAIL after task completion")
            all_failed = all(status == "FAIL" for status in statuses)
            return "PASS" if all_failed else "FAIL"
        else:
            # Normal constraint: all tests must pass
            return "PASS" if all_passed else "FAIL"


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
    Waits for command completion with extended timeout for slow commands (ping, traceroute, etc).
    """
    try:
        import time

        # Send the SSH command and wait for "Password:" prompt
        output = conn.send_command(
            command,
            expect_string=r"Password:",
            read_timeout=10
        )

        # Send the password as raw text (not a command) and wait for output
        conn.write_channel(password + "\n")

        # Give the remote command time to execute (especially for ping/traceroute which take several seconds)
        # Sleep longer for commands that might take 10+ seconds
        time.sleep(3)

        # Read any available output after command execution
        remaining_output = conn.read_channel()
        output += remaining_output

        # If still not getting full output, read more with extended timeout
        if remaining_output:
            time.sleep(1)
            more_output = conn.read_channel()
            output += more_output

        return output
    except Exception as e:
        # Fallback: try sending without special handling
        try:
            return conn.send_command(command, read_timeout=45)
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

                # Calculate derived values (network and wildcard from IP and subnet mask)
                if "desktop_0_ip" in variables and "desktop_0_subnet_mask" in variables:
                    try:
                        network, wildcard = calculate_network_and_wildcard(
                            variables["desktop_0_ip"],
                            variables["desktop_0_subnet_mask"]
                        )
                        variables["desktop_0_network"] = network
                        variables["desktop_0_wildcard"] = wildcard
                    except Exception:
                        pass

                # Re-substitute now that we have new variables
                expected = substitute_variables(test.expected, variables)
                command = substitute_variables(test.command, variables)

                # Special handling for ACL tests: use intelligent IP blocking check
                if "ACL" in test.name.upper() and "show access-lists" in command:
                    if "desktop_0_ip" in variables and "desktop_0_subnet_mask" in variables:
                        # Use intelligent ACL checking instead of regex
                        is_blocked = check_ip_blocked_by_acl(
                            output,
                            variables["desktop_0_ip"],
                            variables["desktop_0_subnet_mask"]
                        )
                        # Test passes if IP is NOT blocked (not_regex semantics)
                        passed = not is_blocked
                        status = "PASS" if passed else "FAIL"
                    else:
                        # Fall back to standard evaluation if variables missing
                        passed = TestEvaluator.evaluate(test.match_type, output, expected)
                        status = "PASS" if passed else "FAIL"
                else:
                    # Standard evaluation for all other tests
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

    # Calculate derived values (network and wildcard from IP and subnet mask)
    if "desktop_0_ip" in variables and "desktop_0_subnet_mask" in variables:
        try:
            network, wildcard = calculate_network_and_wildcard(
                variables["desktop_0_ip"],
                variables["desktop_0_subnet_mask"]
            )
            variables["desktop_0_network"] = network
            variables["desktop_0_wildcard"] = wildcard
        except Exception:
            pass

    return variables


def get_constraints() -> list[Constraint]:
    """
    Define high-level constraints/restrictions for attendee report.
    Maps multiple tests to logical business checks.
    """
    return [
        Constraint(
            name="Checking Active DHCP Leases",
            description="Both desktops must have active DHCP leases",
            test_names=["Desktop-0 uses DHCP", "Desktop-1 uses DHCP"],
        ),
        Constraint(
            name="Checking Access-Lists Configuration",
            description="No access-lists can block traffic to Desktop-0",
            test_names=["No ACL denies Desktop-0 Host or Subnet"],
        ),
        Constraint(
            name="Checking for Connectivity to Desktop-0",
            description="Desktop-1 should NOT be able to ping Desktop-0 (task complete) or CAN (task incomplete)",
            test_names=["Desktop-1 can ping Desktop-0 (before task)"],
            invert_result=True,  # Passes when ping test FAILS (connectivity blocked)
        ),
    ]


def render_report(device_reports: list[DeviceReport], run_timestamp: str) -> str:
    """
    Render list of DeviceReport objects using Jinja2 template (detailed report).
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


def render_attendee_report(device_reports: list[DeviceReport], run_timestamp: str) -> str:
    """
    Render attendee-focused report with high-level constraint checks (no detailed test output).
    Returns HTML string.
    """
    template_path = Path(__file__).parent / "templates" / "attendee_report.html.j2"
    if not template_path.exists():
        raise FileNotFoundError(f"Template not found at {template_path}")

    with open(template_path, "r", encoding="utf-8") as f:
        template_content = f.read()

    template = Template(template_content)

    # Get all test results from all devices
    all_test_results = []
    for device_report in device_reports:
        all_test_results.extend(device_report.test_results)

    # Evaluate constraints
    constraints = get_constraints()
    for constraint in constraints:
        constraint.status = constraint.evaluate(all_test_results)

    # Compute summary stats
    pass_count = sum(1 for c in constraints if c.status == "PASS")
    fail_count = sum(1 for c in constraints if c.status == "FAIL")
    error_count = sum(1 for c in constraints if c.status == "ERROR")

    html = template.render(
        constraints=constraints,
        run_timestamp=run_timestamp,
        pass_count=pass_count,
        fail_count=fail_count,
        error_count=error_count,
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

    # Generate reports
    run_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    detailed_html = render_report(device_reports, run_timestamp)
    attendee_html = render_attendee_report(device_reports, run_timestamp)

    # Derive output filenames from config directory name
    # e.g., "config/network1" -> "network1_report.html" and "network1_attendee_report.html"
    config_dir_name = Path(config_dir).name
    detailed_file = Path.cwd() / f"{config_dir_name}_report.html"
    attendee_file = Path.cwd() / f"{config_dir_name}_attendee_report.html"

    with open(detailed_file, "w", encoding="utf-8") as f:
        f.write(detailed_html)

    with open(attendee_file, "w", encoding="utf-8") as f:
        f.write(attendee_html)

    print(f"Detailed report written to: {detailed_file}")
    print(f"Attendee report written to: {attendee_file}")
    print("Done!")


if __name__ == "__main__":
    main()
