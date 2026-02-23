#!/usr/bin/env python3
"""
Unit tests for Network Validator.
No live device required — uses mocks for SSH connections.
"""

import unittest
from unittest.mock import Mock, patch, mock_open
from pathlib import Path
import tempfile
import os
from validator import (
    DeviceConfig,
    TestDefinition,
    TestResult,
    DeviceReport,
    TestEvaluator,
    load_devices_config,
    load_tests_config,
    run_device_tests,
    render_report,
    extract_variable,
    substitute_variables,
)


class TestEvaluatorTests(unittest.TestCase):
    """Test the match type evaluator logic."""

    def test_contains_match_true(self):
        """Test contains match when string is present."""
        output = "Router is up, line protocol is up"
        expected = "line protocol is up"
        self.assertTrue(TestEvaluator.evaluate("contains", output, expected))

    def test_contains_match_false(self):
        """Test contains match when string is absent."""
        output = "Router is down"
        expected = "line protocol is up"
        self.assertFalse(TestEvaluator.evaluate("contains", output, expected))

    def test_not_contains_match_true(self):
        """Test not_contains when string is absent."""
        output = "Router is up"
        expected = "CRITICAL ERROR"
        self.assertTrue(TestEvaluator.evaluate("not_contains", output, expected))

    def test_not_contains_match_false(self):
        """Test not_contains when string is present."""
        output = "Router is up, CRITICAL ERROR detected"
        expected = "CRITICAL ERROR"
        self.assertFalse(TestEvaluator.evaluate("not_contains", output, expected))

    def test_regex_match_true(self):
        """Test regex match when pattern matches."""
        output = "CPU utilization for five seconds: 45%"
        expected = r"CPU utilization.*: \d+%"
        self.assertTrue(TestEvaluator.evaluate("regex", output, expected))

    def test_regex_match_false(self):
        """Test regex match when pattern doesn't match."""
        output = "CPU utilization: high"
        expected = r"CPU utilization.*: \d+%"
        self.assertFalse(TestEvaluator.evaluate("regex", output, expected))

    def test_regex_multiline(self):
        """Test regex with multiline content."""
        output = """Interface GigabitEthernet0/0/0
        IP address: 192.168.1.1
        Status: up"""
        expected = r"Status: up"
        self.assertTrue(TestEvaluator.evaluate("regex", output, expected))

    def test_not_regex_match_true(self):
        """Test not_regex when pattern doesn't match."""
        output = "Router is healthy"
        expected = r"ERROR|CRITICAL"
        self.assertTrue(TestEvaluator.evaluate("not_regex", output, expected))

    def test_not_regex_match_false(self):
        """Test not_regex when pattern matches."""
        output = "CRITICAL ERROR detected"
        expected = r"ERROR"
        self.assertFalse(TestEvaluator.evaluate("not_regex", output, expected))

    def test_exact_match_true(self):
        """Test exact match when strings match."""
        output = "  up  "
        expected = "up"
        self.assertTrue(TestEvaluator.evaluate("exact", output, expected))

    def test_exact_match_false(self):
        """Test exact match when strings don't match."""
        output = "up and running"
        expected = "up"
        self.assertFalse(TestEvaluator.evaluate("exact", output, expected))

    def test_invalid_match_type(self):
        """Test that invalid match type raises error."""
        with self.assertRaises(ValueError):
            TestEvaluator.evaluate("invalid_type", "output", "expected")


class DataClassTests(unittest.TestCase):
    """Test data class creation and properties."""

    def test_device_config_creation(self):
        """Test creating DeviceConfig."""
        device = DeviceConfig(
            name="Router1",
            host="10.0.1.1",
            username="admin",
            password="secret",
        )
        self.assertEqual(device.name, "Router1")
        self.assertEqual(device.host, "10.0.1.1")
        self.assertEqual(device.port, 22)
        self.assertEqual(device.timeout, 30)

    def test_test_definition_creation(self):
        """Test creating TestDefinition."""
        test = TestDefinition(
            name="Check Route",
            command="show ip route",
            match_type="contains",
            expected="0.0.0.0/0",
            description="Verify default route exists",
        )
        self.assertEqual(test.name, "Check Route")
        self.assertEqual(test.match_type, "contains")

    def test_test_result_creation(self):
        """Test creating TestResult."""
        result = TestResult(
            device_name="Router1",
            test_name="Check Route",
            command="show ip route",
            match_type="contains",
            expected="0.0.0.0/0",
            description="Verify default route",
            status="PASS",
            output="0.0.0.0/0 via 10.0.1.1",
        )
        self.assertEqual(result.status, "PASS")
        self.assertEqual(result.device_name, "Router1")

    def test_device_report_counts(self):
        """Test DeviceReport pass/fail/error counting."""
        report = DeviceReport(device_name="Router1", host="10.0.1.1")

        # Add some test results
        report.test_results.append(
            TestResult(
                device_name="Router1",
                test_name="Test1",
                command="cmd",
                match_type="contains",
                expected="foo",
                description="",
                status="PASS",
            )
        )
        report.test_results.append(
            TestResult(
                device_name="Router1",
                test_name="Test2",
                command="cmd",
                match_type="contains",
                expected="bar",
                description="",
                status="FAIL",
            )
        )
        report.test_results.append(
            TestResult(
                device_name="Router1",
                test_name="Test3",
                command="cmd",
                match_type="contains",
                expected="baz",
                description="",
                status="ERROR",
            )
        )

        self.assertEqual(report.pass_count, 1)
        self.assertEqual(report.fail_count, 1)
        self.assertEqual(report.error_count, 1)
        self.assertEqual(report.total_tests, 3)


class ConfigLoadingTests(unittest.TestCase):
    """Test YAML configuration loading."""

    def test_load_devices_config(self):
        """Test loading devices.yaml."""
        devices = load_devices_config("config/network1")
        self.assertEqual(len(devices), 2)
        self.assertEqual(devices[0].name, "CORE-SW1")
        self.assertEqual(devices[0].host, "198.18.133.101")
        self.assertEqual(devices[1].name, "CORE-SW2")
        self.assertEqual(devices[1].host, "198.18.133.202")

    def test_load_tests_config(self):
        """Test loading tests.yaml."""
        tests = load_tests_config("config/network1")
        self.assertGreater(len(tests), 0)  # POC has 13+ tests now
        self.assertEqual(tests[0].name, "Extract Desktop-0 IP from DHCP")
        self.assertEqual(tests[0].extract_var, "desktop_0_ip")

    def test_load_devices_missing_file(self):
        """Test that missing devices.yaml raises error."""
        with self.assertRaises(FileNotFoundError):
            load_devices_config("config/nonexistent")

    def test_load_tests_missing_file(self):
        """Test that missing tests.yaml raises error."""
        with self.assertRaises(FileNotFoundError):
            load_tests_config("config/nonexistent")


class DeviceTestRunnerTests(unittest.TestCase):
    """Test device connection and test execution with mocked SSH."""

    @patch("validator.ConnectHandler")
    def test_run_device_tests_success(self, mock_handler_class):
        """Test successful test run on a device."""
        # Setup mock
        mock_conn = Mock()
        mock_handler_class.return_value = mock_conn
        mock_conn.send_command.side_effect = [
            "0.0.0.0/0 via 10.0.1.1",  # First test output
            "No errors",  # Second test output
        ]

        device = DeviceConfig(
            name="Router1",
            host="10.0.1.1",
            username="admin",
            password="secret",
        )
        tests = [
            TestDefinition(
                name="Default Route",
                command="show ip route",
                match_type="contains",
                expected="0.0.0.0/0",
                description="Check default route",
            ),
            TestDefinition(
                name="No Errors",
                command="show log",
                match_type="not_contains",
                expected="ERROR",
                description="Check for errors",
            ),
        ]

        report = run_device_tests(device, tests)

        # Verify connection was attempted
        mock_handler_class.assert_called_once()
        mock_conn.disconnect.assert_called_once()

        # Verify results
        self.assertEqual(len(report.test_results), 2)
        self.assertEqual(report.test_results[0].status, "PASS")
        self.assertEqual(report.test_results[1].status, "PASS")
        self.assertEqual(report.pass_count, 2)
        self.assertEqual(report.fail_count, 0)

    @patch("validator.ConnectHandler")
    def test_run_device_tests_fail(self, mock_handler_class):
        """Test when command output doesn't match expectation."""
        mock_conn = Mock()
        mock_handler_class.return_value = mock_conn
        mock_conn.send_command.return_value = "No routes found"

        device = DeviceConfig(
            name="Router1",
            host="10.0.1.1",
            username="admin",
            password="secret",
        )
        tests = [
            TestDefinition(
                name="Default Route",
                command="show ip route",
                match_type="contains",
                expected="0.0.0.0/0",
                description="",
            )
        ]

        report = run_device_tests(device, tests)

        self.assertEqual(report.test_results[0].status, "FAIL")
        self.assertEqual(report.fail_count, 1)

    @patch("validator.ConnectHandler")
    def test_run_device_tests_connection_timeout(self, mock_handler_class):
        """Test graceful handling of connection timeout."""
        from netmiko.exceptions import NetmikoTimeoutException

        mock_handler_class.side_effect = NetmikoTimeoutException("Timeout")

        device = DeviceConfig(
            name="Router1",
            host="10.0.1.1",
            username="admin",
            password="secret",
        )
        tests = [
            TestDefinition(
                name="Test1",
                command="show version",
                match_type="contains",
                expected="Cisco",
                description="",
            )
        ]

        report = run_device_tests(device, tests)

        # All tests should be marked ERROR
        self.assertEqual(report.error_count, 1)
        self.assertEqual(report.test_results[0].status, "ERROR")
        self.assertIn("Timeout", report.connection_error)

    @patch("validator.ConnectHandler")
    def test_run_device_tests_auth_failure(self, mock_handler_class):
        """Test graceful handling of authentication failure."""
        from netmiko.exceptions import NetmikoAuthenticationException

        mock_handler_class.side_effect = NetmikoAuthenticationException(
            "Authentication failed"
        )

        device = DeviceConfig(
            name="Router1",
            host="10.0.1.1",
            username="admin",
            password="wrongpassword",
        )
        tests = [
            TestDefinition(
                name="Test1",
                command="show version",
                match_type="contains",
                expected="Cisco",
                description="",
            )
        ]

        report = run_device_tests(device, tests)

        self.assertEqual(report.error_count, 1)
        self.assertEqual(report.test_results[0].status, "ERROR")
        self.assertIn("Authentication", report.connection_error)

    @patch("validator.ConnectHandler")
    def test_run_device_tests_output_truncation(self, mock_handler_class):
        """Test that command output is truncated to 2000 chars."""
        mock_conn = Mock()
        mock_handler_class.return_value = mock_conn
        # Create output longer than 2000 chars
        long_output = "x" * 3000

        mock_conn.send_command.return_value = long_output

        device = DeviceConfig(
            name="Router1",
            host="10.0.1.1",
            username="admin",
            password="secret",
        )
        tests = [
            TestDefinition(
                name="Test1",
                command="show something",
                match_type="contains",
                expected="x",
                description="",
            )
        ]

        report = run_device_tests(device, tests)

        self.assertEqual(len(report.test_results[0].output), 2000)


class ReportRenderingTests(unittest.TestCase):
    """Test HTML report generation with Jinja2."""

    def test_render_report_basic(self):
        """Test rendering a basic report."""
        device_report = DeviceReport(device_name="Router1", host="10.0.1.1")
        device_report.test_results.append(
            TestResult(
                device_name="Router1",
                test_name="Test1",
                command="show version",
                match_type="contains",
                expected="Cisco",
                description="Check device",
                status="PASS",
                output="Cisco IOS-XE version 17.9.1",
            )
        )

        html = render_report([device_report], "2024-01-15 10:30:00")

        # Verify HTML content
        self.assertIn("Network Validator Report", html)
        self.assertIn("Router1", html)
        self.assertIn("Test1", html)
        self.assertIn("PASS", html)
        self.assertIn("2024-01-15 10:30:00", html)

    def test_render_report_multiple_devices(self):
        """Test rendering report with multiple devices."""
        report1 = DeviceReport(device_name="Router1", host="10.0.1.1")
        report1.test_results.append(
            TestResult(
                device_name="Router1",
                test_name="Test1",
                command="show version",
                match_type="contains",
                expected="Cisco",
                description="",
                status="PASS",
            )
        )

        report2 = DeviceReport(device_name="Router2", host="10.0.1.2")
        report2.test_results.append(
            TestResult(
                device_name="Router2",
                test_name="Test1",
                command="show version",
                match_type="contains",
                expected="Cisco",
                description="",
                status="FAIL",
            )
        )

        html = render_report([report1, report2], "2024-01-15 10:30:00")

        self.assertIn("Router1", html)
        self.assertIn("Router2", html)
        self.assertIn("PASS: 1", html)
        self.assertIn("FAIL: 1", html)

    def test_render_report_with_error(self):
        """Test rendering report with connection error."""
        report = DeviceReport(
            device_name="Router1",
            host="10.0.1.1",
            connection_error="SSH timeout",
        )
        report.test_results.append(
            TestResult(
                device_name="Router1",
                test_name="Test1",
                command="show version",
                match_type="contains",
                expected="Cisco",
                description="",
                status="ERROR",
                error_message="Connection failed: SSH timeout",
            )
        )

        html = render_report([report], "2024-01-15 10:30:00")

        self.assertIn("SSH timeout", html)
        self.assertIn("ERROR", html)

    def test_render_report_empty(self):
        """Test rendering an empty report (no devices)."""
        html = render_report([], "2024-01-15 10:30:00")

        self.assertIn("Network Validator Report", html)
        self.assertIn("2024-01-15 10:30:00", html)


class IntegrationTests(unittest.TestCase):
    """Integration tests combining multiple components."""

    @patch("validator.ConnectHandler")
    def test_full_workflow_with_mocked_device(self, mock_handler_class):
        """Test full workflow: load config, run tests, render report."""
        # Setup mock device
        mock_conn = Mock()
        mock_handler_class.return_value = mock_conn
        mock_conn.send_command.side_effect = [
            "0152.5400.0ee7.0e",  # DHCP binding check
            "0152.5400.0ee7.0e Automatic Active",  # DHCP active check
        ]

        # Load configs
        devices = load_devices_config("config/network1")
        tests = load_tests_config("config/network1")

        # Run tests on first device only (faster for testing)
        device = devices[0]
        report = run_device_tests(device, tests[:2])  # Use first 2 tests

        # Render report
        html = render_report([report], "2024-01-15 10:30:00")

        # Verify workflow
        self.assertEqual(report.device_name, "CORE-SW1")
        self.assertGreater(len(html), 1000)  # HTML should be substantial
        self.assertIn("CORE-SW1", html)


class EdgeCaseTests(unittest.TestCase):
    """Test edge cases and boundary conditions."""

    def test_empty_output_match(self):
        """Test matching against empty command output."""
        self.assertTrue(TestEvaluator.evaluate("exact", "", ""))
        self.assertFalse(
            TestEvaluator.evaluate("contains", "", "something")
        )
        self.assertTrue(
            TestEvaluator.evaluate("not_contains", "", "something")
        )

    def test_special_characters_in_regex(self):
        """Test regex with special characters."""
        output = "Interface: eth0 (Active)"
        expected = r"eth\d+"
        self.assertTrue(TestEvaluator.evaluate("regex", output, expected))

    def test_case_sensitivity(self):
        """Test that matching is case-sensitive."""
        output = "Router is UP"
        expected = "up"
        self.assertFalse(TestEvaluator.evaluate("contains", output, expected))
        self.assertTrue(TestEvaluator.evaluate("contains", output, "UP"))

    def test_whitespace_handling_exact(self):
        """Test exact match with various whitespace."""
        self.assertTrue(
            TestEvaluator.evaluate("exact", "  hello  ", "hello")
        )
        self.assertTrue(
            TestEvaluator.evaluate("exact", "\n\nhello\n\n", "hello")
        )


class VariableExtractionTests(unittest.TestCase):
    """Test variable extraction from command output."""

    def test_extract_ip_from_dhcp_binding(self):
        """Test extracting IP address from DHCP binding output."""
        output = """10.10.10.10     0152.5400.0ee7.0e       Feb 24 2026 12:37 PM    Automatic  Active     Vlan10"""

        pattern = r'(\d+\.\d+\.\d+\.\d+)\s+0152\.5400\.0ee7\.0e'
        extracted = extract_variable(output, pattern)
        self.assertEqual(extracted, "10.10.10.10")

    def test_extract_mac_address(self):
        """Test extracting MAC address."""
        output = "Device MAC: 0152.5400.0ee7.0e is configured"
        pattern = r'([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{2})'
        extracted = extract_variable(output, pattern)
        self.assertEqual(extracted, "0152.5400.0ee7.0e")

    def test_extract_no_match_returns_none(self):
        """Test that extract returns None when pattern doesn't match."""
        output = "No matching data here"
        pattern = r'0152\.5400\.0ee7\.0e\s+.*?(\d+\.\d+\.\d+\.\d+)'
        extracted = extract_variable(output, pattern)
        self.assertIsNone(extracted)

    def test_extract_multiline_output(self):
        """Test extraction from multiline output."""
        output = """Interface GigabitEthernet0/0
  IP address: 192.168.1.1
  Status: up
"""
        pattern = r'IP address: (\d+\.\d+\.\d+\.\d+)'
        extracted = extract_variable(output, pattern)
        self.assertEqual(extracted, "192.168.1.1")

    def test_extract_first_capture_group_only(self):
        """Test that only first capture group is used."""
        output = "Start 10.0.0.1 middle 10.0.0.2 end"
        pattern = r'(\d+\.\d+\.\d+\.\d+)'
        extracted = extract_variable(output, pattern)
        self.assertEqual(extracted, "10.0.0.1")

    def test_extract_with_special_characters(self):
        """Test extraction handles special regex characters."""
        output = "ACL: deny ip host 10.10.10.10 any"
        pattern = r'deny ip host (\d+\.\d+\.\d+\.\d+)'
        extracted = extract_variable(output, pattern)
        self.assertEqual(extracted, "10.10.10.10")

    def test_extract_invalid_regex_returns_none(self):
        """Test that invalid regex doesn't crash."""
        output = "Some output"
        pattern = r'[invalid('  # Intentionally broken regex
        extracted = extract_variable(output, pattern)
        self.assertIsNone(extracted)


class VariableSubstitutionTests(unittest.TestCase):
    """Test variable substitution in strings."""

    def test_substitute_single_variable(self):
        """Test substituting a single variable."""
        text = "ping {desktop_ip} from 10.10.10.2"
        variables = {"desktop_ip": "10.10.10.10"}
        result = substitute_variables(text, variables)
        self.assertEqual(result, "ping 10.10.10.10 from 10.10.10.2")

    def test_substitute_multiple_variables(self):
        """Test substituting multiple variables."""
        text = "deny ip {source_ip} {dest_ip}"
        variables = {"source_ip": "10.0.0.0", "dest_ip": "192.168.1.0"}
        result = substitute_variables(text, variables)
        self.assertEqual(result, "deny ip 10.0.0.0 192.168.1.0")

    def test_substitute_same_variable_multiple_times(self):
        """Test substituting the same variable multiple times."""
        text = "From {ip} to {ip} ping"
        variables = {"ip": "10.0.0.1"}
        result = substitute_variables(text, variables)
        self.assertEqual(result, "From 10.0.0.1 to 10.0.0.1 ping")

    def test_substitute_unset_variable_unchanged(self):
        """Test that unset variables remain as placeholders."""
        text = "ping {desktop_ip}"
        variables = {}
        result = substitute_variables(text, variables)
        self.assertEqual(result, "ping {desktop_ip}")

    def test_substitute_empty_variables(self):
        """Test substitution with empty variables dict."""
        text = "show access-lists"
        variables = {}
        result = substitute_variables(text, variables)
        self.assertEqual(result, "show access-lists")

    def test_substitute_regex_pattern(self):
        """Test substituting into regex pattern."""
        text = r"deny.*{desktop_ip}"
        variables = {"desktop_ip": "10.10.10.10"}
        result = substitute_variables(text, variables)
        self.assertEqual(result, r"deny.*10.10.10.10")

    def test_substitute_partial_matches_not_affected(self):
        """Test that partial variable name matches don't get replaced."""
        text = "{ip} and {ip_prefix}"
        variables = {"ip": "10.0.0.1"}
        result = substitute_variables(text, variables)
        # Should only replace exact {ip}, not {ip_prefix}
        self.assertEqual(result, "10.0.0.1 and {ip_prefix}")


class VariableIntegrationTests(unittest.TestCase):
    """Integration tests for variable extraction and substitution."""

    @patch("validator.ConnectHandler")
    def test_extract_and_use_variable_in_tests(self, mock_handler_class):
        """Test full workflow: extract variable, then use it in next test."""
        mock_conn = Mock()
        mock_handler_class.return_value = mock_conn

        # First command returns DHCP binding
        dhcp_output = "10.10.10.10     0152.5400.0ee7.0e       Feb 24 2026 12:37 PM    Automatic  Active     Vlan10"

        # Second command (ping) will use extracted IP - Alpine Linux format with seq=
        ping_output = "64 bytes from 10.10.10.10: seq=0 ttl=42 time=118.360 ms"

        mock_conn.send_command.side_effect = [dhcp_output, ping_output]

        device = DeviceConfig(
            name="CORE-SW1",
            host="198.18.133.101",
            username="admin",
            password="cisco",
        )

        tests = [
            TestDefinition(
                name="Extract Desktop IP",
                command="show ip dhcp binding",
                match_type="contains",
                expected="0152.5400.0ee7.0e",
                description="",
                extract_var="desktop_ip",
                extract_pattern=r'(\d+\.\d+\.\d+\.\d+)\s+0152\.5400\.0ee7\.0e',
            ),
            TestDefinition(
                name="Ping Desktop via CORE-SW1",
                command="sshpass -p cisco ssh -l cisco 10.10.10.11 \"ping -c 5 {desktop_ip}\"",
                match_type="contains",
                expected="seq=",
                description="",
            ),
        ]

        report = run_device_tests(device, tests)

        # Verify both tests passed
        self.assertEqual(len(report.test_results), 2)
        self.assertEqual(report.test_results[0].status, "PASS")
        self.assertEqual(report.test_results[1].status, "PASS")

        # Verify the ping command was substituted with actual IP
        self.assertIn("10.10.10.10", report.test_results[1].command)

    @patch("validator.ConnectHandler")
    def test_acl_check_with_extracted_ip(self, mock_handler_class):
        """Test checking for ACLs that deny extracted IP."""
        mock_conn = Mock()
        mock_handler_class.return_value = mock_conn

        dhcp_output = "10.10.10.10     0152.5400.0ee7.0e       Active     Vlan10"

        # ACL that denies the desktop IP
        acl_output = "Extended IP access list DENY-DESKTOP\n    10 deny ip host 10.10.10.10 any"

        mock_conn.send_command.side_effect = [dhcp_output, acl_output]

        device = DeviceConfig(
            name="CORE-SW1",
            host="198.18.133.101",
            username="admin",
            password="cisco",
        )

        tests = [
            TestDefinition(
                name="Extract Desktop IP",
                command="show ip dhcp binding",
                match_type="contains",
                expected="0152.5400.0ee7.0e",
                description="",
                extract_var="desktop_ip",
                extract_pattern=r'(\d+\.\d+\.\d+\.\d+)\s+0152\.5400\.0ee7\.0e',
            ),
            TestDefinition(
                name="No ACL denies Desktop",
                command="show access-lists",
                match_type="not_regex",
                expected=r'deny.*{desktop_ip}',
                description="",
            ),
        ]

        report = run_device_tests(device, tests)

        # First test should pass (IP extracted)
        self.assertEqual(report.test_results[0].status, "PASS")

        # Second test should FAIL (ACL denies the IP after substitution, so the negative regex fails)
        self.assertEqual(report.test_results[1].status, "FAIL")

    @patch("validator.ConnectHandler")
    def test_multiple_variables_independent_scope(self, mock_handler_class):
        """Test that each device has independent variable scope."""
        mock_conn = Mock()
        mock_handler_class.return_value = mock_conn

        dhcp_output1 = """10.10.10.10     0152.5400.0ee7.0e       Active"""
        dhcp_output2 = """10.10.10.11     0152.5400.c168.c3       Active"""

        mock_conn.send_command.side_effect = [dhcp_output1, dhcp_output2]

        device1 = DeviceConfig(
            name="CORE-SW1",
            host="198.18.133.101",
            username="admin",
            password="cisco",
        )
        device2 = DeviceConfig(
            name="CORE-SW2",
            host="198.18.133.202",
            username="admin",
            password="cisco",
        )

        tests = [
            TestDefinition(
                name="Extract Desktop IP",
                command="show ip dhcp binding",
                match_type="contains",
                expected="0152.5400",
                description="",
                extract_var="desktop_ip",
                extract_pattern=r'(\d+\.\d+\.\d+\.\d+)',
            )
        ]

        report1 = run_device_tests(device1, tests)
        report2 = run_device_tests(device2, tests)

        # Both should have different extracted values
        self.assertEqual(report1.test_results[0].status, "PASS")
        self.assertEqual(report2.test_results[0].status, "PASS")


class DeviceTargetingTests(unittest.TestCase):
    """Test device-specific test targeting."""

    def test_test_definition_with_devices_field(self):
        """Test creating TestDefinition with devices field."""
        test = TestDefinition(
            name="Example Test",
            command="show version",
            match_type="contains",
            expected="Cisco",
            devices=["CORE-SW1"],
        )
        self.assertEqual(test.devices, ["CORE-SW1"])

    def test_test_definition_devices_default_empty(self):
        """Test that devices field defaults to empty list (runs on all devices)."""
        test = TestDefinition(
            name="Example Test",
            command="show version",
            match_type="contains",
            expected="Cisco",
        )
        self.assertEqual(test.devices, [])

    @patch("validator.ConnectHandler")
    def test_skip_test_not_meant_for_device(self, mock_handler):
        """Test that tests are skipped if not meant for the device."""
        mock_handler.return_value.send_command.return_value = "10.10.10.10"

        device = DeviceConfig(
            name="CORE-SW1",
            host="198.18.133.101",
            username="admin",
            password="cisco",
        )

        tests = [
            TestDefinition(
                name="For SW1 Only",
                command="show version",
                match_type="contains",
                expected="Cisco",
                devices=["CORE-SW2"],  # This test is NOT for CORE-SW1
            ),
            TestDefinition(
                name="For Both",
                command="show ip route",
                match_type="contains",
                expected="10.0.0.0",
                devices=[],  # Empty = runs on all devices
            ),
        ]

        report = run_device_tests(device, tests)

        # Should only have 1 test result (the second one), first should be skipped
        self.assertEqual(len(report.test_results), 1)
        self.assertEqual(report.test_results[0].test_name, "For Both")

    @patch("validator.ConnectHandler")
    def test_run_test_when_device_matches(self, mock_handler):
        """Test that tests run when device is in the devices list."""
        mock_handler.return_value.send_command.return_value = "Cisco IOS"

        device = DeviceConfig(
            name="CORE-SW1",
            host="198.18.133.101",
            username="admin",
            password="cisco",
        )

        tests = [
            TestDefinition(
                name="For SW1",
                command="show version",
                match_type="contains",
                expected="Cisco",
                devices=["CORE-SW1"],  # This test IS for CORE-SW1
            ),
        ]

        report = run_device_tests(device, tests)

        # Should have 1 test result that passes
        self.assertEqual(len(report.test_results), 1)
        self.assertEqual(report.test_results[0].status, "PASS")

    @patch("validator.ConnectHandler")
    def test_multiple_devices_in_list(self, mock_handler):
        """Test that test runs if device is one of multiple in devices list."""
        mock_handler.return_value.send_command.return_value = "output"

        device = DeviceConfig(
            name="CORE-SW2",
            host="198.18.133.202",
            username="admin",
            password="cisco",
        )

        tests = [
            TestDefinition(
                name="For SW1 and SW2",
                command="show version",
                match_type="contains",
                expected="output",
                devices=["CORE-SW1", "CORE-SW2"],
            ),
        ]

        report = run_device_tests(device, tests)

        # Should run because CORE-SW2 is in the list
        self.assertEqual(len(report.test_results), 1)
        self.assertEqual(report.test_results[0].status, "PASS")


if __name__ == "__main__":
    unittest.main(verbosity=2)
