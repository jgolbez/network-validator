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
        self.assertEqual(devices[0].name, "Core Router - DC1")
        self.assertEqual(devices[0].host, "192.168.1.1")
        self.assertEqual(devices[1].name, "Access Switch - Building A")

    def test_load_tests_config(self):
        """Test loading tests.yaml."""
        tests = load_tests_config("config/network1")
        self.assertEqual(len(tests), 8)
        self.assertEqual(tests[0].name, "Default Route Present")
        self.assertEqual(tests[0].match_type, "contains")
        self.assertEqual(tests[1].match_type, "not_contains")
        self.assertEqual(tests[2].match_type, "regex")

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
            "0.0.0.0/0 via 10.0.1.1",  # Default Route test
            "no errors",  # No Errors test
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
        self.assertEqual(report.device_name, "Core Router - DC1")
        self.assertGreater(len(html), 1000)  # HTML should be substantial
        self.assertIn("Core Router - DC1", html)


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
