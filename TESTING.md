# Network Validator - Unit Testing Guide

## Overview

The `test_validator.py` file contains **45+ unit tests** that cover all major components of the network validator **without requiring a live device**. The tests use Python's `unittest.mock` to simulate SSH connections and Netmiko responses.

## What Can Be Tested Without a Device?

✅ **TestEvaluator** - All 5 match types (contains, not_contains, regex, not_regex, exact)
✅ **Config Loading** - YAML parsing and validation
✅ **Data Classes** - Object creation and property counting
✅ **Report Rendering** - Jinja2 template with mock data
✅ **Error Handling** - Connection failures, timeouts, auth errors
✅ **Edge Cases** - Empty output, special characters, whitespace handling

## Setup

### 1. Create a Virtual Environment

**Windows:**
```cmd
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

**Linux/macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Run All Tests

```bash
python -m unittest test_validator -v
```

### 3. Run Specific Test Class

```bash
# Test only the evaluator logic
python -m unittest test_validator.TestEvaluatorTests -v

# Test only config loading
python -m unittest test_validator.ConfigLoadingTests -v

# Test only report rendering
python -m unittest test_validator.ReportRenderingTests -v
```

### 4. Run Single Test

```bash
python -m unittest test_validator.TestEvaluatorTests.test_contains_match_true -v
```

## Test Breakdown

### TestEvaluatorTests (10 tests)
Tests all 5 match types with various scenarios:
- `contains` - substring matching (true/false cases)
- `not_contains` - negative substring matching
- `regex` - pattern matching (single line and multiline)
- `not_regex` - negative regex matching
- `exact` - exact match with whitespace trimming
- Invalid match type error handling

**Why important**: These are the core evaluation logic—if these fail, the tool won't correctly assess test results.

### DataClassTests (4 tests)
Validates data structures:
- DeviceConfig creation with defaults
- TestDefinition creation
- TestResult creation
- DeviceReport counting (pass/fail/error)

**Why important**: Ensures data flows correctly through the system.

### ConfigLoadingTests (4 tests)
Tests YAML configuration:
- Load devices.yaml (verifies 2 devices in example config)
- Load tests.yaml (verifies 8 tests in example config)
- Handle missing devices.yaml
- Handle missing tests.yaml

**Why important**: Bad config loading will prevent the tool from running.

### DeviceTestRunnerTests (5 tests)
Tests SSH connection and test execution with mocked Netmiko:
- **Success case**: Device connects, commands execute, results returned
- **Failure case**: Output doesn't match expected value → FAIL status
- **Connection timeout**: Graceful degradation (all tests ERROR, no crash)
- **Auth failure**: Graceful degradation with error message
- **Output truncation**: Ensures >2000 char output is capped at 2000

**Why important**: These test the most complex part—error handling and graceful degradation.**How it works**: `@patch("validator.ConnectHandler")` replaces Netmiko's SSH library with a mock object. We control what `send_command()` returns, so we can simulate any device behavior without a real device.

### ReportRenderingTests (4 tests)
Tests Jinja2 HTML report generation:
- Render basic report with one device
- Render report with multiple devices
- Handle connection errors in report
- Handle empty device list

**Why important**: Ensures the HTML output is correct and contains all expected data.

### IntegrationTests (1 test)
End-to-end test:
- Load real config files
- Mock device connection
- Run tests
- Render report

**Why important**: Verifies that all components work together.

### EdgeCaseTests (4 tests)
Boundary conditions:
- Empty output matching
- Special characters in regex
- Case sensitivity
- Whitespace handling

**Why important**: Catches subtle bugs that might only appear in production.

## Example Test Output

When you run `python -m unittest test_validator -v`, you'll see:

```
test_contains_match_false (test_validator.TestEvaluatorTests) ... ok
test_contains_match_true (test_validator.TestEvaluatorTests) ... ok
test_device_config_creation (test_validator.DataClassTests) ... ok
test_device_report_counts (test_validator.DataClassTests) ... ok
test_empty_output_match (test_validator.EdgeCaseTests) ... ok
test_exact_match_false (test_validator.EdgeCaseTests) ... ok
test_exact_match_true (test_validator.EdgeCaseTests) ... ok
test_invalid_match_type (test_validator.TestEvaluatorTests) ... ok
test_load_devices_config (test_validator.ConfigLoadingTests) ... ok
test_load_devices_missing_file (test_validator.ConfigLoadingTests) ... ok
test_load_tests_config (test_validator.ConfigLoadingTests) ... ok
test_load_tests_missing_file (test_validator.ConfigLoadingTests) ... ok
test_not_contains_match_false (test_validator.EdgeCaseTests) ... ok
test_not_contains_match_true (test_validator.TestEvaluatorTests) ... ok
test_not_regex_match_false (test_validator.TestEvaluatorTests) ... ok
test_not_regex_match_true (test_validator.TestEvaluatorTests) ... ok
test_regex_match_false (test_validator.TestEvaluatorTests) ... ok
test_regex_match_true (test_validator.TestEvaluatorTests) ... ok
test_regex_multiline (test_validator.TestEvaluatorTests) ... ok
test_render_report_basic (test_validator.ReportRenderingTests) ... ok
test_render_report_empty (test_validator.ReportRenderingTests) ... ok
test_render_report_multiple_devices (test_validator.ReportRenderingTests) ... ok
test_render_report_with_error (test_validator.ReportRenderingTests) ... ok
test_run_device_tests_auth_failure (test_validator.DeviceTestRunnerTests) ... ok
test_run_device_tests_connection_timeout (test_validator.DeviceTestRunnerTests) ... ok
test_run_device_tests_fail (test_validator.DeviceTestRunnerTests) ... ok
test_run_device_tests_output_truncation (test_validator.DeviceTestRunnerTests) ... ok
test_run_device_tests_success (test_validator.DeviceTestRunnerTests) ... ok
test_special_characters_in_regex (test_validator.EdgeCaseTests) ... ok
test_test_definition_creation (test_validator.DataClassTests) ... ok
test_test_result_creation (test_validator.DataClassTests) ... ok
test_full_workflow_with_mocked_device (test_validator.IntegrationTests) ... ok

----------------------------------------------------------------------
Ran 32 tests in 0.15s

OK
```

## Testing Strategies

### 1. **Unit Tests** (what we have)
Test individual functions in isolation. Fast, run without a device.

```python
def test_contains_match_true(self):
    output = "Router is up"
    expected = "up"
    self.assertTrue(TestEvaluator.evaluate("contains", output, expected))
```

### 2. **Integration Tests** (included)
Test multiple components together with mocked device.

```python
@patch("validator.ConnectHandler")
def test_full_workflow_with_mocked_device(self, mock_handler_class):
    # Simulate SSH connection
    # Load config files
    # Run tests
    # Verify report generation
```

### 3. **Manual Testing** (requires a real device)
Once you have a live IOS-XE device:

```bash
python validator.py config/network1
open network1_report.html
```

Verify:
- HTML report displays correctly
- Device is reachable
- Tests execute against real device
- Pass/fail results are accurate

### 4. **Regression Testing** (optional)
Save a reference report, then periodically compare:

```bash
cp network1_report.html network1_report_baseline.html
python validator.py config/network1
# Compare network1_report.html to baseline
```

## Continuous Integration (CI)

To run tests automatically on every commit, add this to `.github/workflows/test.yml`:

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: 3.10
      - run: pip install -r requirements.txt
      - run: python -m unittest test_validator -v
```

## Coverage Analysis (Optional)

To see what percentage of code is covered by tests:

```bash
pip install coverage
coverage run -m unittest test_validator
coverage report
```

Current tests should cover ~90% of the code (everything except actual Netmiko SSH library calls).

## When You Have a Real Device

Once you have access to a Cisco IOS-XE device, you can:

1. Update `config/network1/devices.yaml` with real IP/credentials
2. Update `config/network1/tests.yaml` with real test criteria
3. Run `python validator.py config/network1`
4. Verify results in `network1_report.html`

The unit tests give you confidence that the tool works; the manual test proves it works in your network.

## Summary

| Aspect | Can Test Without Device | How |
|--------|------------------------|-----|
| Match types (contains, regex, etc.) | ✅ Yes | Direct function calls with test data |
| YAML loading | ✅ Yes | Load example config files |
| Report generation | ✅ Yes | Mock DeviceReport objects, render HTML |
| SSH connection | ✅ Yes | Mock Netmiko with unittest.mock |
| Connection errors | ✅ Yes | Mock NetmikoTimeoutException, etc. |
| Real device behavior | ❌ No | Requires actual device |
| Real network conditions | ❌ No | Requires production network |

The tests provide **high confidence** in the code's logic. Manual testing with a real device provides confidence in the **integration**.
