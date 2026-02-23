# Variable Extraction and Substitution Guide

The Network Validator now supports **dynamic variable extraction and substitution**, enabling tests that reference dynamically discovered values.

## How It Works

### 1. Extract Variables from Command Output

Any test can extract a value from its command output using a regex capture group:

```yaml
- name: "Extract Desktop-0 IP from DHCP"
  description: "Find desktop-0's DHCP-assigned IP by matching its MAC"
  command: "show ip dhcp binding"
  match_type: "contains"
  expected: "0152.5400.0ee7.0e"
  extract_var: "desktop_0_ip"
  extract_pattern: '0152\.5400\.0ee7\.0e\s+.*?(\d+\.\d+\.\d+\.\d+)'
```

**Key fields:**
- `extract_var`: Name of the variable to store (e.g., `desktop_0_ip`)
- `extract_pattern`: Regex pattern with a capture group `(...)` that captures the value
  - The **first capture group** `(...)` will be extracted
  - Use `\s+` for whitespace, `\d+` for digits, `\.` for literal dots
  - Patterns are matched with `re.MULTILINE | re.DOTALL` for multi-line matching

### 2. Use Variables in Subsequent Tests

Reference extracted variables using `{variable_name}` syntax:

```yaml
- name: "No ACL denies Desktop-0"
  description: "Check that no access-list denies traffic to desktop-0"
  command: "show access-lists"
  match_type: "not_contains"
  expected: "deny.*{desktop_0_ip}"
```

Before the test runs:
- `{desktop_0_ip}` is replaced with the extracted value (e.g., `10.10.10.10`)
- The `expected` pattern becomes: `deny.*10\.10\.10\.10`
- The test evaluates normally with substituted values

## Examples from POC

### Example 1: Extract and Use IP in Ping Test

```yaml
# Extract the IP
- name: "Extract Desktop-0 IP from DHCP"
  command: "show ip dhcp binding"
  match_type: "contains"
  expected: "0152.5400.0ee7.0e"
  extract_var: "desktop_0_ip"
  extract_pattern: '0152\.5400\.0ee7\.0e\s+.*?(\d+\.\d+\.\d+\.\d+)'

# Use it in a subsequent ping test
- name: "Ping Desktop-0 should succeed"
  command: "ping {desktop_0_ip} source 10.10.10.2"
  match_type: "contains"
  expected: "!!!"
```

### Example 2: Extract and Verify No ACL Denies It

```yaml
# Extract MAC-identified IP
- name: "Extract Desktop-1 IP"
  command: "show ip dhcp binding"
  match_type: "contains"
  expected: "0152.5400.c168.c3"
  extract_var: "desktop_1_ip"
  extract_pattern: '0152\.5400\.c168\.c3\s+.*?(\d+\.\d+\.\d+\.\d+)'

# Verify no ACL blocks it
- name: "No ACL denies Desktop-1"
  command: "show access-lists"
  match_type: "not_contains"
  expected: "deny.*{desktop_1_ip}"
```

## Regex Pattern Tips

### Matching DHCP Binding Output

Original output:
```
10.10.10.10     0152.5400.0ee7.0e       Feb 24 2026 12:37 PM    Automatic  Active     Vlan10
```

Pattern to extract IP:
```regex
0152\.5400\.0ee7\.0e\s+.*?(\d+\.\d+\.\d+\.\d+)
```

**Breakdown:**
- `0152\.5400\.0ee7\.0e` - Match the exact MAC (escaping dots)
- `\s+` - Match one or more whitespace chars
- `.*?` - Match anything (non-greedy) until...
- `(\d+\.\d+\.\d+\.\d+)` - Capture group: match and capture an IP address

### Common Patterns

**Extract IP address:**
```regex
(\d+\.\d+\.\d+\.\d+)
```

**Extract MAC address:**
```regex
([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})
```

**Extract word after specific text:**
```regex
Status:\s+(\w+)
```

**Extract number:**
```regex
Memory:\s+(\d+)\s+MB
```

## Variable Scope

- Variables are **device-specific**: Each device maintains its own set of extracted variables
- Variables persist across all tests run on a device in sequence
- Variables do NOT carry over between devices

## Error Handling

- If `extract_pattern` doesn't match the output, the variable is **not set**
- Using an unset variable in a subsequent test will leave the `{variable_name}` placeholder as-is
- The test continues normally with the unsubstituted placeholder (may cause unexpected results)
- **Best practice**: Ensure extraction tests use `match_type: "contains"` to verify the data exists before extracting

## POC Test Workflow

1. **Extract Desktop IPs** from DHCP binding by matching known MAC addresses
2. **Verify DHCP** is active (not static IPs)
3. **Check for ACLs** that deny the extracted IPs
4. **Ping tests** that use the extracted IPs to verify connectivity constraints
   - These tests may FAIL initially (before attendee completes task)
   - After attendee makes changes, re-run to verify task success

## Running the POC

```bash
source .venv/bin/activate
python validator.py config/network1
open network1_report.html
```

The report will show:
- ✅ PASS: DHCP leases extracted and verified
- ✅ PASS: No deny ACLs found
- ❌ FAIL or ⚠ ERROR: Ping tests (expected before task completion)
- ✅ PASS: Ping tests (after attendee completes task)
