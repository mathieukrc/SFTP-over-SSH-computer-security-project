# Security Policy Tests

Comprehensive automated test suite for DAC, MAC, RBAC, composite policies, and audit logging.

## Overview

This test suite validates the security mechanisms of the SFTP server:

- **DAC (Discretionary Access Control)**: Owner/group/other permissions
- **MAC (Mandatory Access Control)**: Clearance-based access (public/internal/confidential/secret)
- **RBAC (Role-Based Access Control)**: Role permissions (admin, analyst, developer, etc.)
- **Composite Policies**: Combined evaluation of all three mechanisms
- **Audit Logging**: Verification that security decisions are logged

## Test Coverage

### DAC Tests (10 tests)
- ✓ Owner read/write permissions
- ✓ Non-owner access denial
- ✓ Group member permissions
- ✓ Directory execute bit effects on ls/stat
- ✓ Write-only and read-only directory modes
- ✓ Mode 000 denying all access

### MAC Tests (8 tests)
- ✓ Clearance hierarchy (public < internal < confidential < secret)
- ✓ Read-up allowed (lower clearance cannot read higher)
- ✓ Write-down prevention (higher clearance cannot write to lower)
- ✓ Internal clearance accessing public and internal
- ✓ Public clearance limited to public only

### RBAC Tests (9 tests)
- ✓ Role permissions (analyst, admin, developer, guest)
- ✓ Adding roles enables access
- ✓ Deny overrides (explicit deny blocks role permissions)
- ✓ Allow overrides (explicit allow grants extra permissions)
- ✓ Multiple roles combining permissions

### Composite Policy Tests (8 tests)
- ✓ DAC allows + MAC denies = deny
- ✓ MAC allows + DAC denies = deny
- ✓ All allow = allow
- ✓ Path traversal denial
- ✓ Symlink traversal prevention
- ✓ All three policies must allow for access

### Audit Tests (6 tests)
- ✓ Allow decisions logged with correct fields
- ✓ Deny decisions logged with reason
- ✓ Individual policy results included
- ✓ Timestamp and session info
- ✓ Failed auth attempts logged
- ✓ Tamper-evident log design

### Edge Cases Tests (8 tests)
- ✓ Undefined users denied
- ✓ Undefined paths handled
- ✓ Case sensitivity
- ✓ Root path access control
- ✓ Concurrent evaluations consistent
- ✓ Special characters in filenames
- ✓ Very long paths
- ✓ Action parameter validation

**Total: 49 comprehensive security tests**

## Running Tests

### Run all security policy tests:
```powershell
cd tests
pytest test_security_policies.py -v
```

### Run specific test class:
```powershell
# DAC tests only
pytest test_security_policies.py::TestDAC -v

# MAC tests only
pytest test_security_policies.py::TestMAC -v

# RBAC tests only
pytest test_security_policies.py::TestRBAC -v

# Composite tests only
pytest test_security_policies.py::TestCompositePolicies -v

# Audit tests only
pytest test_security_policies.py::TestAuditLogging -v
```

### Run specific test:
```powershell
pytest test_security_policies.py::TestDAC::test_owner_can_read_own_file -v
```

### Run with coverage:
```powershell
pytest test_security_policies.py --cov=../server --cov-report=html --cov-report=term
```

### Run in parallel (faster):
```powershell
pytest test_security_policies.py -n auto
```

### Run with detailed output:
```powershell
pytest test_security_policies.py -v -s
```

## Test Structure

Each test follows this pattern:

```python
def test_name(self):
    """One-line objective describing what is being tested"""
    # Setup (if needed)
    user = "alice"
    resource = "/admin/config.txt"
    action = "read"
    
    # Execute
    result = policy_function(user, resource, action)
    
    # Assert with clear message
    assert result == expected, "Clear explanation of why this should pass"
```

## Test Data

Tests use the existing policy data files in `server/data/`:

- `mac_labels.json` - MAC security levels and user clearances
- `dac_owners.csv` - File ownership and permissions
- `user_roles.json` - User-to-role mappings
- `role_perms.csv` - Role-to-permission mappings

### Test Users

| User | Clearance | Roles | Purpose |
|------|-----------|-------|---------|
| alice | secret | admin, auditor | Full access testing |
| bob | internal | developer, employee | Medium access testing |
| eve | public | guest | Limited access testing |
| charlie | - | analyst | Role-specific testing |

### Security Levels

| Level | Value | Description |
|-------|-------|-------------|
| public | 0 | Lowest - accessible to all |
| internal | 1 | Company internal only |
| confidential | 2 | Restricted - need-to-know |
| secret | 3 | Highest - maximum restriction |

## Understanding Test Results

### Passing Test
```
test_security_policies.py::TestDAC::test_owner_can_read_own_file PASSED [10%]
```
✓ The security policy is working as expected

### Failing Test
```
test_security_policies.py::TestMAC::test_internal_cannot_read_confidential FAILED [20%]
AssertionError: Internal clearance should not access confidential files
```
✗ Security policy is not enforcing the rule correctly - **SECURITY RISK**

## Integration with SFTP Server

To test the actual SFTP server with these policies:

1. Start the server:
```powershell
cd server
python server.py
```

2. Run integration tests (in another terminal):
```powershell
cd tests
pytest test_sftp.py -v
```

## Adding New Tests

To add a new security test:

1. Choose the appropriate test class:
   - `TestDAC` for file permission tests
   - `TestMAC` for clearance-level tests
   - `TestRBAC` for role-based tests
   - `TestCompositePolicies` for multi-policy tests
   - `TestAuditLogging` for audit verification

2. Add test method with clear docstring:
```python
def test_new_security_requirement(self):
    """One-line description of security requirement being tested"""
    # Your test code
    assert result == expected, "Why this should pass"
```

3. Run the test to verify:
```powershell
pytest test_security_policies.py::TestClass::test_new_security_requirement -v
```

## Continuous Integration

Example GitHub Actions workflow:

```yaml
name: Security Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install dependencies
        run: |
          pip install -r tests/requirements.txt
      
      - name: Run security policy tests
        run: |
          cd tests
          pytest test_security_policies.py -v --tb=short
      
      - name: Generate coverage report
        run: |
          pytest test_security_policies.py --cov=server --cov-report=xml
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

## Troubleshooting

### Import errors for policy modules
```
ModuleNotFoundError: No module named 'policy'
```
**Solution**: Tests add `../server` to Python path automatically. Ensure file structure:
```
project/
  server/
    policy.py
    auth.py
  tests/
    test_security_policies.py
```

### Policy data files not found
```
FileNotFoundError: server/data/mac_labels.json
```
**Solution**: Run tests from project root or `tests/` directory. Policy functions expect `server/data/` path.

### All tests fail
```
AssertionError: [Multiple test failures]
```
**Solution**: Check that `server/data/` policy files are properly formatted JSON/CSV and match the expected schema.

### Tests pass but server fails
**Solution**: Unit tests validate policy logic. Integration tests (`test_sftp.py`) are needed to verify server implementation.

## Security Test Checklist

Before deploying, ensure:

- [ ] All DAC tests pass (file permissions enforced)
- [ ] All MAC tests pass (clearance levels enforced)
- [ ] All RBAC tests pass (role permissions enforced)
- [ ] All composite tests pass (policies combine correctly)
- [ ] Audit tests pass (security decisions are logged)
- [ ] No unauthorized access allowed
- [ ] Path traversal attempts are blocked
- [ ] Deny overrides are working
- [ ] Edge cases handled gracefully

## Performance

Tests are fast (unit tests, no I/O):

- Full suite: ~0.5-1 second
- Individual class: ~0.1-0.2 seconds
- Parallel execution: even faster with `-n auto`

## License and Attribution

Part of the SFTP-over-SSH-computer-security-project.
Tests verify security policies for educational and production use.

## Questions or Issues?

If tests reveal security vulnerabilities:
1. **Do not** deploy to production
2. Fix the policy implementation
3. Re-run tests to verify fix
4. Document the issue and resolution

For new security requirements:
1. Add tests first (test-driven security)
2. Implement policy changes
3. Verify all tests pass
4. Review with security team
