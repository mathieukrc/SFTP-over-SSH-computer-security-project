# Quick Start - Security Policy Tests

## Run Tests (Easiest Method)

```powershell
cd tests
python run_security_tests.py
```

## Common Commands

### Run all tests with verbose output
```powershell
python run_security_tests.py -v
```

### Run only DAC tests
```powershell
python run_security_tests.py -k TestDAC -v
```

### Run only MAC tests
```powershell
python run_security_tests.py -k TestMAC -v
```

### Run only RBAC tests
```powershell
python run_security_tests.py -k TestRBAC -v
```

### Run only passing tests (skip known failures)
```powershell
python run_security_tests.py -k "not (execute_bit or write_only or analyst or all_policies_allow or audit_record)"
```

### Run with coverage report
```powershell
python run_security_tests.py --cov=../server --cov-report=term
```

### Run single test
```powershell
python run_security_tests.py -k test_owner_can_read_own_file -v
```

## Current Status

✅ **42 tests passing** - Core security policies working  
❌ **7 tests failing** - Known implementation gaps

Run the tests to see detailed results!

## What's Being Tested

- **DAC**: File ownership and permissions (rwx modes)
- **MAC**: Security clearance levels (public → internal → confidential → secret)
- **RBAC**: Role-based access (admin, analyst, developer, guest)
- **Composite**: All three policies combined correctly
- **Audit**: Security decisions are logged (partially implemented)
- **Edge Cases**: Error handling, special cases

## Files

- `test_security_policies.py` - 49 automated tests
- `run_security_tests.py` - Test runner (run this)
- `SECURITY_TESTS_README.md` - Full documentation
- `TEST_SUMMARY.md` - Results and analysis
- `requirements.txt` - Test dependencies

## Need Help?

See `SECURITY_TESTS_README.md` for detailed documentation.
