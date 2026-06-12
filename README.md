# ForensicVault API Test Suite

Automated test suite for the ForensicVault API using pytest.
Tests run against the live GCP Cloud Run deployment.

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements-test.txt
```

## Run all tests

```bash
pytest tests/ -v
```

## Run a specific class

```bash
pytest tests/test_api.py::TestAuth -v
pytest tests/test_api.py::TestCases -v
pytest tests/test_api.py::TestSamples -v
pytest tests/test_api.py::TestAuditLog -v
```

## Test coverage

| Class | Tests | What it covers |
|---|---|---|
| TestHealth | 2 | API live check, version field |
| TestAuth | 7 | Register, login, duplicate user, wrong password, JWT protection |
| TestCases | 5 | CRUD, encryption verification, 404 handling |
| TestSamples | 3 | Sample creation, SHA-256 integrity hash, listing |
| TestAuditLog | 4 | Log structure, required fields, auth protection |

## Why this matters

Every test runs against a live HIPAA-compliant API. The test suite validates:
- AES-256-GCM encryption is transparent on read
- SHA-256 integrity hashes are 64 hex characters (correct format)
- Every protected endpoint rejects unauthenticated requests
- Audit log contains all required chain-of-custody fields
