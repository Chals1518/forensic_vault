"""
ForensicVault API Test Suite
Run: pytest tests/ -v
"""
import pytest
import requests
import uuid
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE_URL = "https://forensicvault-api-574234818408.europe-west2.run.app"
TEST_USER = "pytest_runner"
TEST_PASS = "TestPassword123!"

def make_session():
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=2, status_forcelist=[502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    return session

SESSION = make_session()

@pytest.fixture(scope="session")
def auth_token():
    SESSION.post(f"{BASE_URL}/auth/register", json={"username": TEST_USER, "password": TEST_PASS})
    r = SESSION.post(f"{BASE_URL}/auth/login", json={"username": TEST_USER, "password": TEST_PASS})
    assert r.status_code == 200, f"Login failed: {r.text}"
    token = r.json().get("access_token")
    assert token is not None
    return token

@pytest.fixture(scope="session")
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}

@pytest.fixture(scope="session")
def case_id(auth_headers):
    payload = {"title": "Pytest Test Case", "victim_name": "Test Victim", "location": "Liverpool, UK", "notes": "Automated test case", "status": "open"}
    r = SESSION.post(f"{BASE_URL}/cases", headers=auth_headers, json=payload)
    assert r.status_code == 201, f"Case creation failed: {r.text}"
    cid = r.json().get("case_id")
    assert cid is not None
    return cid

class TestHealth:
    def test_root_returns_200(self):
        r = SESSION.get(f"{BASE_URL}/")
        assert r.status_code == 200

    def test_root_has_content(self):
        r = SESSION.get(f"{BASE_URL}/")
        assert len(r.json()) > 0

class TestAuth:
    def test_register_new_user(self):
        unique = f"user_{uuid.uuid4().hex[:8]}"
        r = SESSION.post(f"{BASE_URL}/auth/register", json={"username": unique, "password": "SecurePass123!"})
        assert r.status_code == 201

    def test_register_duplicate_user_fails(self):
        unique = f"dup_{uuid.uuid4().hex[:8]}"
        SESSION.post(f"{BASE_URL}/auth/register", json={"username": unique, "password": "Pass123!"})
        r = SESSION.post(f"{BASE_URL}/auth/register", json={"username": unique, "password": "Pass123!"})
        assert r.status_code in [400, 409]

    def test_login_valid_credentials(self):
        r = SESSION.post(f"{BASE_URL}/auth/login", json={"username": TEST_USER, "password": TEST_PASS})
        assert r.status_code == 200
        assert "access_token" in r.json()

    def test_login_wrong_password(self):
        r = SESSION.post(f"{BASE_URL}/auth/login", json={"username": TEST_USER, "password": "WrongPassword!"})
        assert r.status_code == 401

    def test_login_nonexistent_user(self):
        r = SESSION.post(f"{BASE_URL}/auth/login", json={"username": "nobody_xyz_123", "password": "irrelevant"})
        assert r.status_code in [401, 404]

    def test_protected_route_without_token(self):
        r = SESSION.get(f"{BASE_URL}/cases")
        assert r.status_code in [401, 403]

    def test_protected_route_with_invalid_token(self):
        r = SESSION.get(f"{BASE_URL}/cases", headers={"Authorization": "Bearer invalidtoken123"})
        assert r.status_code in [401, 403]

class TestCases:
    def test_create_case(self, auth_headers):
        payload = {"title": "Unit Test Case", "victim_name": "Test Victim", "location": "Liverpool, UK", "notes": "Created by automated test", "status": "open"}
        r = SESSION.post(f"{BASE_URL}/cases", headers=auth_headers, json=payload)
        assert r.status_code == 201, f"Failed: {r.text}"
        assert "case_id" in r.json()

    def test_list_cases(self, auth_headers):
        r = SESSION.get(f"{BASE_URL}/cases", headers=auth_headers)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_get_single_case(self, auth_headers, case_id):
        r = SESSION.get(f"{BASE_URL}/cases/{case_id}", headers=auth_headers)
        assert r.status_code == 200
        assert r.json().get("case_id") == case_id

    def test_get_nonexistent_case(self, auth_headers):
        r = SESSION.get(f"{BASE_URL}/cases/{uuid.uuid4()}", headers=auth_headers)
        assert r.status_code == 404

    def test_case_data_is_decrypted_on_read(self, auth_headers, case_id):
        r = SESSION.get(f"{BASE_URL}/cases/{case_id}", headers=auth_headers)
        assert r.status_code == 200
        assert len(r.json().get("title", "")) > 0

class TestSamples:
    def test_add_fingerprint_sample(self, auth_headers, case_id):
        payload = {"collection_method": "gel lift", "decomposition_stage": "fresh", "instrument": "sfPESI-MS", "collection_notes": "Pytest test sample", "pmi_estimate_hours": 12.5, "temperature_celsius": 18.0}
        r = SESSION.post(f"{BASE_URL}/cases/{case_id}/samples", headers=auth_headers, json=payload)
        assert r.status_code == 201, f"Failed: {r.text}"
        assert "sample_id" in r.json()

    def test_sample_has_integrity_hash(self, auth_headers, case_id):
        payload = {"collection_method": "direct", "decomposition_stage": "early", "instrument": "DESI-MS", "collection_notes": "Hash test sample", "pmi_estimate_hours": 6.0, "temperature_celsius": 20.0}
        r = SESSION.post(f"{BASE_URL}/cases/{case_id}/samples", headers=auth_headers, json=payload)
        assert r.status_code == 201, f"Failed: {r.text}"
        data = r.json()
        assert "integrity_hash" in data
        assert len(data["integrity_hash"]) == 64

    def test_list_samples_for_case(self, auth_headers, case_id):
        r = SESSION.get(f"{BASE_URL}/cases/{case_id}/samples", headers=auth_headers)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

class TestAuditLog:
    def test_audit_log_returns_200(self, auth_headers):
        r = SESSION.get(f"{BASE_URL}/audit", headers=auth_headers)
        assert r.status_code == 200

    def test_audit_log_is_list(self, auth_headers):
        r = SESSION.get(f"{BASE_URL}/audit", headers=auth_headers)
        assert isinstance(r.json(), list)

    def test_audit_entry_has_required_fields(self, auth_headers):
        r = SESSION.get(f"{BASE_URL}/audit", headers=auth_headers)
        entries = r.json()
        assert len(entries) > 0
        entry = entries[0]
        for field in ["log_id", "user", "action", "resource", "timestamp"]:
            assert field in entry, f"Missing field: {field}"

    def test_audit_log_without_token(self):
        r = SESSION.get(f"{BASE_URL}/audit")
        assert r.status_code in [401, 403]
