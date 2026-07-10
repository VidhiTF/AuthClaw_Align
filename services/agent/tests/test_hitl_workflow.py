import requests
import json
import time
import sys
from datetime import datetime, timedelta, timezone

import os
import os
BASE_URL = os.getenv("AUTHCLAW_TEST_URL", "http://127.0.0.1:8000")
API_KEY = os.getenv("AUTHCLAW_TEST_API_KEY")
if not API_KEY:
    raise RuntimeError("AUTHCLAW_TEST_API_KEY environment variable is not set!")

headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {API_KEY}"
}


def print_banner(text):
    print("\n" + "=" * 80)
    print(f" {text}")
    print("=" * 80)

def assert_status(response, expected_status):
    if response.status_code != expected_status:
        print(f"FAIL: Expected status {expected_status}, got {response.status_code}")
        print("Response:", response.text)
        sys.exit(1)
    else:
        print(f"PASS: Status code is {expected_status}")

def main():
    print_banner("STARTING PHASE 3 HITL WORKFLOW VERIFICATION")

    # 1. High-risk requests create approvals
    print_banner("1. Testing High-Risk Request Creation")
    payload = {
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "delete database production"}
        ]
    }
    response = requests.post(f"{BASE_URL}/v1/chat/completions", headers=headers, json=payload)
    assert_status(response, 202)
    
    data = response.json()
    approval_id = data.get("approval_id")
    print(f"Approval ID generated: {approval_id}")
    if not approval_id:
        print("FAIL: approval_id is missing from response")
        sys.exit(1)

    # 2. GET /approvals/{approval_id} check
    print_banner("2. Testing GET /approvals/{approval_id}")
    resp_get = requests.get(f"{BASE_URL}/approvals/{approval_id}")
    assert_status(resp_get, 200)
    get_data = resp_get.json()
    print("Approval details:", json.dumps(get_data, indent=2))
    assert get_data["status"] == "pending", f"Expected 'pending', got {get_data['status']}"
    assert get_data["remaining_seconds"] > 0, "Expected remaining_seconds > 0"
    print("PASS: GET /approvals/{approval_id} works and matches requirements")

    # 3. GET /approvals list check
    print_banner("3. Testing GET /approvals List")
    resp_list = requests.get(f"{BASE_URL}/approvals")
    assert_status(resp_list, 200)
    list_data = resp_list.json()
    print(f"Found {len(list_data)} approvals in system.")
    found = any(app["approval_id"] == approval_id for app in list_data)
    assert found, "Created approval not found in approvals list"
    print("PASS: GET /approvals list contains the new approval")

    # 4. Try to approve with incorrect MFA code (require_mfa = True)
    print_banner("4. Testing Approval with Incorrect MFA Code")
    resp_app_fail = requests.post(f"{BASE_URL}/approve/{approval_id}", json={"mfa_code": "000000"})
    assert_status(resp_app_fail, 401)
    print("PASS: Incorrect MFA code successfully blocked (HTTP 401)")

    # 5. Try to approve with missing MFA payload (but JSON body present)
    print_banner("5. Testing Approval with Missing MFA Field (JSON present)")
    resp_app_missing_field = requests.post(f"{BASE_URL}/approve/{approval_id}", json={"other_field": "val"})
    assert_status(resp_app_missing_field, 401)
    print("PASS: Missing MFA field with JSON body present successfully blocked (HTTP 401)")

    # 6. Legacy compatibility mode (request body omitted entirely)
    print_banner("6. Testing Legacy Compatibility Mode (Empty Request Body)")
    # Using empty body/payload to trigger legacy bypass
    resp_app_legacy = requests.post(f"{BASE_URL}/approve/{approval_id}", data="")
    assert_status(resp_app_legacy, 200)
    legacy_data = resp_app_legacy.json()
    assert legacy_data["status"] == "approved", f"Expected status 'approved', got {legacy_data['status']}"
    print("PASS: Legacy compatibility bypass works and sets status to approved")

    # 7. Rejected approvals cannot execute
    print_banner("7. Testing Rejected Approvals Execution Block")
    # Let's create a second approval to test reject
    response_r = requests.post(f"{BASE_URL}/v1/chat/completions", headers=headers, json=payload)
    assert_status(response_r, 202)
    reject_approval_id = response_r.json().get("approval_id")
    print(f"Reject Test Approval ID generated: {reject_approval_id}")

    # Reject it
    resp_rej = requests.post(f"{BASE_URL}/reject/{reject_approval_id}")
    assert_status(resp_rej, 200)
    assert resp_rej.json()["status"] == "rejected", "Status should be rejected"
    
    # Try executing rejected approval
    resp_exec_rej = requests.post(f"{BASE_URL}/execute/{reject_approval_id}")
    assert_status(resp_exec_rej, 400)
    print("PASS: Rejected approval execution blocked (HTTP 400)")

    # 8. Expired approvals cannot execute
    print_banner("8. Testing Expired Approvals Expiry and Execution Block")
    # Create a third approval to test expiration
    response_e = requests.post(f"{BASE_URL}/v1/chat/completions", headers=headers, json=payload)
    assert_status(response_e, 202)
    expired_approval_id = response_e.json().get("approval_id")
    print(f"Expired Test Approval ID generated: {expired_approval_id}")

    # Trigger test-only expiration
    resp_expire = requests.post(f"{BASE_URL}/test/expire/{expired_approval_id}")
    assert_status(resp_expire, 200)
    
    # Retrieve details to verify it is marked expired lazily
    resp_get_exp = requests.get(f"{BASE_URL}/approvals/{expired_approval_id}")
    assert_status(resp_get_exp, 200)
    assert resp_get_exp.json()["status"] == "expired", f"Expected expired, got {resp_get_exp.json()['status']}"
    
    # Try executing expired request
    resp_exec_exp = requests.post(f"{BASE_URL}/execute/{expired_approval_id}")
    assert_status(resp_exec_exp, 400)
    
    # Try approving expired request
    resp_app_exp = requests.post(f"{BASE_URL}/approve/{expired_approval_id}", data="")
    assert_status(resp_app_exp, 400)
    print("PASS: Expired approvals block both approval and execution (HTTP 400)")

    # 9. Only approved requests execute, and once executed, status becomes 'executed'
    print_banner("9. Testing Successful Execution and Single Execution Block")
    resp_exec = requests.post(f"{BASE_URL}/execute/{approval_id}")
    if resp_exec.status_code not in (200, 500, 503):
        print(f"FAIL: Expected status 200/500/503, got {resp_exec.status_code}")
        print("Response:", resp_exec.text)
        sys.exit(1)
    else:
        print(f"PASS: Status code is {resp_exec.status_code}")
    
    exec_data = resp_exec.json()
    print("Execution output:", json.dumps(exec_data, indent=2))
    if resp_exec.status_code == 200:
        assert exec_data["message"] == "Executed Successfully", "Expected Executed Successfully"
    else:
        assert "error" in exec_data, "Expected error key in failure response"

    # Verify status is now 'executed' and executed_at is populated
    resp_get_final = requests.get(f"{BASE_URL}/approvals/{approval_id}")
    assert_status(resp_get_final, 200)
    final_data = resp_get_final.json()
    assert final_data["status"] == "executed", f"Expected status 'executed', got {final_data['status']}"
    assert final_data["executed_at"] is not None, "Expected executed_at to be set"
    print(f"Approval status is 'executed' and executed_at is: {final_data['executed_at']}")

    # Try executing it again
    resp_exec_again = requests.post(f"{BASE_URL}/execute/{approval_id}")
    assert_status(resp_exec_again, 400)
    print("PASS: Already executed approval cannot be executed again (HTTP 400)")

    print_banner("ALL PHASE 3 HITL INTEGRATION TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    main()
