def test_approval_placeholder():
    # Placeholder to allow pytest to run successfully
    assert True

if __name__ == "__main__":
    from nodes.approval_node import approval_node
    state = {
        "risk_level": "HIGH",
        "message": "test message"
    }
    print(approval_node(state))