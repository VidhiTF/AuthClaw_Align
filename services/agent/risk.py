from policy import get_policy

def calculate_risk(query: str) -> str:
    """
    Calculates the risk level (HIGH, MEDIUM, or LOW) for a query dynamically
    based on keywords loaded from the active policy configuration.
    """
    query = query.lower()
    policy = get_policy()

    high_risk_keywords = policy.get("high_risk_keywords", [])
    medium_risk_keywords = policy.get("medium_risk_keywords", [])

    for word in high_risk_keywords:
        if word in query:
            return "HIGH"

    for word in medium_risk_keywords:
        if word in query:
            return "MEDIUM"

    return "LOW"