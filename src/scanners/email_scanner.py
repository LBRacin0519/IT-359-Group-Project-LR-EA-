import re


def scan_email(content):
    """Check pasted email text using basic, explainable rules."""
    content = content.strip()

    if not content:
        return {
            "score": 0,
            "risk": "Invalid",
            "findings": ["No email content provided."],
        }

    findings = []
    score = 0

    # Each group contributes points only once, even with repeated matches.
    rules = [
        (
            r"\b(urgent|immediately|act now|within 24 hours)\b",
            15,
            "Urgency language may pressure the recipient to act quickly.",
        ),
        (
            r"\b(verify your account|confirm your password|"
            r"enter your password|send your password)\b",
            25,
            "The message requests account verification or password action.",
        ),
        (
            r"\b(account suspended|account will be closed|"
            r"account will be locked)\b",
            20,
            "The message threatens loss of account access.",
        ),
        (
            r"\b(gift cards?|wire transfer|send bitcoin)\b",
            20,
            "The message mentions payment methods often used in scams.",
        ),
        (
            r"\b(you have won|claim your prize|lottery winner)\b",
            20,
            "The message uses prize or lottery language.",
        ),
    ]

    for pattern, points, explanation in rules:
        if re.search(pattern, content, flags=re.IGNORECASE):
            score += points
            findings.append(explanation)

    score = min(score, 100)

    if score >= 75:
        risk = "Critical"
    elif score >= 50:
        risk = "High"
    elif score >= 25:
        risk = "Medium"
    else:
        risk = "Low"

    if not findings:
        findings.append("No indicators matched the current text rules.")

    return {
        "score": score,
        "risk": risk,
        "findings": findings,
    }