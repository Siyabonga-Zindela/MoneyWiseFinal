"""Simple rule-based checks for common scam warning signs."""

from .schemas import (
    AnalysisIndicator,
    IndicatorSeverity,
    RiskCategory,
    ScamAssessment,
    compute_risk_score,
)


RULES = [
    {
        "code": "credential_request",
        "title": "Request for a password or security code",
        "explanation": "The message asks for sensitive account information.",
        "severity": IndicatorSeverity.HIGH,
        "phrases": (
            "send your otp",
            "share your otp",
            "provide your one-time password",
            "share your pin",
            "send your password",
            "give me your verification code",
        ),
    },
    {
        "code": "guaranteed_returns",
        "title": "Guaranteed or unusually high returns",
        "explanation": "The message promises a guaranteed or unusually large return.",
        "severity": IndicatorSeverity.HIGH,
        "phrases": (
            "guaranteed returns",
            "guaranteed profit",
            "risk-free returns",
            "double your money",
            "100% return",
        ),
    },
    {
        "code": "recruitment_earnings",
        "title": "Earnings linked to recruiting people",
        "explanation": "The message links earnings to bringing in new participants.",
        "severity": IndicatorSeverity.HIGH,
        "phrases": (
            "earn by recruiting",
            "recruit new members",
            "recruit others to earn",
            "earnings depend on recruitment",
            "invite people to earn",
        ),
    },
    {
        "code": "urgent_payment",
        "title": "Pressure to pay quickly",
        "explanation": "The message uses urgency to encourage a quick payment or decision.",
        "severity": IndicatorSeverity.MEDIUM,
        "phrases": (
            "pay now",
            "transfer immediately",
            "act now",
            "offer expires today",
            "within 24 hours",
        ),
    },
    {
        "code": "unusual_payment_method",
        "title": "Unusual payment method",
        "explanation": "The message asks for a payment method that can be difficult to reverse.",
        "severity": IndicatorSeverity.MEDIUM,
        "phrases": (
            "pay with gift cards",
            "send payment in gift cards",
            "pay in cryptocurrency",
        ),
    },
]

LIMITATIONS = (
    "This is an automated check of the text provided, not proof of fraud or "
    "a legal finding. A low-risk result does not prove that an offer is safe."
)


def find_indicators(text: str) -> list[AnalysisIndicator]:
    """Return the warning signs whose example phrases appear in the text."""
    lower_text = text.casefold()
    indicators = []

    for rule in RULES:
        for phrase in rule["phrases"]:
            if phrase in lower_text:
                indicators.append(
                    AnalysisIndicator(
                        code=rule["code"],
                        title=rule["title"],
                        explanation=rule["explanation"],
                        evidence=phrase,
                        severity=rule["severity"],
                    )
                )
                break

    return indicators


def analyze_text(text: str) -> ScamAssessment:
    """Create a baseline assessment without calling an external AI service."""
    cleaned_text = text.strip()
    if not cleaned_text:
        return ScamAssessment(
            category=RiskCategory.INCONCLUSIVE,
            risk_score=0.0,
            explanation="There is no text to assess.",
            next_steps=["Paste the message or offer you want to check."],
            limitations=LIMITATIONS,
        )

    indicators = find_indicators(cleaned_text)
    if any(item.severity == IndicatorSeverity.HIGH for item in indicators):
        category = RiskCategory.HIGH
        explanation = (
            "The text includes one or more strong warning signs. Pause and "
            "verify the message before sharing information or sending money."
        )
        next_steps = [
            "Do not send money or share passwords, PINs, or one-time codes.",
            "Verify the person or provider using contact details from an official source.",
        ]
    elif indicators:
        category = RiskCategory.MEDIUM
        explanation = (
            "The text includes warning signs that deserve a closer check "
            "before you respond or pay."
        )
        next_steps = [
            "Pause before responding or sending money.",
            "Check the offer and recipient using a separate, trusted source.",
        ]
    else:
        category = RiskCategory.LOW
        explanation = (
            "These checks did not find the warning signs they look for. "
            "That does not confirm the message or offer is safe."
        )
        next_steps = [
            "Check who sent the message and verify any payment details independently.",
        ]

    return ScamAssessment(
        category=category,
        risk_score=compute_risk_score(category, indicators),
        indicators=indicators,
        explanation=explanation,
        next_steps=next_steps,
        limitations=LIMITATIONS,
    )
