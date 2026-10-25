"""Deterministic rule checks for common scam warning signs.

Every rule fires only on an exact phrase found in the submitted text, and
carries its own evidence trail:

- ``evidence``  - the exact matched phrase;
- ``context``   - the matched phrase with surrounding words, quoted from the
  original message, so the user can see where it appears;
- ``explanation`` - why this specific detail matters, what it is commonly
  associated with, and (where relevant) when the same detail can also appear
  in legitimate messages. Explanations never claim proof of fraud.

The checks are deliberately conservative: a single MEDIUM indicator is a
reason to verify, not a verdict. Categories: any HIGH indicator => HIGH,
else any MEDIUM => MEDIUM, else LOW (nothing known was found - which is NOT
a safety certificate; see LIMITATIONS).
"""

import re

from .schemas import (
    AnalysisIndicator,
    IndicatorSeverity,
    RiskCategory,
    ScamAssessment,
    compute_risk_score,
)

# Money tokens such as R1000, R 4 500, R250.00 (matched case-insensitively).
# The grouped form requires at least one " 500" group; plain digits otherwise.
_MONEY_RE = re.compile(
    r"\br\s?(\d{1,3}(?:[ ,]\d{3})+(?:\.\d{1,2})?|\d+(?:\.\d{1,2})?)", re.IGNORECASE
)

# A phrase occurrence immediately preceded by one of these is advice NOT to
# do something ("Do not share your OTP"), not a request - never fire on it.
_NEGATIONS = ("do not", "don't", "don\u2019t", "don`", "dont", "never", "no need to", "no investment is", "nothing is")

# The largest amount only counts as a "promised payout" when the text links
# it to receiving something ("get R5000 back", "return of R5000"). Without
# this, itemised prices ("goods R1500, delivery R120") would false-positive.
_GAIN_WORDS = (
    "get", "receive", "win", "return", "payout", "paid to you", "back",
    "profit", "earn", "bonus", "prize", "claim", "yours",
)


RULES = [
    {
        "code": "credential_request",
        "title": "Request for a password, PIN or one-time code",
        "explanation": (
            "The message asks for sensitive account information. No bank or "
            "legitimate company ever needs your PIN, password or one-time PIN - "
            "not by phone, SMS, email or WhatsApp. Anyone who receives yours can "
            "take money from your account or take over your profile."
        ),
        "severity": IndicatorSeverity.HIGH,
        "phrases": (
            "send your otp",
            "share your otp",
            "send your pin",
            "share your pin",
            "provide your one-time password",
            "give me your verification code",
            "send your password",
            "send me the code they sent you",
        ),
    },
    {
        "code": "upfront_fee",
        "title": "Upfront fee to release money or a prize",
        "explanation": (
            "The message asks for a payment before you receive money, a prize or "
            "a loan. This 'pay first to receive later' pattern is known as "
            "advance-fee fraud: once you pay, the promised money never arrives "
            "and new 'fees' keep appearing. Legitimate lotteries deduct costs "
            "from the prize, and reputable lenders disclose and deduct fees from "
            "the loan amount - they do not ask you to pay first."
        ),
        "severity": IndicatorSeverity.HIGH,
        "phrases": (
            "release fee",
            "clearance fee",
            "activation fee",
            "processing fee",
            "administration fee",
            "pay the courier",
            "courier fee",
            "pay the tax on your winnings",
            "transfer fee first",
            "deposit to release",
        ),
    },
    {
        "code": "guaranteed_returns",
        "title": "Guaranteed or unusually high returns",
        "explanation": (
            "The message promises a guaranteed or unusually large return. Every "
            "real investment carries risk and returns are never guaranteed; "
            "'guaranteed' high returns are a hallmark of Ponzi and pyramid "
            "schemes. Legitimate licensed providers are not allowed to promise "
            "them."
        ),
        "severity": IndicatorSeverity.HIGH,
        "phrases": (
            "guaranteed returns",
            "guaranteed profit",
            "guaranteed income",
            "guaranteed monthly returns",
            "risk-free returns",
            "risk free investment",
            "completely risk free",
            "totally risk free",
            "absolutely risk free",
            "100% risk free",
            "risk free profits",
            "no risk at all",
            "double your money",
            "100% return",
            "you cannot lose",
            "can't lose",
            "daily returns",
            "daily profit",
            "per day return",
            "monthly returns",
            "monthly profit",
            "weekly returns",
        ),
    },
    {
        "code": "recruitment_earnings",
        "title": "Earnings linked to recruiting people",
        "explanation": (
            "The message ties a bonus or extra earnings to bringing in new "
            "participants. When income depends mainly on recruiting rather "
            "than selling a real product, the structure is that of a pyramid "
            "scheme: most participants - usually the last to join - lose their "
            "money. The recruitment link below comes from the message itself; "
            "what the scheme actually pays out cannot be confirmed."
        ),
        "severity": IndicatorSeverity.HIGH,
        "phrases": (
            "earn by recruiting",
            "recruit new members",
            "recruit others to earn",
            "earnings depend on recruitment",
            "invite people to earn",
            "get paid for inviting",
            "bonus for every person you",
            "earn from referrals",
            # Generic invitation wording only counts when the text also talks
            # about money or rewards (checked via requires_any below).
            "if you invite",
            "when you invite",
            "for every person you invite",
            "for everyone you invite",
        ),
        "requires_any": (
            "bonus", "extra", "earn", "get paid", "commission", "reward", "cash"
        ),
    },
    {
        "code": "prize_claim",
        "title": "You apparently won a prize or draw",
        "explanation": (
            "The message says you have won or been selected for a prize. You "
            "cannot win a draw you never entered, and real promoters never "
            "require you to pay or share personal details to receive a prize. "
            "Combined with any request for money or details, this is a classic "
            "prize-claim scam pattern."
        ),
        "severity": IndicatorSeverity.HIGH,
        "phrases": (
            "you have won",
            "you've won",
            "you are a winner",
            "you've been selected",
            "you have been selected",
            "claim your prize",
            "claim your winnings",
            "lucky draw winner",
            "your number was selected",
            "congratulations you are our",
        ),
    },
    {
        "code": "account_verification_request",
        "title": "Urgent request to verify or update account details",
        "explanation": (
            "The message pressures you to verify, confirm or update account or "
            "banking details. Real banks and companies do not collect account "
            "details through links in messages. The same wording also appears in "
            "genuine notices, so check it against the sender's official app or "
            "the number on your card before doing anything."
        ),
        "severity": IndicatorSeverity.MEDIUM,
        "phrases": (
            "verify your account",
            "confirm your banking details",
            "update your banking details",
            "verify your banking details",
            "your account has been limited",
            "your account has been locked",
            "unusual activity on your account",
            "we detected unusual activity",
            "click here to verify",
            "click the link below to verify",
        ),
    },
    {
        "code": "urgent_payment",
        "title": "Pressure to pay or act quickly",
        "explanation": (
            "The message uses urgency to push a quick payment or decision. "
            "Urgency is a pressure tactic because it stops you from verifying or "
            "asking advice. Legitimate businesses also send time-limited offers, "
            "so urgency alone is not proof of a scam - but it is a reason to "
            "slow down and check before paying."
        ),
        "severity": IndicatorSeverity.MEDIUM,
        "phrases": (
            "pay now",
            "transfer immediately",
            "act now",
            "act fast",
            "offer expires today",
            "expires today",
            "last chance",
            "within 24 hours",
            "within 10 minutes",
            "within 1 hour",
            "limited spots",
            "only today",
        ),
    },
    {
        "code": "unusual_payment_method",
        "title": "Hard-to-reverse payment method",
        "explanation": (
            "The message asks for a payment method such as gift cards, "
            "cryptocurrency or cash transfers. These are favourites of scammers "
            "because the money is difficult or impossible to recover once sent. "
            "Traceable payment channels give you some protection; these do not."
        ),
        "severity": IndicatorSeverity.MEDIUM,
        "phrases": (
            "gift card",
            "gift cards",
            "pay in cryptocurrency",
            "bitcoin",
            "usdt",
            "western union",
            "moneygram",
            "send cash to",
        ),
    },
    {
        "code": "suspicious_link",
        "title": "Link shortener or generic call-to-click",
        "explanation": (
            "The message contains a shortened link or a vague 'click here' "
            "instruction. Shortened links hide the real destination, and fake "
            "login or prize pages are common scam tools. The link itself is not "
            "proof of a scam - check whether the real destination belongs to the "
            "organisation it claims to be, and never sign in through a link you "
            "received unexpectedly."
        ),
        "severity": IndicatorSeverity.MEDIUM,
        "phrases": (
            "bit.ly",
            "tinyurl",
            "cutt.ly",
            "shorturl",
            "t.me/",
            "click here to claim",
            "click the link below",
            "follow this link to claim",
        ),
    },
]

LIMITATIONS = (
    "This is an automated check of the text you submitted, based on known "
    "warning-sign patterns - it is not proof of fraud or a legal finding. It "
    "cannot see who really sent the message, whether a company or website "
    "genuinely exists, or what happens after you respond. A low-risk result "
    "does not prove an offer is safe: new scams exist that no check can "
    "recognise, and legitimate messages can contain urgency or links."
)

VERIFICATION = {
    RiskCategory.HIGH: (
        "Do not use any contact details from the message. If it claims to come "
        "from your bank, call the number printed on your card or statement. If "
        "it names a company, find that company's official website yourself and "
        "contact them there. For investments, search the provider in the FSCA "
        "database at fsca.co.za - unlicensed financial providers are operating "
        "illegally. You can also report suspected fraud to the Southern African "
        "Fraud Prevention Service (SAFPS)."
    ),
    RiskCategory.MEDIUM: (
        "Verify before you respond: contact the organisation using details from "
        "their official website, app or your card - never the details in the "
        "message. For investment providers, check whether they are licensed in "
        "the FSCA database at fsca.co.za. Search the sender's name or number "
        "together with the word 'scam' to see other people's experiences."
    ),
    RiskCategory.LOW: (
        "Even with no warning signs found, verify independently: check "
        "investment providers in the FSCA database at fsca.co.za, look up the "
        "company's official contact details yourself, and never pay before you "
        "have confirmed who you are paying."
    ),
    RiskCategory.INCONCLUSIVE: (
        "There is not enough text to judge. If you have more of the message, "
        "check it too, and verify the sender through official channels such as "
        "your bank's app or the company's official website."
    ),
}


def _context_quote(text: str, start: int, end: int, window: int = 45) -> str:
    """Cut `text` around [start:end) with `window` chars of context either side."""
    lo = max(0, start - window)
    hi = min(len(text), end + window)
    quote = " ".join(text[lo:hi].split())
    prefix = "\u2026 " if lo > 0 else ""
    suffix = " \u2026" if hi < len(text) else ""
    return f"{prefix}{quote}{suffix}"


def _parse_amounts(text: str) -> list[tuple[str, float, int]]:
    """Return (display, value, start_index) for every money token in the text."""
    found = []
    for match in _MONEY_RE.finditer(text):
        digits = match.group(1).replace(" ", "").replace(",", "")
        try:
            value = float(digits)
        except ValueError:
            continue
        if value > 0:
            found.append((match.group(0).strip(), value, match.start()))
    return found


def _payout_multiplier_indicator(text: str) -> AnalysisIndicator | None:
    """Detect 'invest R1000, receive R5000' payout multiples.

    Fires only when the text references at least two different positive rand
    amounts and the largest is at least 3x the smallest. At 3x-5x this is a
    MEDIUM warning (could still be a generous marketing bundle); at 5x or
    more it is the classic Ponzi/pyramid pitch and counts as a HIGH sign.
    The amounts quoted as evidence come straight from the message.
    """
    amounts = _parse_amounts(text)
    if len(amounts) < 2:
        return None

    smallest = min(amounts, key=lambda a: a[1])
    largest = max(amounts, key=lambda a: a[1])
    if smallest[1] == largest[1]:
        return None

    # The big amount must sit in a gain context ("... get R5000 back"),
    # otherwise it is just another price and there is no promised payout.
    around_largest = text.casefold()[max(0, largest[2] - 40): largest[2] + len(largest[0]) + 15]
    if not any(word in around_largest for word in _GAIN_WORDS):
        return None

    multiple = largest[1] / smallest[1]
    if multiple < 3:
        return None

    severity = IndicatorSeverity.HIGH if multiple >= 5 else IndicatorSeverity.MEDIUM
    lo, hi = sorted((smallest[2], largest[2] + len(largest[0])))
    context = _context_quote(text, lo, hi, window=30)

    explanation = (
        f"The message mentions {smallest[0]} and {largest[0]} - a payout of "
        f"about {round(multiple)} times the amount asked for. No licensed "
        "investment produces multiples like this; returns several times the "
        "money paid in are the classic structure of Ponzi and pyramid pitches. "
        "The two figures come from the message itself; whether anything would "
        "actually be paid out cannot be confirmed by this check."
    )
    return AnalysisIndicator(
        code="payout_multiplier",
        title="Payout promised is a multiple of the money asked for",
        explanation=explanation,
        evidence=f"{smallest[0]} / {largest[0]}",
        context=context,
        severity=severity,
    )


def _negated(lower_text: str, index: int, window: int = 25) -> bool:
    """True when the text just before `index` negates the matched phrase."""
    start = max(0, index - window)
    preceding = lower_text[start:index]
    return any(word in preceding for word in _NEGATIONS)


def _find_unnegated(lower_text: str, phrase: str) -> int | None:
    """First index of `phrase` that is not preceded by a negation, if any."""
    index = lower_text.find(phrase)
    while index != -1:
        if not _negated(lower_text, index):
            return index
        index = lower_text.find(phrase, index + 1)
    return None


def find_indicators(text: str) -> list[AnalysisIndicator]:
    """Return the warning signs whose example phrases appear in the text."""
    lower_text = text.casefold()
    indicators = []
    seen_codes = set()

    for rule in RULES:
        required = rule.get("requires_any")
        if required and not any(word in lower_text for word in required):
            continue
        for phrase in rule["phrases"]:
            index = _find_unnegated(lower_text, phrase)
            if index is None:
                continue
            indicators.append(
                AnalysisIndicator(
                    code=rule["code"],
                    title=rule["title"],
                    explanation=rule["explanation"],
                    evidence=phrase,
                    context=_context_quote(text, index, index + len(phrase)),
                    severity=rule["severity"],
                )
            )
            seen_codes.add(rule["code"])
            break

    multiplier = _payout_multiplier_indicator(text)
    if multiplier is not None:
        indicators.append(multiplier)

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
            verification=VERIFICATION[RiskCategory.INCONCLUSIVE],
        )

    indicators = find_indicators(cleaned_text)
    if any(item.severity == IndicatorSeverity.HIGH for item in indicators):
        category = RiskCategory.HIGH
        explanation = (
            "The text contains warning signs strongly associated with "
            "financial scams. Each sign is listed below with the exact words "
            "from your message that triggered it. Treat the offer as unsafe "
            "until you have verified it through official channels."
        )
        next_steps = [
            "Do not send money or share passwords, PINs, or one-time codes.",
            "Do not use contact details from the message; reach the organisation through its official channels.",
            "Keep the message in case you need it for a report to your bank or the police.",
        ]
    elif indicators:
        category = RiskCategory.MEDIUM
        explanation = (
            "The text includes warning signs that deserve a closer check "
            "before you respond or pay. Each one is listed below with the "
            "exact words from your message that triggered it, together with "
            "what it can - and cannot - tell you."
        )
        next_steps = [
            "Pause before responding or sending money.",
            "Check the offer and recipient using a separate, trusted source.",
            "If pressure to pay continues, stop responding and report the sender.",
        ]
    else:
        category = RiskCategory.LOW
        explanation = (
            "The checks found none of the warning-sign patterns they look "
            "for. That does not confirm the message or offer is safe - it "
            "means this specific check has no evidence of a scam. Verify the "
            "sender through official channels before sending money."
        )
        next_steps = [
            "Check who sent the message and verify any payment details independently.",
            "If anything still feels wrong, do not pay - trust the official source, not the message.",
        ]

    return ScamAssessment(
        category=category,
        risk_score=compute_risk_score(category, indicators),
        indicators=indicators,
        explanation=explanation,
        next_steps=next_steps,
        limitations=LIMITATIONS,
        verification=VERIFICATION[category],
    )
