"""PII and secret detection.

Detectors are validated, not just pattern-matched, to keep false positives
down on numeric data: card numbers must pass Luhn, Aadhaar numbers must pass
Verhoeff, IBANs must pass mod-97. Every match is returned redacted so raw
PII never ends up in alerts, logs or evidence.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------- checksums


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_ok(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def iban_ok(iban: str) -> bool:
    s = iban.replace(" ", "").upper()
    if len(s) < 15 or len(s) > 34:
        return False
    s = s[4:] + s[:4]
    num = "".join(str(int(ch, 36)) for ch in s)
    return int(num) % 97 == 1


# ---------------------------------------------------------------- detectors


@dataclass
class PIIMatch:
    kind: str
    count: int
    samples: list[str] = field(default_factory=list)   # redacted

    def to_dict(self) -> dict:
        return {"kind": self.kind, "count": self.count, "samples": self.samples}


@dataclass
class PIIReport:
    matches: list[PIIMatch] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(m.count for m in self.matches)

    @property
    def kinds(self) -> list[str]:
        return [m.kind for m in self.matches]

    def __bool__(self) -> bool:
        return self.total > 0

    def to_dict(self) -> dict:
        return {"total": self.total, "matches": [m.to_dict() for m in self.matches]}


def redact(value: str, keep: int = 4) -> str:
    v = re.sub(r"\s|-", "", value)
    if len(v) <= keep:
        return "*" * len(v)
    return "*" * (len(v) - keep) + v[-keep:]


_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_AADHAAR = re.compile(r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)")
_PAN = re.compile(r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b")
_SSN = re.compile(r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_IN = re.compile(r"(?<![\d+])(?:\+91[ -]?|0)?[6-9]\d{4}[ -]?\d{5}(?!\d)")
_PHONE_US = re.compile(r"(?<!\d)(?:\+1[ -]?)?\(?[2-9]\d{2}\)?[ -.]\d{3}[ -.]\d{4}(?!\d)")
_ACCOUNT = re.compile(
    r"(?i)\b(?:a/?c|acct|account)(?:\s*(?:no|number|#))?\.?\s*[:#-]?\s*(\d{9,18})\b")
_DOB = re.compile(
    r"(?i)\b(?:dob|date of birth|born)\s*[:=-]?\s*(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2})")
_IFSC = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")


def _collect(kind: str, values: list[str], out: list[PIIMatch]) -> None:
    uniq = list(dict.fromkeys(values))
    if uniq:
        out.append(PIIMatch(kind=kind, count=len(uniq), samples=[redact(v) for v in uniq[:3]]))


def scan_pii(text: str, max_chars: int = 2_000_000) -> PIIReport:
    """Return validated PII found in ``text`` (redacted)."""
    if not text:
        return PIIReport()
    text = text[:max_chars]
    out: list[PIIMatch] = []

    cards, used_spans = [], []
    for m in _CARD.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if 13 <= len(digits) <= 19 and luhn_ok(digits) and len(set(digits)) > 2:
            cards.append(digits)
            used_spans.append(m.span())
    _collect("credit_card", cards, out)

    def overlaps(span: tuple[int, int]) -> bool:
        return any(span[0] < e and s < span[1] for s, e in used_spans)

    aadhaar = []
    for m in _AADHAAR.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if not overlaps(m.span()) and verhoeff_ok(digits):
            aadhaar.append(digits)
    _collect("aadhaar", aadhaar, out)

    _collect("pan", _PAN.findall(text), out)
    _collect("ssn", _SSN.findall(text), out)
    _collect("iban", [m.group() for m in _IBAN.finditer(text) if iban_ok(m.group())], out)
    _collect("email", _EMAIL.findall(text), out)
    phones = [m.group() for m in _PHONE_IN.finditer(text) if not overlaps(m.span())]
    phones += [m.group() for m in _PHONE_US.finditer(text) if not overlaps(m.span())]
    _collect("phone", phones, out)
    _collect("bank_account", _ACCOUNT.findall(text), out)
    _collect("date_of_birth", _DOB.findall(text), out)
    _collect("ifsc", _IFSC.findall(text), out)
    return PIIReport(out)


def redact_text(text: str) -> str:
    """Replace PII and secrets with type tokens, e.g. before sending to an LLM."""
    if not text:
        return text
    out = text
    for _, rx in _SECRETS:
        out = rx.sub("[SECRET]", out)
    for m in list(_CARD.finditer(out))[::-1]:
        digits = re.sub(r"\D", "", m.group())
        if 13 <= len(digits) <= 19 and luhn_ok(digits) and len(set(digits)) > 2:
            out = out[:m.start()] + "[CARD]" + out[m.end():]
    for m in list(_AADHAAR.finditer(out))[::-1]:
        if verhoeff_ok(re.sub(r"\D", "", m.group())):
            out = out[:m.start()] + "[AADHAAR]" + out[m.end():]
    out = _PAN.sub("[PAN]", out)
    out = _SSN.sub("[SSN]", out)
    out = _EMAIL.sub("[EMAIL]", out)
    out = _PHONE_IN.sub("[PHONE]", out)
    out = _PHONE_US.sub("[PHONE]", out)
    out = _ACCOUNT.sub("account [ACCOUNT]", out)
    return out


# Sensitive kinds = enough to identify / defraud a person on their own.
HIGH_RISK_KINDS = {"credit_card", "aadhaar", "pan", "ssn", "iban", "bank_account"}


# ---------------------------------------------------------------- secrets

_SECRETS = [
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws_secret_key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("generic_api_key", re.compile(r"\b(?:sk|pk|rk)_(?:live|prod)_[A-Za-z0-9]{16,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("password_assignment", re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*\S{6,}")),
]


def scan_secrets(text: str) -> list[str]:
    if not text:
        return []
    return [name for name, rx in _SECRETS if rx.search(text)]
