"""Prompt-injection detection on untrusted content an agent ingests.

Agents go rogue most often because something they *read* told them to. This
detector scores the untrusted inputs attached to an event (``event.inputs``:
web pages, emails, documents, tool results) for instruction-like content,
hidden characters and exfiltration payloads. It also decodes base64 blobs and
rescans them, since encoding is the cheapest evasion.

It is a heuristic first pass; the LLM judge provides the semantic second
opinion for agents whose policy enables it.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

from .models import ActionEvent, Finding, Severity
from .rules import C_INJECTION

_PATTERNS: list[tuple[str, float, re.Pattern[str]]] = [
    ("override_instructions", 0.6, re.compile(
        r"(?i)\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|"
        r"all|your|system|original)\b[^.\n]{0,20}\b(instructions?|prompts?|rules?|directives?|guidelines?)")),
    ("new_instructions", 0.45, re.compile(
        r"(?i)(new|updated|real|actual|true)\s+(instructions?|task|objective|orders?)\s*[:\-]")),
    ("role_hijack", 0.45, re.compile(
        r"(?i)\b(you are now|from now on,? you|act as (?:an? )?(?:unrestricted|jailbroken|developer)|"
        r"pretend (?:to be|you are)|enter (?:developer|god|dan) mode|do anything now)\b")),
    ("fake_system", 0.5, re.compile(
        r"(?i)(<\s*/?\s*(system|sys|instructions?|admin)\s*>|\[\s*(system|admin)\s*(message|note)?\s*\]|"
        r"BEGIN (SYSTEM|ADMIN) (PROMPT|MESSAGE)|###\s*system)")),
    ("authority_claim", 0.3, re.compile(
        r"(?i)\b(this (?:message|request) (?:is|comes) from (?:the )?(?:admin|administrator|security team|"
        r"anthropic|openai|your developer)|authori[sz]ed by (?:the )?(?:ciso|admin|security))")),
    ("exfil_instruction", 0.6, re.compile(
        r"(?i)\b(send|post|upload|forward|email|transmit|exfiltrate|copy)\b[^.\n]{0,60}"
        r"\b(customer|user|account|credential|password|api key|secret|pii|record|data(?:base)?|files?)\b"
        r"[^.\n]{0,60}\b(to|at)\b[^.\n]{0,30}(https?://|[\w.-]+@[\w.-]+|\b\d{1,3}(?:\.\d{1,3}){3}\b)")),
    ("markdown_exfil", 0.6, re.compile(
        r"!\[[^\]]*\]\(\s*https?://[^)\s]+[?&][^)\s]*=(?:\{|%7B|\$|<)?[^)\s]*\)")),
    ("secrecy", 0.3, re.compile(
        r"(?i)\b(do not|don't|never)\s+(tell|inform|mention|reveal|alert|notify|log)\b[^.\n]{0,30}"
        r"\b(user|human|operator|admin|anyone|security|monitor)")),
    ("tool_coercion", 0.35, re.compile(
        r"(?i)\b(call|invoke|use|run|execute)\s+(the\s+)?(tool|function|command)\b[^.\n]{0,40}"
        r"\b(immediately|now|without (asking|confirmation|approval))")),
    ("disable_safety", 0.5, re.compile(
        r"(?i)\b(disable|turn off|bypass|skip|evade)\b[^.\n]{0,30}\b(safety|guardrails?|filters?|monitor(?:ing)?|"
        r"sentinel|logging|audit|security checks?)")),
]

_ZERO_WIDTH = re.compile("[​‌‍⁠﻿­]")
_TAG_CHARS = re.compile("[\U000E0000-\U000E007F]")
_BIDI = re.compile("[‪-‮⁦-⁩]")
_B64 = re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)


@dataclass
class InjectionReport:
    score: float = 0.0
    signals: list[str] = field(default_factory=list)

    def add(self, name: str, weight: float) -> None:
        if name not in self.signals:
            self.signals.append(name)
            # noisy-OR so independent signals combine without exceeding 1
            self.score = 1 - (1 - self.score) * (1 - weight)


def _scan_text(text: str, rep: InjectionReport, prefix: str = "") -> None:
    for name, weight, rx in _PATTERNS:
        if rx.search(text):
            rep.add(prefix + name, weight)


def scan_injection(text: str, max_chars: int = 500_000) -> InjectionReport:
    rep = InjectionReport()
    if not text:
        return rep
    text = text[:max_chars]

    tags = _TAG_CHARS.findall(text)
    if tags:
        rep.add("hidden_unicode_tags", 0.7)
        # decode the smuggled ASCII and scan it too
        hidden = "".join(chr(ord(c) - 0xE0000) for c in tags)
        _scan_text(hidden, rep, "hidden:")
    if len(_ZERO_WIDTH.findall(text)) >= 5:
        rep.add("zero_width_chars", 0.25)
    if _BIDI.search(text):
        rep.add("bidi_override", 0.3)

    clean = _TAG_CHARS.sub("", _ZERO_WIDTH.sub("", text))
    clean = unicodedata.normalize("NFKC", clean)
    _scan_text(clean, rep)

    for m in _HTML_COMMENT.finditer(clean):
        sub = InjectionReport()
        _scan_text(m.group(1), sub)
        if sub.signals:
            rep.add("instructions_in_html_comment", 0.4)

    for m in list(_B64.finditer(clean))[:20]:
        try:
            decoded = base64.b64decode(m.group(), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        sub = InjectionReport()
        _scan_text(decoded, sub)
        if sub.signals:
            rep.add("encoded_instructions", 0.6)
            for s in sub.signals:
                rep.add("b64:" + s, 0.0)
    return rep


def evaluate_injection(ev: ActionEvent, threshold: float = 0.5,
                       critical: float = 0.85) -> list[Finding]:
    if not ev.inputs:
        return []
    rep = scan_injection(ev.inputs)
    if rep.score < threshold:
        return []
    sev = Severity.CRITICAL if rep.score >= critical else Severity.HIGH
    return [Finding(
        detector="injection", rule_id="injection.prompt_injection", severity=sev,
        title="Prompt injection in agent input",
        detail=f"Untrusted content ingested by '{ev.agent_id}' contains instruction-injection "
               f"signals ({', '.join(rep.signals)}); score {rep.score:.2f}. The action that "
               f"follows it is treated as potentially attacker-directed.",
        controls=[C_INJECTION],
        evidence={"score": round(rep.score, 3), "signals": rep.signals},
    )]
