"""Risk register for AI agents, linked to controls.

Inherent risk = likelihood x impact (1-5 each). Residual risk is recalculated
from the live status of the linked controls every time control tests run: a
risk is only "treated" while every control that mitigates it is passing.
"""
from __future__ import annotations

import time
from typing import Any

DEFAULT_RISKS: list[dict[str, Any]] = [
    {"risk_id": "R-01", "title": "Agent harvests or exfiltrates customer PII",
     "description": "A compromised, misaligned or mis-configured agent reads customer personal data "
                    "beyond its task and sends it outside the bank.",
     "likelihood": 3, "impact": 5, "controls": ["AGT-02", "AGT-03", "AGT-04", "AGT-07", "AGT-11"],
     "owner": "Data protection officer", "treatment": "mitigate"},
    {"risk_id": "R-02", "title": "Prompt injection redirects an agent",
     "description": "Content an agent reads (email, web page, document) carries instructions that "
                    "hijack its behaviour.",
     "likelihood": 4, "impact": 4, "controls": ["AGT-08", "AGT-12", "AGT-09"],
     "owner": "AI security", "treatment": "mitigate"},
    {"risk_id": "R-03", "title": "Agent escalates its own privileges",
     "description": "An agent creates credentials or modifies IAM to widen its access.",
     "likelihood": 2, "impact": 5, "controls": ["AGT-05", "AGT-11"],
     "owner": "Identity & access management", "treatment": "mitigate"},
    {"risk_id": "R-04", "title": "Agent bypasses its guardrail",
     "description": "An agent calls data stores directly with its IAM role instead of via the "
                    "Sentinel-wrapped tools.",
     "likelihood": 2, "impact": 5, "controls": ["AGT-11", "AGT-02"],
     "owner": "Security engineering", "treatment": "mitigate"},
    {"risk_id": "R-05", "title": "Shadow / unregistered agents",
     "description": "Teams deploy agents that are not in the inventory and not governed.",
     "likelihood": 3, "impact": 4, "controls": ["AGT-01"],
     "owner": "AI governance lead", "treatment": "mitigate"},
    {"risk_id": "R-06", "title": "Agent silently stops working",
     "description": "An agent stalls, loops or fails and business processes stop without anyone noticing.",
     "likelihood": 3, "impact": 3, "controls": ["AGT-10"],
     "owner": "Platform engineering", "treatment": "mitigate"},
    {"risk_id": "R-07", "title": "Credentials leaked through agent output",
     "description": "Secrets present in an agent's context are echoed into outputs or messages.",
     "likelihood": 3, "impact": 4, "controls": ["AGT-06", "AGT-03"],
     "owner": "Security engineering", "treatment": "mitigate"},
    {"risk_id": "R-08", "title": "Automated high-impact action without human oversight",
     "description": "Destructive or high-risk actions are executed with no human in the loop.",
     "likelihood": 3, "impact": 4, "controls": ["AGT-09", "AGT-12"],
     "owner": "AI governance lead", "treatment": "mitigate"},
]


def level(score: int) -> str:
    return "CRITICAL" if score >= 20 else "HIGH" if score >= 12 else "MEDIUM" if score >= 6 else "LOW"


def evaluate_risk(risk: dict[str, Any], control_results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    r = dict(risk)
    inherent = int(r["likelihood"]) * int(r["impact"])
    statuses = {cid: control_results.get(cid, {}).get("status", "UNTESTED") for cid in r["controls"]}
    passing = sum(1 for s in statuses.values() if s == "PASS")
    warn = sum(1 for s in statuses.values() if s == "WARN")
    effectiveness = (passing + 0.5 * warn) / len(statuses) if statuses else 0.0
    # Controls reduce likelihood, not impact. Full effectiveness reduces likelihood to 1.
    residual_likelihood = max(1, round(int(r["likelihood"]) - (int(r["likelihood"]) - 1) * effectiveness))
    residual = residual_likelihood * int(r["impact"])
    r.update(
        inherent_score=inherent, inherent_level=level(inherent),
        residual_score=residual, residual_level=level(residual),
        control_status=statuses, control_effectiveness=round(effectiveness, 2),
        status="treated" if passing == len(statuses) else "open",
        evaluated_at=time.time(),
    )
    return r
