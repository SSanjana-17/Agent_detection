"""Control library for AI-agent governance, mapped to external frameworks.

Each control is continuously tested (see ``tests.py``) and every result is
written to the evidence chain, the way Vanta/Drata do for SOC 2 — but scoped
to what a fleet of AI agents is doing.

Framework references are mappings for audit preparation. Confirm the final
mapping with your auditor; regulators (e.g. RBI, MAS, OCC) may require
additional controls, which can be added here without code changes elsewhere.
"""
from __future__ import annotations

from dataclasses import dataclass, field

FRAMEWORKS = {
    "SOC2": "SOC 2 (AICPA Trust Services Criteria 2017, rev. 2022)",
    "ISO27001": "ISO/IEC 27001:2022 Annex A",
    "ISO42001": "ISO/IEC 42001:2023 Annex A (AI management system)",
    "PCIDSS": "PCI DSS v4.0.1",
    "NISTAIRMF": "NIST AI Risk Management Framework 1.0",
}


@dataclass(frozen=True)
class Control:
    id: str
    name: str
    objective: str
    owner_role: str
    frameworks: dict[str, list[str]] = field(default_factory=dict)


CONTROLS: list[Control] = [
    Control("AGT-01", "AI agent inventory",
            "Every agent that acts is registered with an owner, purpose, risk tier and permissions; "
            "unregistered agents are blocked.",
            "AI governance lead",
            {"SOC2": ["CC6.1", "CC2.1"], "ISO27001": ["5.9"], "ISO42001": ["A.4.2", "A.6.2.2"],
             "PCIDSS": ["12.5.1"], "NISTAIRMF": ["GOVERN 1.6", "MAP 1.1"]}),
    Control("AGT-02", "Least-privilege data access for agents",
            "Agents can only reach resources and data classifications their role requires; "
            "restricted data access is bounded per action.",
            "Security engineering",
            {"SOC2": ["CC6.1", "CC6.3"], "ISO27001": ["5.15", "5.18", "8.3"],
             "ISO42001": ["A.7.2", "A.9.2"], "PCIDSS": ["7.2.1", "7.2.2", "7.2.5"],
             "NISTAIRMF": ["MEASURE 2.7"]}),
    Control("AGT-03", "Data loss prevention on agent outputs",
            "Personal and financial data in agent outputs, messages and outbound calls is detected "
            "and stopped before it leaves.",
            "Data protection officer",
            {"SOC2": ["CC6.7", "C1.1"], "ISO27001": ["8.12", "5.34"], "ISO42001": ["A.7.5"],
             "PCIDSS": ["3.3.1", "3.4.1", "4.2.1"], "NISTAIRMF": ["MEASURE 2.10"]}),
    Control("AGT-04", "Agent egress restriction",
            "Agents can only send data to approved destinations.",
            "Network security",
            {"SOC2": ["CC6.6", "CC6.7"], "ISO27001": ["8.20", "8.23"], "PCIDSS": ["1.3.2", "1.4.2"],
             "NISTAIRMF": ["MEASURE 2.7"]}),
    Control("AGT-05", "Privilege escalation prevention",
            "Agents cannot grant themselves or others permissions or create credentials.",
            "Identity & access management",
            {"SOC2": ["CC6.2", "CC6.3"], "ISO27001": ["8.2", "5.18"], "PCIDSS": ["7.2.4", "8.6.1"],
             "NISTAIRMF": ["MANAGE 2.4"]}),
    Control("AGT-06", "Secret and credential leakage prevention",
            "API keys, tokens and passwords in agent outputs are blocked.",
            "Security engineering",
            {"SOC2": ["CC6.1"], "ISO27001": ["5.17", "8.24"], "PCIDSS": ["8.3.2", "8.6.2"]}),
    Control("AGT-07", "Behavioural monitoring of agents",
            "Agent activity is continuously monitored against rate limits and learned baselines; "
            "anomalies raise alerts.",
            "Security operations",
            {"SOC2": ["CC7.2", "CC7.3"], "ISO27001": ["8.16"], "ISO42001": ["A.6.2.6"],
             "PCIDSS": ["10.4.1", "11.5.1"], "NISTAIRMF": ["MANAGE 4.1", "MEASURE 2.4"]}),
    Control("AGT-08", "Prompt-injection defence",
            "Untrusted content ingested by agents is screened for injected instructions, and "
            "actions influenced by it are blocked.",
            "AI security",
            {"SOC2": ["CC6.8", "CC7.1"], "ISO27001": ["8.7"], "ISO42001": ["A.6.2.4"],
             "NISTAIRMF": ["MEASURE 2.7", "MANAGE 2.2"]}),
    Control("AGT-09", "Human oversight of high-risk agent actions",
            "High-severity actions pause for human approval; held actions fail closed on timeout; "
            "quarantined agents are released only by a human.",
            "AI governance lead",
            {"SOC2": ["CC7.4", "CC5.1"], "ISO27001": ["5.24", "5.26"],
             "ISO42001": ["A.9.2", "A.9.3"], "PCIDSS": ["12.10.1"],
             "NISTAIRMF": ["GOVERN 3.2", "MANAGE 2.4"]}),
    Control("AGT-10", "Agent availability and health",
            "Agents that stop reporting, fail or loop are detected.",
            "Platform engineering",
            {"SOC2": ["A1.1", "A1.2", "CC7.2"], "ISO27001": ["8.6", "8.16"],
             "ISO42001": ["A.6.2.6"], "NISTAIRMF": ["MANAGE 4.1"]}),
    Control("AGT-11", "Immutable audit trail of agent activity",
            "Agent decisions and governance actions are recorded in a tamper-evident, WORM-protected "
            "log; direct data access is cross-checked against CloudTrail.",
            "Internal audit",
            {"SOC2": ["CC7.2", "CC4.1"], "ISO27001": ["8.15", "5.28", "5.33"],
             "ISO42001": ["A.6.2.8"], "PCIDSS": ["10.2.1", "10.3.2", "10.5.1"],
             "NISTAIRMF": ["GOVERN 1.4"]}),
    Control("AGT-12", "Task-alignment review",
            "High-risk agents' sensitive actions are checked by an independent model for "
            "consistency with the assigned task.",
            "AI governance lead",
            {"ISO42001": ["A.6.2.4", "A.9.4"], "NISTAIRMF": ["MEASURE 2.5", "MEASURE 2.6"],
             "SOC2": ["CC7.2"]}),
]

CONTROL_INDEX = {c.id: c for c in CONTROLS}


def controls_for(framework: str) -> list[Control]:
    return [c for c in CONTROLS if framework in c.frameworks]
