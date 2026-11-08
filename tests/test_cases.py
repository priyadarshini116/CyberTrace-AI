"""
Evaluation scenarios for the SOC detection engine.

Attack scenarios are known-positive cases.
Benign scenarios represent normal security activity.
"""

from __future__ import annotations

from typing import Any

from copilot.attack_simulator import generate_attack


# ---------------------------------------------------------
# KNOWN ATTACK CASES
# ---------------------------------------------------------

def get_attack_cases() -> list[dict[str, Any]]:
    """
    Generate known malicious scenarios from the attack simulator.
    """

    scenarios = [
        "Brute Force",
        "PowerShell",
        "Credential Access",
        "Lateral Movement",
        "Full APT Chain",
    ]

    cases = []

    for scenario in scenarios:

        events = generate_attack(scenario)

        cases.append(
            {
                "case_id": f"ATTACK-{scenario.upper().replace(' ', '_')}",
                "name": scenario,
                "expected_attack": True,
                "events": events,
            }
        )

    return cases


# ---------------------------------------------------------
# BENIGN CASES
# ---------------------------------------------------------

def get_benign_cases() -> list[dict[str, Any]]:
    """
    Generate normal activity that should not trigger
    the current detection rules.
    """

    return [
        {
            "case_id": "BENIGN-NORMAL-LOGIN",
            "name": "Normal Login",
            "expected_attack": False,
            "events": [
                {
                    "incident_id": "BENIGN-001",
                    "timestamp": "2026-09-15T10:00:00Z",
                    "host": "WS-FIN-014",
                    "user": "j.smith",
                    "event_type": "successful_login",
                    "source_ip": "10.10.10.20",
                    "source_host": "VPN-GW-01",
                    "destination_host": "-",
                    "command": "-",
                    "details": "Normal successful VPN login",
                }
            ],
        },
        {
            "case_id": "BENIGN-NORMAL-POWERSHELL",
            "name": "Normal PowerShell",
            "expected_attack": False,
            "events": [
                {
                    "incident_id": "BENIGN-002",
                    "timestamp": "2026-09-15T11:00:00Z",
                    "host": "WS-DEV-021",
                    "user": "developer",
                    "event_type": "process_start",
                    "source_ip": "10.10.10.30",
                    "source_host": "WS-DEV-021",
                    "destination_host": "-",
                    "command": "powershell.exe -Command Get-Date",
                    "details": "Routine administrative command",
                }
            ],
        },
        {
            "case_id": "BENIGN-NORMAL-REMOTE",
            "name": "Normal Remote Connection",
            "expected_attack": False,
            "events": [
                {
                    "incident_id": "BENIGN-003",
                    "timestamp": "2026-09-15T12:00:00Z",
                    "host": "WS-ADMIN-01",
                    "user": "admin",
                    "event_type": "process_start",
                    "source_ip": "10.10.10.40",
                    "source_host": "WS-ADMIN-01",
                    "destination_host": "FS-01",
                    "command": "mstsc.exe",
                    "details": "Approved administrative remote access",
                }
            ],
        },
        {
            "case_id": "BENIGN-NORMAL-TASK",
            "name": "Normal Scheduled Task",
            "expected_attack": False,
            "events": [
                {
                    "incident_id": "BENIGN-004",
                    "timestamp": "2026-09-15T13:00:00Z",
                    "host": "WS-OPS-05",
                    "user": "SYSTEM",
                    "event_type": "process_start",
                    "source_ip": "10.10.10.50",
                    "source_host": "WS-OPS-05",
                    "destination_host": "-",
                    "command": "taskeng.exe",
                    "details": "Routine Windows maintenance task",
                }
            ],
        },
        {
            "case_id": "BENIGN-NORMAL-AUTH",
            "name": "Single Failed Login",
            "expected_attack": False,
            "events": [
                {
                    "incident_id": "BENIGN-005",
                    "timestamp": "2026-09-15T14:00:00Z",
                    "host": "VPN-GW-01",
                    "user": "j.smith",
                    "event_type": "failed_login",
                    "source_ip": "10.10.10.60",
                    "source_host": "VPN-GW-01",
                    "destination_host": "-",
                    "command": "-",
                    "details": "Single mistyped password",
                }
            ],
        },
    ]