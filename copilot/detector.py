"""Detection-as-code layer for the AI SOC Copilot."""

from __future__ import annotations

from collections import defaultdict
from typing import Any


def _finding(
    rule_id: str,
    title: str,
    severity: str,
    confidence: int,
    tactic: str,
    technique_id: str,
    technique_name: str,
    evidence: str,
    timestamp: str | None,
) -> dict[str, Any]:
    """Build a standardized detection finding."""

    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "mitre": {
            "tactic": tactic,
            "technique_id": technique_id,
            "technique_name": technique_name,
        },
        "evidence": evidence,
        "event_timestamp": timestamp,
    }


def detect(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run detection rules against security events."""

    findings: list[dict[str, Any]] = []

    by_src: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for event in events:
        by_src[event.get("source_ip", "-")].append(event)

    # ---------------------------------------------------------
    # DET-001: Repeated Authentication Failures
    # ---------------------------------------------------------

    for source_ip, source_events in by_src.items():

        failed_logins = [
            event
            for event in source_events
            if event.get("event_type") == "failed_login"
        ]

        if len(failed_logins) >= 3:

            users = sorted(
                {
                    event.get("user", "-")
                    for event in failed_logins
                }
            )

            first_timestamp = failed_logins[0].get("timestamp")
            last_timestamp = failed_logins[-1].get("timestamp")

            findings.append(
                _finding(
                    rule_id="DET-001",
                    title="Repeated authentication failures",
                    severity="Medium",
                    confidence=95,
                    tactic="Credential Access",
                    technique_id="T1110",
                    technique_name="Brute Force",
                    evidence=(
                        f"{len(failed_logins)} failed login attempts "
                        f"from {source_ip} targeting "
                        f"{', '.join(users)} "
                        f"between {first_timestamp} and {last_timestamp}"
                    ),
                    timestamp=last_timestamp,
                )
            )

    # ---------------------------------------------------------
    # Event-level detections
    # ---------------------------------------------------------

    for event in events:

        event_type = event.get("event_type")
        command = (event.get("command") or "").lower()
        details = (event.get("details") or "").lower()
        timestamp = event.get("timestamp")

        source_ip = event.get("source_ip")

        source_events = by_src.get(source_ip, [])

        # -----------------------------------------------------
        # DET-002: Brute-force success
        # -----------------------------------------------------

        if event_type == "successful_login":

            failures = sum(
                1
                for e in source_events
                if e.get("event_type") == "failed_login"
            )

            if failures >= 3:

                findings.append(
                    _finding(
                        rule_id="DET-002",
                        title="Brute-force success",
                        severity="High",
                        confidence=97,
                        tactic="Credential Access",
                        technique_id="T1110",
                        technique_name="Brute Force",
                        evidence=(
                            f"Successful login after "
                            f"{failures} failed attempts "
                            f"from {source_ip}"
                        ),
                        timestamp=timestamp,
                    )
                )

        # -----------------------------------------------------
        # DET-003: Suspicious PowerShell
        # -----------------------------------------------------

        if (
            "powershell" in command
            and (
                "-enc" in command
                or "downloadstring" in command
            )
        ):

            findings.append(
                _finding(
                    rule_id="DET-003",
                    title="Suspicious PowerShell execution",
                    severity="High",
                    confidence=92,
                    tactic="Execution",
                    technique_id="T1059.001",
                    technique_name="PowerShell",
                    evidence=event.get("command", ""),
                    timestamp=timestamp,
                )
            )

        # -----------------------------------------------------
        # DET-004: LSASS credential access
        # -----------------------------------------------------

        if (
            event_type == "credential_access"
            or "lsass" in details
        ):

            findings.append(
                _finding(
                    rule_id="DET-004",
                    title="LSASS credential access",
                    severity="Critical",
                    confidence=96,
                    tactic="Credential Access",
                    technique_id="T1003.001",
                    technique_name="LSASS Memory",
                    evidence=event.get(
                        "details",
                        "LSASS credential material accessed",
                    ),
                    timestamp=timestamp,
                )
            )

        # -----------------------------------------------------
        # DET-005: Lateral movement
        # -----------------------------------------------------

        if event_type == "lateral_movement":

            findings.append(
                _finding(
                    rule_id="DET-005",
                    title="Lateral movement to internal host",
                    severity="High",
                    confidence=90,
                    tactic="Lateral Movement",
                    technique_id="T1021",
                    technique_name="Remote Services",
                    evidence=(
                        f"{event.get('source_host')} → "
                        f"{event.get('destination_host')}"
                    ),
                    timestamp=timestamp,
                )
            )

        # -----------------------------------------------------
        # DET-006: Scheduled task persistence
        # -----------------------------------------------------

        if event_type == "persistence":

            findings.append(
                _finding(
                    rule_id="DET-006",
                    title="Scheduled task persistence",
                    severity="Critical",
                    confidence=94,
                    tactic="Persistence",
                    technique_id="T1053.005",
                    technique_name="Scheduled Task/Job",
                    evidence=event.get(
                        "details",
                        "Scheduled task persistence created",
                    ),
                    timestamp=timestamp,
                )
            )

    return findings