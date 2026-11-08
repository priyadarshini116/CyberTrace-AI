"""Deterministic incident-investigation pipeline for the demo."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .ai_analyst import build_assessment
from .detector import detect
from .normalizer import normalize_events
from .threat_intel import enrich_events


def load_events(path: str | Path) -> list[dict[str, Any]]:
    """Load security events from a JSON file."""

    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)

    if not isinstance(data, list):
        raise ValueError("Event file must contain a JSON array")

    return data


def investigate_incident(
    path: str | Path,
    use_llm: bool = True,
) -> dict[str, Any]:
    # ---------------------------------------------------------
    # 1. Load raw events
    # ---------------------------------------------------------

    raw_events = load_events(path)

    if not raw_events:
        raise ValueError("No events supplied")

    # ---------------------------------------------------------
    # 2. Normalize events
    # ---------------------------------------------------------

    events = normalize_events(raw_events)
    events = enrich_events(events)

    # ---------------------------------------------------------
    # 3. Run detection engine
    # ---------------------------------------------------------

    findings = detect(events)

    # ---------------------------------------------------------
    # 4. Build AI analyst assessment
    # ---------------------------------------------------------

    ai_assessment = build_assessment(
        events,
        findings,
        use_llm=use_llm,
)

    # ---------------------------------------------------------
    # 5. Build attack timeline
    # ---------------------------------------------------------

    timeline = []

    for event in events:
        timeline.append(
            {
                "timestamp": event.get("timestamp", "-"),
                "host": event.get("host", "-"),
                "user": event.get("user", "-"),
                "event_type": event.get("event_type", "-"),
                "source_ip": event.get("source_ip", "-"),
                "command": event.get("command", "-"),
            }
        )

    # ---------------------------------------------------------
    # 6. Incident summary
    # ---------------------------------------------------------

    incident_id = events[0].get(
        "incident_id",
        "SIM-INCIDENT-001",
    )

    summary = {
        "incident_id": incident_id,
        "event_count": len(events),
        "finding_count": len(findings),
        "severity": ai_assessment["severity"],
        "confidence": ai_assessment["confidence"],
    }

    # ---------------------------------------------------------
    # 7. Return complete investigation
    # ---------------------------------------------------------

    return {
        "summary": summary,
        "timeline": timeline,
        "findings": findings,
        "ai_assessment": ai_assessment,
        "events": events,
    }
    