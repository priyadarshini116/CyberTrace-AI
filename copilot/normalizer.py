"""Security event normalization layer."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


EVENT_TYPE_MAP = {
    "login_failed": "failed_login",
    "authentication_failure": "failed_login",
    "auth_failure": "failed_login",

    "login_success": "successful_login",
    "authentication_success": "successful_login",
    "auth_success": "successful_login",

    "process_created": "process_start",
    "process_creation": "process_start",

    "credential_dump": "credential_access",
    "credential_access_event": "credential_access",

    "remote_login": "lateral_movement",
    "remote_connection": "lateral_movement",

    "scheduled_task": "persistence",
    "scheduled_task_created": "persistence",
}


def normalize_timestamp(value: Any) -> str:
    """Convert timestamps into UTC ISO-8601 format."""

    if not value:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    text = str(value).strip()

    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        parsed = parsed.astimezone(timezone.utc)

        return parsed.isoformat().replace("+00:00", "Z")

    except ValueError:
        return text


def normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    """Convert a raw security event into the common SOC schema."""

    raw_event_type = str(
        event.get("event_type", "unknown")
    ).strip().lower()

    normalized_event_type = EVENT_TYPE_MAP.get(
        raw_event_type,
        raw_event_type,
    )

    normalized = {
        "incident_id": str(
            event.get("incident_id", "SIM-INCIDENT-001")
        ),

        "timestamp": normalize_timestamp(
            event.get("timestamp")
        ),

        "host": str(
            event.get("host", "-")
        ).strip(),

        "user": str(
            event.get("user", "-")
        ).strip(),

        "event_type": normalized_event_type,

        "source_ip": str(
            event.get("source_ip", "-")
        ).strip(),

        "source_host": str(
            event.get("source_host", "-")
        ).strip(),

        "destination_host": str(
            event.get("destination_host", "-")
        ).strip(),

        "command": str(
            event.get("command", "-")
        ).strip(),

        "details": str(
            event.get("details", "-")
        ).strip(),
    }

    # Preserve the original event for investigation/auditing.
    normalized["_raw_event"] = event

    return normalized


def normalize_events(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Normalize a collection of security events."""

    if not isinstance(events, list):
        raise ValueError("Events must be provided as a list")

    return [
        normalize_event(event)
        for event in events
    ]