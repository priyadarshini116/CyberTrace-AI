"""Local threat-intelligence enrichment for security events."""

from __future__ import annotations

import ipaddress
from typing import Any


# Local simulated threat-intelligence dataset.
#
# This is intentionally local and deterministic so the project
# works without requiring a paid external API.

KNOWN_IOCS = {
    "185.220.101.44": {
        "type": "ipv4",
        "reputation": "malicious",
        "confidence": 95,
        "source": "Local Threat Intelligence Feed",
        "description": "Known simulated attacker infrastructure",
    },
    "10.10.10.50": {
        "type": "ipv4",
        "reputation": "internal",
        "confidence": 100,
        "source": "Internal Network Context",
        "description": "Private/internal address",
    },
}


def classify_ip(ip: str) -> str:
    """Classify an IP address as public, private, or invalid."""

    try:
        address = ipaddress.ip_address(ip)

        if address.is_private:
            return "private"

        return "public"

    except ValueError:
        return "invalid"


def lookup_ip(ip: str) -> dict[str, Any]:
    """Look up an IP in the local threat-intelligence dataset."""

    if ip in KNOWN_IOCS:
        return KNOWN_IOCS[ip].copy()

    classification = classify_ip(ip)

    if classification == "private":
        return {
            "type": "ipv4",
            "reputation": "internal",
            "confidence": 100,
            "source": "IP Classification",
            "description": "Private/internal network address",
        }

    if classification == "public":
        return {
            "type": "ipv4",
            "reputation": "unknown",
            "confidence": 20,
            "source": "IP Classification",
            "description": "Public IP with no local threat-intelligence match",
        }

    return {
        "type": "unknown",
        "reputation": "unknown",
        "confidence": 0,
        "source": "IP Classification",
        "description": "Invalid or unavailable IP address",
    }


def enrich_event(event: dict[str, Any]) -> dict[str, Any]:
    """Add threat-intelligence context to a normalized event."""

    enriched = dict(event)

    source_ip = event.get("source_ip")

    if source_ip and source_ip != "-":
        enriched["threat_intel"] = {
            "source_ip": source_ip,
            **lookup_ip(source_ip),
        }
    else:
        enriched["threat_intel"] = {
            "source_ip": "-",
            "type": "unknown",
            "reputation": "unknown",
            "confidence": 0,
            "source": "Threat Intelligence",
            "description": "No source IP available",
        }

    return enriched


def enrich_events(
    events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Enrich all normalized security events."""

    if not isinstance(events, list):
        raise ValueError("Events must be provided as a list")

    return [
        enrich_event(event)
        for event in events
    ]