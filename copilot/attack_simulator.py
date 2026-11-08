from datetime import datetime, timedelta, timezone
import random


def _timestamp(base_time, seconds):
    return (
        base_time + timedelta(seconds=seconds)
    ).isoformat().replace("+00:00", "Z")


def generate_brute_force(
    incident_id,
    user,
    host,
    source_ip,
    failures=5,
    base_time=None,
):
    """Generate synthetic VPN brute-force telemetry."""

    if base_time is None:
        base_time = datetime.now(timezone.utc)

    events = []

    # Failed login attempts
    for i in range(failures):
        events.append({
            "incident_id": incident_id,
            "timestamp": _timestamp(base_time, i * 8),
            "host": host,
            "user": user,
            "event_type": "failed_login",
            "source_ip": source_ip,
            "details": "Invalid password",
        })

    # Successful login after failures
    events.append({
        "incident_id": incident_id,
        "timestamp": _timestamp(
            base_time,
            failures * 8 + 5
        ),
        "host": host,
        "user": user,
        "event_type": "successful_login",
        "source_ip": source_ip,
        "details": "VPN login succeeded",
    })

    return events


def generate_powershell(
    incident_id,
    user,
    host,
    source_ip,
    base_time=None,
):
    """Generate synthetic suspicious PowerShell telemetry."""

    if base_time is None:
        base_time = datetime.now(timezone.utc)

    return [{
        "incident_id": incident_id,
        "timestamp": _timestamp(base_time, 180),
        "host": host,
        "user": user,
        "event_type": "process_start",
        "source_ip": source_ip,
        "command": (
            "powershell.exe -EncodedCommand "
            "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAI..."
        ),
    }]


def generate_credential_access(
    incident_id,
    user,
    host,
    source_ip,
    base_time=None,
):
    """Generate synthetic credential-access telemetry."""

    if base_time is None:
        base_time = datetime.now(timezone.utc)

    return [{
        "incident_id": incident_id,
        "timestamp": _timestamp(base_time, 240),
        "host": host,
        "user": user,
        "event_type": "credential_access",
        "source_ip": source_ip,
        "details": "LSASS memory access by unsigned process",
    }]


def generate_lateral_movement(
    incident_id,
    user,
    source_host,
    destination_host,
    source_ip,
    base_time=None,
):
    """Generate synthetic lateral-movement telemetry."""

    if base_time is None:
        base_time = datetime.now(timezone.utc)

    return [{
        "incident_id": incident_id,
        "timestamp": _timestamp(base_time, 420),
        "host": source_host,
        "user": user,
        "event_type": "lateral_movement",
        "source_ip": source_ip,
        "source_host": source_host,
        "destination_host": destination_host,
    }]


def generate_persistence(
    incident_id,
    user,
    host,
    source_ip,
    base_time=None,
):
    """Generate synthetic scheduled-task persistence telemetry."""

    if base_time is None:
        base_time = datetime.now(timezone.utc)

    return [{
        "incident_id": incident_id,
        "timestamp": _timestamp(base_time, 540),
        "host": host,
        "user": user,
        "event_type": "persistence",
        "source_ip": source_ip,
        "details": (
            "New scheduled task created: "
            "WindowsUpdateCheck"
        ),
    }]


def generate_attack(
    scenario,
    user="j.smith",
    source_ip="10.10.10.50",
):
    """
    Main attack simulator entry point.

    Returns a list of synthetic security events.
    """

    incident_id = f"SIM-{random.randint(1000, 9999)}"

    base_time = datetime.now(timezone.utc)

    # --------------------------------------------------------
    # BRUTE FORCE
    # --------------------------------------------------------

    if scenario == "Brute Force":

        return generate_brute_force(
            incident_id=incident_id,
            user=user,
            host="VPN-GW-01",
            source_ip=source_ip,
            failures=5,
            base_time=base_time,
        )

    # --------------------------------------------------------
    # POWERSHELL
    # --------------------------------------------------------

    if scenario == "PowerShell":

        return generate_powershell(
            incident_id=incident_id,
            user=user,
            host="WS-FIN-014",
            source_ip=source_ip,
            base_time=base_time,
        )

    # --------------------------------------------------------
    # CREDENTIAL ACCESS
    # --------------------------------------------------------

    if scenario == "Credential Access":

        return generate_credential_access(
            incident_id=incident_id,
            user=user,
            host="WS-FIN-014",
            source_ip=source_ip,
            base_time=base_time,
        )

    # --------------------------------------------------------
    # LATERAL MOVEMENT
    # --------------------------------------------------------

    if scenario == "Lateral Movement":

        return generate_lateral_movement(
            incident_id=incident_id,
            user=user,
            source_host="WS-FIN-014",
            destination_host="FS-01",
            source_ip=source_ip,
            base_time=base_time,
        )

    # --------------------------------------------------------
    # FULL APT ATTACK CHAIN
    # --------------------------------------------------------

    if scenario == "Full APT Chain":

        events = []

        # Stage 1:
        # Brute force → successful login
        events.extend(
            generate_brute_force(
                incident_id=incident_id,
                user=user,
                host="VPN-GW-01",
                source_ip=source_ip,
                failures=5,
                base_time=base_time,
            )
        )

        # Stage 2:
        # Suspicious PowerShell
        events.extend(
            generate_powershell(
                incident_id=incident_id,
                user=user,
                host="WS-FIN-014",
                source_ip=source_ip,
                base_time=base_time,
            )
        )

        # Stage 3:
        # Credential access
        events.extend(
            generate_credential_access(
                incident_id=incident_id,
                user=user,
                host="WS-FIN-014",
                source_ip=source_ip,
                base_time=base_time,
            )
        )

        # Stage 4:
        # Lateral movement
        events.extend(
            generate_lateral_movement(
                incident_id=incident_id,
                user=user,
                source_host="WS-FIN-014",
                destination_host="FS-01",
                source_ip=source_ip,
                base_time=base_time,
            )
        )

        # Stage 5:
        # Persistence
        events.extend(
            generate_persistence(
                incident_id=incident_id,
                user="svc_backup",
                host="FS-01",
                source_ip=source_ip,
                base_time=base_time,
            )
        )

        return events

    raise ValueError(
        f"Unknown attack scenario: {scenario}"
    )