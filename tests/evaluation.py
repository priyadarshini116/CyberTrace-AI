"""
Detection evaluation engine.

Evaluates the deterministic SOC detection layer using
attack and benign test cases.

Metrics:
- True Positive
- False Positive
- True Negative
- False Negative
- Precision
- Recall
- F1 Score
- False Positive Rate
- Detection Coverage
"""

from __future__ import annotations

from typing import Any

from copilot.detector import detect
from copilot.normalizer import normalize_events


def evaluate_case(
    events: list[dict[str, Any]],
    expected_attack: bool,
) -> dict[str, Any]:
    """
    Evaluate one security-event scenario.

    expected_attack:
        True  -> this scenario is known malicious.
        False -> this scenario is known benign.
    """

    normalized_events = normalize_events(events)
    findings = detect(normalized_events)

    detected = len(findings) > 0

    if expected_attack and detected:
        classification = "TP"

    elif expected_attack and not detected:
        classification = "FN"

    elif not expected_attack and detected:
        classification = "FP"

    else:
        classification = "TN"

    return {
        "classification": classification,
        "expected_attack": expected_attack,
        "detected": detected,
        "finding_count": len(findings),
        "findings": findings,
    }


def calculate_metrics(
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Calculate aggregate detection metrics.
    """

    tp = sum(
        1 for result in results
        if result["classification"] == "TP"
    )

    fp = sum(
        1 for result in results
        if result["classification"] == "FP"
    )

    tn = sum(
        1 for result in results
        if result["classification"] == "TN"
    )

    fn = sum(
        1 for result in results
        if result["classification"] == "FN"
    )

    precision = (
        tp / (tp + fp)
        if (tp + fp) > 0
        else 0.0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn) > 0
        else 0.0
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    false_positive_rate = (
        fp / (fp + tn)
        if (fp + tn) > 0
        else 0.0
    )

    attack_cases = tp + fn

    detection_coverage = (
        tp / attack_cases
        if attack_cases > 0
        else 0.0
    )

    return {
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(
            false_positive_rate,
            4,
        ),
        "detection_coverage": round(
            detection_coverage,
            4,
        ),
        "total_cases": len(results),
    }


def evaluate_dataset(
    attack_cases: list[list[dict[str, Any]]],
    benign_cases: list[list[dict[str, Any]]],
) -> dict[str, Any]:
    """
    Evaluate all attack and benign scenarios.
    """

    results = []

    for index, events in enumerate(
        attack_cases,
        start=1,
    ):
        result = evaluate_case(
            events,
            expected_attack=True,
        )

        result["case_id"] = f"ATTACK-{index:03d}"
        results.append(result)

    for index, events in enumerate(
        benign_cases,
        start=1,
    ):
        result = evaluate_case(
            events,
            expected_attack=False,
        )

        result["case_id"] = f"BENIGN-{index:03d}"
        results.append(result)

    metrics = calculate_metrics(results)

    return {
        "metrics": metrics,
        "results": results,
    }