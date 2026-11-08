"""
Rule-level detection coverage evaluation.

Checks whether each known attack scenario triggers the
specific detection rules expected for that scenario.
"""

from __future__ import annotations

from typing import Any

from copilot.detector import detect
from copilot.normalizer import normalize_events
from tests.test_cases import (
    get_attack_cases,
    get_benign_cases,
)


# ---------------------------------------------------------
# EXPECTED DETECTION RULES
# ---------------------------------------------------------

EXPECTED_RULES = {
    "Brute Force": {
        "DET-001",
        "DET-002",
    },
    "PowerShell": {
        "DET-003",
    },
    "Credential Access": {
        "DET-004",
    },
    "Lateral Movement": {
        "DET-005",
    },
    "Full APT Chain": {
        "DET-001",
        "DET-002",
        "DET-003",
        "DET-004",
        "DET-005",
        "DET-006",
    },
}


# ---------------------------------------------------------
# EVALUATE ONE ATTACK
# ---------------------------------------------------------

def evaluate_attack_case(
    case: dict[str, Any],
) -> dict[str, Any]:

    events = normalize_events(
        case["events"]
    )

    findings = detect(events)

    actual_rules = {
        finding["rule_id"]
        for finding in findings
    }

    expected_rules = EXPECTED_RULES.get(
        case["name"],
        set(),
    )

    correctly_detected = (
        expected_rules & actual_rules
    )

    missing_rules = (
        expected_rules - actual_rules
    )

    unexpected_rules = (
        actual_rules - expected_rules
    )

    return {
        "case_id": case["case_id"],
        "name": case["name"],
        "expected_rules": sorted(expected_rules),
        "actual_rules": sorted(actual_rules),
        "correctly_detected": sorted(correctly_detected),
        "missing_rules": sorted(missing_rules),
        "unexpected_rules": sorted(unexpected_rules),
        "expected_count": len(expected_rules),
        "correct_count": len(correctly_detected),
        "coverage": (
            len(correctly_detected)
            / len(expected_rules)
            if expected_rules
            else 1.0
        ),
    }


# ---------------------------------------------------------
# EVALUATE BENIGN CASES
# ---------------------------------------------------------

def evaluate_benign_case(
    case: dict[str, Any],
) -> dict[str, Any]:

    events = normalize_events(
        case["events"]
    )

    findings = detect(events)

    actual_rules = {
        finding["rule_id"]
        for finding in findings
    }

    return {
        "case_id": case["case_id"],
        "name": case["name"],
        "actual_rules": sorted(actual_rules),
        "clean": len(actual_rules) == 0,
    }


# ---------------------------------------------------------
# RUN COMPLETE RULE EVALUATION
# ---------------------------------------------------------

def run_rule_evaluation() -> dict[str, Any]:

    attack_cases = get_attack_cases()
    benign_cases = get_benign_cases()

    attack_results = [
        evaluate_attack_case(case)
        for case in attack_cases
    ]

    benign_results = [
        evaluate_benign_case(case)
        for case in benign_cases
    ]

    total_expected = sum(
        result["expected_count"]
        for result in attack_results
    )

    total_correct = sum(
        result["correct_count"]
        for result in attack_results
    )

    overall_coverage = (
        total_correct / total_expected
        if total_expected
        else 0.0
    )

    benign_clean = sum(
        1
        for result in benign_results
        if result["clean"]
    )

    return {
        "attack_results": attack_results,
        "benign_results": benign_results,
        "total_expected_rules": total_expected,
        "total_correct_rules": total_correct,
        "overall_rule_coverage": overall_coverage,
        "benign_clean_cases": benign_clean,
        "total_benign_cases": len(benign_results),
    }


# ---------------------------------------------------------
# CLI
# ---------------------------------------------------------

def main() -> None:

    evaluation = run_rule_evaluation()

    print("\n" + "=" * 65)
    print("AI SOC COPILOT — RULE-LEVEL DETECTION EVALUATION")
    print("=" * 65)

    print("\nATTACK RULE COVERAGE")
    print("-" * 65)

    for result in evaluation["attack_results"]:

        print(
            f"{result['case_id']:<25}"
            f"{result['correct_count']}/"
            f"{result['expected_count']} rules"
            f"  Coverage: "
            f"{result['coverage']:.0%}"
        )

        print(
            f"  Expected : "
            f"{', '.join(result['expected_rules'])}"
        )

        print(
            f"  Actual   : "
            f"{', '.join(result['actual_rules'])}"
        )

        if result["missing_rules"]:
            print(
                f"  MISSING  : "
                f"{', '.join(result['missing_rules'])}"
            )

        if result["unexpected_rules"]:
            print(
                f"  UNEXPECTED: "
                f"{', '.join(result['unexpected_rules'])}"
            )

        print()

    print("BENIGN CASES")
    print("-" * 65)

    for result in evaluation["benign_results"]:

        status = (
            "CLEAN"
            if result["clean"]
            else "ALERT TRIGGERED"
        )

        rules = (
            ", ".join(result["actual_rules"])
            if result["actual_rules"]
            else "None"
        )

        print(
            f"{result['case_id']:<25}"
            f"{status:<18}"
            f"Rules: {rules}"
        )

    print("\nOVERALL")
    print("-" * 65)

    print(
        f"Expected rules : "
        f"{evaluation['total_expected_rules']}"
    )

    print(
        f"Correct rules  : "
        f"{evaluation['total_correct_rules']}"
    )

    print(
        f"Rule coverage  : "
        f"{evaluation['overall_rule_coverage']:.2%}"
    )

    print(
        f"Benign clean   : "
        f"{evaluation['benign_clean_cases']}/"
        f"{evaluation['total_benign_cases']}"
    )

    print("=" * 65)


if __name__ == "__main__":
    main()