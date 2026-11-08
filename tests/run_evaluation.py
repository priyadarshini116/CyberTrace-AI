"""
Run the SOC detection evaluation suite.
"""

from __future__ import annotations

from tests.evaluation import evaluate_dataset
from tests.test_cases import (
    get_attack_cases,
    get_benign_cases,
)


def main() -> None:

    attack_cases = get_attack_cases()
    benign_cases = get_benign_cases()

    attack_events = [
        case["events"]
        for case in attack_cases
    ]

    benign_events = [
        case["events"]
        for case in benign_cases
    ]

    evaluation = evaluate_dataset(
        attack_cases=attack_events,
        benign_cases=benign_events,
    )

    metrics = evaluation["metrics"]
    results = evaluation["results"]

    print("\n" + "=" * 60)
    print("AI SOC COPILOT — DETECTION EVALUATION")
    print("=" * 60)

    print("\nCONFUSION MATRIX")
    print("-" * 30)

    print(
        f"True Positives : {metrics['true_positive']}"
    )

    print(
        f"False Positives: {metrics['false_positive']}"
    )

    print(
        f"True Negatives : {metrics['true_negative']}"
    )

    print(
        f"False Negatives: {metrics['false_negative']}"
    )

    print("\nMETRICS")
    print("-" * 30)

    print(
        f"Precision          : {metrics['precision']:.2%}"
    )

    print(
        f"Recall             : {metrics['recall']:.2%}"
    )

    print(
        f"F1 Score           : {metrics['f1_score']:.2%}"
    )

    print(
        f"False Positive Rate: {metrics['false_positive_rate']:.2%}"
    )

    print(
        f"Detection Coverage : {metrics['detection_coverage']:.2%}"
    )

    print(
        f"Total Test Cases   : {metrics['total_cases']}"
    )

    print("\nCASE RESULTS")
    print("-" * 60)

    for result in results:

        print(
            f"{result['case_id']:<35}"
            f"{result['classification']:<5}"
            f"Findings: {result['finding_count']}"
        )

    print("=" * 60)


if __name__ == "__main__":
    main()