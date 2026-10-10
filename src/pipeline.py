"""Read, normalise, detect, print alerts."""

import argparse
from pathlib import Path

from src.ingest.reader import read_directory
from src.normalise.cloudtrail import normalise
from src.detect.loader import load_rules
from src.detect.engine import evaluate


def main() -> None:
    parser = argparse.ArgumentParser(description="CloudTrail Sentinel")
    parser.add_argument("--input", required=True, type=Path)
    args = parser.parse_args()

    events = [normalise(record) for record in read_directory(args.input)]
    rules = load_rules("rules")
    alerts = evaluate(events, rules)

    for alert in alerts:
        print(
            f"[{alert.severity.upper():<8}] {alert.rule_id:<22} "
            f"{alert.mitre_attack:<10} {alert.event.event_name:<18} "
            f"{alert.event.actor_name}"
        )

    print(f"\n{len(events)} events, {len(alerts)} alerts")


if __name__ == "__main__":
    main()