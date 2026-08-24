"""Phase 1: read, normalise, print."""

import argparse
from pathlib import Path

from src.ingest.reader import read_directory
from src.normalise.cloudtrail import normalise


def main() -> None:
    parser = argparse.ArgumentParser(description="CloudTrail Sentinel")
    parser.add_argument("--input", required=True, type=Path)
    args = parser.parse_args()

    count = 0
    for record in read_directory(args.input):
        event = normalise(record)
        print(
            f"{event.timestamp:%Y-%m-%d %H:%M:%S}  "
            f"{event.outcome:<8} {event.actor_type:<12} "
            f"{str(event.actor_name):<12} {event.event_name:<20} "
            f"{event.region:<15} {event.source_ip}"
        )
        count += 1

    print(f"\n{count} events normalised")


if __name__ == "__main__":
    main()