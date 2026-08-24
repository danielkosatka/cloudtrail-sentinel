"""Read CloudTrail records from local disk."""

import gzip
import json
from pathlib import Path
from typing import Iterator


def read_file(path: Path) -> list[dict]:
    """Return the Records list from one CloudTrail file."""
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as f:
            data = json.load(f)
    else:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
    return data.get("Records", [])


def read_directory(directory: Path) -> Iterator[dict]:
    """Yield every CloudTrail record found under a directory."""
    for pattern in ("*.json", "*.json.gz"):
        for path in sorted(directory.rglob(pattern)):
            for record in read_file(path):
                yield record