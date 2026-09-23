"""Load and validate YAML detection rules."""
# ^ A docstring: a description of the whole file. Python stores it,
#   and tools like VS Code show it when you hover over the module.

from pathlib import Path   # Path = modern, cross-platform way to handle file paths

import yaml                # PyYAML: turns YAML text into Python objects (dicts, lists, strings)

# Constants: values that never change while the program runs.
# UPPER_CASE names are the Python convention for "don't modify this".
# The curly braces make these SETS: unordered collections of unique items,
# which are fast to check membership against and support set maths (used below).
REQUIRED_KEYS = {"id", "description", "mitre_attack", "severity", "condition"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}


class RuleError(Exception):
    """Raised when a rule file is empty or malformed."""
    # A custom exception: our own named error type.
    # "(Exception)" means it inherits from Python's built-in Exception,
    # so it behaves like any normal error, but with a specific name.
    # Later, the pipeline can catch RuleError specifically ("skip this broken
    # rule and warn") without accidentally swallowing unrelated bugs.


def load_rule(path):
    """Read one YAML rule file, check it's valid, and return it as a dict."""

    # Accept either a string ('rules/x.yaml') or a Path, and convert to a Path
    # so we can use handy features like path.name below.
    path = Path(path)

    # "with" opens the file and GUARANTEES it's closed afterwards, even if an
    # error happens partway through. "as f" gives us a handle to read from.
    # encoding="utf-8" avoids Windows reading the file with the wrong text encoding.
    with path.open(encoding="utf-8") as f:
        # safe_load parses YAML into Python objects. "safe" = it will only build
        # basic types (dicts, lists, strings, numbers). The unsafe version can
        # execute code embedded in a file: a real deserialisation vulnerability.
        rule = yaml.safe_load(f)

    # --- Validation: check the rule is usable, failing loudly if not ---
    # Each check "raises" (throws) a RuleError that names the file and the
    # problem. A rule that silently fails to load = a detection gap nobody sees.

    # Check 1: an empty file parses to None (Python's "nothing" value).
    if rule is None:
        raise RuleError(f"{path.name}: file is empty")
        # f"..." is an f-string: {path.name} inside it gets replaced
        # with the actual filename, e.g. "console_brute_force.yaml".

    # Check 2: a rule must be key/value pairs (a dict). A file containing
    # just "hello" is valid YAML, but parses to a string, not a rule.
    # isinstance(x, dict) asks "is x a dictionary?"
    if not isinstance(rule, dict):
        raise RuleError(f"{path.name}: expected key/value pairs, got {type(rule).__name__}")

    # Check 3: all five required keys must be present.
    # Set difference: (everything required) minus (everything present)
    # leaves exactly what's missing. Empty set = nothing missing.
    missing = REQUIRED_KEYS - rule.keys()
    if missing:   # an empty set counts as False, a non-empty set as True
        # sorted() puts them in alphabetical order; ", ".join() glues them
        # into one readable string: "condition, description, id"
        raise RuleError(f"{path.name}: missing required keys: {', '.join(sorted(missing))}")

    # Check 4: severity must be one of our agreed values, catching typos like "hihg".
    if rule["severity"] not in VALID_SEVERITIES:
        raise RuleError(f"{path.name}: invalid severity '{rule['severity']}'")

    # Check 5: condition must be a dict with at least one field: value pair.
    # "not rule['condition']" catches an empty dict {}, because a rule with
    # no conditions would match EVERY event and flood the dashboard with alerts.
    if not isinstance(rule["condition"], dict) or not rule["condition"]:
        raise RuleError(f"{path.name}: condition must be a non-empty set of field: value pairs")

    # All checks passed: hand the rule back to whoever called this function.
    return rule