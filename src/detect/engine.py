import re
from dataclasses import dataclass

from dataclasses import dataclass


@dataclass
class Alert:
    rule_id: str
    severity: str
    mitre_attack: str
    description: str
    event: object


def evaluate(events, rules):
    """Check every event against every rule and return a list of Alerts."""
    alerts = []
    for event in events:
        for rule in rules:
            if matches(event, rule):
                alerts.append(Alert(
                    rule_id=rule["id"],
                    severity=rule["severity"],
                    mitre_attack=rule["mitre_attack"],
                    description=rule["description"],
                    event=event,
                ))
    return alerts

def get_field(event, name):
    """Return the value of a field on an event, or None if it's missing."""
    if name.startswith("raw["):
        keys = re.findall(r"\[([^\]]+)\]", name)
        # keys is now ["requestParameters", "policyArn"]
        value = event.raw
        for key in keys:
            if not isinstance(value, dict) or key not in value:
                return None
            value = value[key]
        return value
    return getattr(event, name, None)

def matches(event, rule):
    """Return True if the event satisfies every field in the rule's condition."""
    for field, expected in rule["condition"].items():
        actual = get_field(event, field)

        if isinstance(expected, dict):
            if "not_in" in expected:
                if actual in expected["not_in"]:
                    return False
            else:
                raise ValueError(f"unknown operator in rule {rule['id']}: {list(expected)}")
        elif isinstance(expected, list):
            if actual not in expected:
                return False
        else:
            if actual != expected:
                return False
    return True

@dataclass
class Alert:
    rule_id: str
    severity: str
    mitre_attack: str
    description: str
    event: object


def evaluate(events, rules):
    """Check every event against every rule and return a list of Alerts."""
    alerts = []
    for event in events:
        for rule in rules:
            if matches(event, rule):
                alerts.append(Alert(
                    rule_id=rule["id"],
                    severity=rule["severity"],
                    mitre_attack=rule["mitre_attack"],
                    description=rule["description"],
                    event=event,
                ))
    return alerts