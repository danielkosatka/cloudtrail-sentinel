import re

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

        if isinstance(expected, list):
            if actual not in expected:
                return False
        else:
            if actual != expected:
                return False

    return True