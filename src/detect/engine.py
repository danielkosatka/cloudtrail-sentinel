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