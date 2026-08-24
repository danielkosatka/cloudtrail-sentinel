"""Convert CloudTrail records into NormalisedEvent objects."""

from datetime import datetime
from typing import Optional

from src.normalise.schema import NormalisedEvent


def _parse_time(value: str) -> datetime:
    """CloudTrail timestamps look like 2026-08-14T09:02:44Z."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _outcome(record: dict) -> str:
    """Determine success or failure.

    Console logins report the result in responseElements.
    Ordinary API calls signal failure via the presence of errorCode.
    """
    response = record.get("responseElements") or {}
    console_result = response.get("ConsoleLogin")
    if console_result:
        return "success" if console_result == "Success" else "failure"
    return "failure" if record.get("errorCode") else "success"


def _mfa_used(record: dict) -> Optional[bool]:
    """Return True, False, or None where the event does not say.

    Console logins  -> additionalEventData.MFAUsed  ("Yes"/"No")
    Assumed roles   -> sessionContext.attributes.mfaAuthenticated
                       ("true"/"false" as strings, not booleans)
    """
    additional = record.get("additionalEventData") or {}
    if "MFAUsed" in additional:
        return additional["MFAUsed"] == "Yes"

    identity = record.get("userIdentity") or {}
    attributes = (identity.get("sessionContext") or {}).get("attributes") or {}
    if "mfaAuthenticated" in attributes:
        return attributes["mfaAuthenticated"] == "true"

    return None


def _actor_name(record: dict) -> Optional[str]:
    """Return a human-readable name for whoever performed the action."""
    identity = record.get("userIdentity") or {}
    identity_type = identity.get("type")

    if identity_type == "Root":
        return "root"

    if identity_type == "AssumedRole":
        session_context = identity.get("sessionContext") or {}
        issuer = session_context.get("sessionIssuer") or {}
        issuer_name = issuer.get("userName")
        if issuer_name:
            return issuer_name

    return identity.get("userName") or identity.get("principalId")


def normalise(record: dict) -> NormalisedEvent:
    """Build a NormalisedEvent from one raw CloudTrail record."""
    identity = record.get("userIdentity") or {}

    return NormalisedEvent(
        timestamp=_parse_time(record["eventTime"]),
        event_id=record.get("eventID", ""),
        event_source=record.get("eventSource", ""),
        event_name=record.get("eventName", ""),
        actor_type=identity.get("type", "Unknown"),
        actor_name=_actor_name(record),
        actor_arn=identity.get("arn"),
        account_id=record.get("recipientAccountId") or identity.get("accountId"),
        source_ip=record.get("sourceIPAddress"),
        user_agent=record.get("userAgent"),
        region=record.get("awsRegion"),
        outcome=_outcome(record),
        error_code=record.get("errorCode"),
        mfa_used=_mfa_used(record),
        read_only=record.get("readOnly"),
        raw=record,
    )