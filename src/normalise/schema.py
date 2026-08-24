"""Normalised event schema.

Every log source is converted into this shape before detection rules
see it. Rules depend on this contract, not on any source format.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class NormalisedEvent:
    timestamp: datetime
    event_id: str
    event_name: str
    event_source: str
    actor_type: str
    actor_name: Optional[str]
    actor_arn: Optional[str]
    account_id: Optional[str]
    source_ip: Optional[str]
    user_agent: Optional[str]
    region: Optional[str]
    outcome: str
    error_code: Optional[str]
    mfa_used: Optional[bool]
    read_only: Optional[bool]
    raw: dict[str, Any] = field(repr=False, default_factory=dict)