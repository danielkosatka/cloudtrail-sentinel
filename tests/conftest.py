"""Shared fixtures for the test suite.

pytest loads this file automatically. A fixture is a helper that a test
asks for by naming it as a parameter, e.g. `def test_x(make_event): ...`.
"""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.detect.loader import load_rule
from src.normalise.schema import NormalisedEvent

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def rules_dir():
    """The real rules/ directory in the repository."""
    return REPO_ROOT / "rules"


@pytest.fixture
def sample_logs_dir():
    """The bundled sample CloudTrail logs."""
    return REPO_ROOT / "sample_logs"


@pytest.fixture
def make_event():
    """Build a NormalisedEvent, overriding only the fields a test cares about.

    The defaults describe a boring, benign event (a read-only
    DescribeInstances by an IAM user in an approved region), so a test
    only has to state what makes its event interesting.
    """

    def _make(**overrides):
        fields = dict(
            timestamp=datetime(2026, 8, 14, 8, 31, 12, tzinfo=timezone.utc),
            event_id="test-event",
            event_name="DescribeInstances",
            event_source="ec2.amazonaws.com",
            actor_type="IAMUser",
            actor_name="analyst",
            actor_arn="arn:aws:iam::123456789012:user/analyst",
            account_id="123456789012",
            source_ip="203.0.113.14",
            user_agent="aws-cli/2.15.30",
            region="eu-west-2",
            outcome="success",
            error_code=None,
            mfa_used=None,
            read_only=True,
            raw={},
        )
        fields.update(overrides)
        return NormalisedEvent(**fields)

    return _make


@pytest.fixture
def rule(rules_dir):
    """Load one real rule from rules/ by its id, e.g. rule("root_account_usage")."""

    def _load(rule_id):
        return load_rule(rules_dir / f"{rule_id}.yaml")

    return _load
