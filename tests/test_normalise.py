"""Tests for CloudTrail normalisation.

Rules trust the normalised fields, so the three derived ones (outcome,
mfa_used, actor_name) are checked for each way CloudTrail reports them.
"""

from datetime import datetime, timezone

from src.normalise.cloudtrail import normalise


def record(**fields):
    """A minimal raw CloudTrail record; tests add only what they need."""
    base = {
        "eventTime": "2026-08-14T09:02:44Z",
        "eventName": "DescribeInstances",
        "eventSource": "ec2.amazonaws.com",
        "userIdentity": {"type": "IAMUser", "userName": "analyst"},
    }
    base.update(fields)
    return base


def test_basic_fields_are_copied():
    raw = record(
        eventID="e-1",
        awsRegion="eu-west-2",
        sourceIPAddress="203.0.113.14",
        recipientAccountId="123456789012",
        readOnly=True,
    )
    event = normalise(raw)

    assert event.event_id == "e-1"
    assert event.event_name == "DescribeInstances"
    assert event.event_source == "ec2.amazonaws.com"
    assert event.actor_type == "IAMUser"
    assert event.region == "eu-west-2"
    assert event.source_ip == "203.0.113.14"
    assert event.account_id == "123456789012"
    assert event.read_only is True
    assert event.raw is raw  # original kept for investigation


def test_timestamp_is_parsed_as_utc():
    event = normalise(record(eventTime="2026-08-14T09:02:44Z"))
    assert event.timestamp == datetime(2026, 8, 14, 9, 2, 44, tzinfo=timezone.utc)


# --- outcome ---------------------------------------------------------------

def test_outcome_console_login_success():
    event = normalise(record(eventName="ConsoleLogin", responseElements={"ConsoleLogin": "Success"}))
    assert event.outcome == "success"


def test_outcome_console_login_failure():
    event = normalise(record(eventName="ConsoleLogin", responseElements={"ConsoleLogin": "Failure"}))
    assert event.outcome == "failure"


def test_outcome_api_call_with_error_code_is_failure():
    event = normalise(record(errorCode="AccessDenied", responseElements=None))
    assert event.outcome == "failure"
    assert event.error_code == "AccessDenied"


def test_outcome_api_call_without_error_code_is_success():
    assert normalise(record(responseElements=None)).outcome == "success"


# --- mfa_used --------------------------------------------------------------

def test_mfa_used_from_console_login():
    assert normalise(record(additionalEventData={"MFAUsed": "Yes"})).mfa_used is True
    assert normalise(record(additionalEventData={"MFAUsed": "No"})).mfa_used is False


def test_mfa_used_from_assumed_role_session():
    def assumed_role(flag):
        return record(userIdentity={
            "type": "AssumedRole",
            "sessionContext": {"attributes": {"mfaAuthenticated": flag}},
        })

    assert normalise(assumed_role("true")).mfa_used is True
    assert normalise(assumed_role("false")).mfa_used is False


def test_mfa_used_is_none_when_event_does_not_say():
    assert normalise(record()).mfa_used is None


# --- actor_name ------------------------------------------------------------

def test_actor_name_root():
    event = normalise(record(userIdentity={"type": "Root", "principalId": "123456789012"}))
    assert event.actor_name == "root"


def test_actor_name_iam_user():
    assert normalise(record()).actor_name == "analyst"


def test_actor_name_assumed_role_uses_role_name():
    event = normalise(record(userIdentity={
        "type": "AssumedRole",
        "principalId": "AROAEXAMPLE:deploy-session",
        "sessionContext": {"sessionIssuer": {"userName": "DeployRole"}},
    }))
    assert event.actor_name == "DeployRole"


def test_actor_name_falls_back_to_principal_id():
    event = normalise(record(userIdentity={"type": "AWSService", "principalId": "AIDAEXAMPLE"}))
    assert event.actor_name == "AIDAEXAMPLE"
