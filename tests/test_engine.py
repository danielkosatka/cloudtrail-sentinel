"""Tests for the evaluation engine: get_field, matches and evaluate.

These use small hand-written rules rather than the real ones in rules/,
so a failure here points at the engine and not at a rule file.
"""

import pytest

from src.detect.engine import Alert, evaluate, get_field, matches


def rule_with(condition, rule_id="test_rule"):
    """A minimal valid rule around the given condition."""
    return {
        "id": rule_id,
        "description": "test rule",
        "mitre_attack": "T0000",
        "severity": "low",
        "condition": condition,
    }


# --- get_field -------------------------------------------------------------

def test_get_field_reads_normalised_field(make_event):
    event = make_event(event_name="StopLogging")
    assert get_field(event, "event_name") == "StopLogging"


def test_get_field_unknown_field_returns_none(make_event):
    assert get_field(make_event(), "no_such_field") is None


def test_get_field_reads_nested_raw_path(make_event):
    event = make_event(raw={"requestParameters": {"policyArn": "arn:example"}})
    assert get_field(event, "raw[requestParameters][policyArn]") == "arn:example"


def test_get_field_missing_raw_key_returns_none(make_event):
    event = make_event(raw={"requestParameters": {}})
    assert get_field(event, "raw[requestParameters][policyArn]") is None


def test_get_field_raw_path_through_non_dict_returns_none(make_event):
    # CloudTrail often sets requestParameters to null; that must not crash.
    event = make_event(raw={"requestParameters": None})
    assert get_field(event, "raw[requestParameters][policyArn]") is None


# --- matches ---------------------------------------------------------------

def test_single_value_must_be_equal(make_event):
    rule = rule_with({"event_name": "StopLogging"})
    assert matches(make_event(event_name="StopLogging"), rule)
    assert not matches(make_event(event_name="StartLogging"), rule)


def test_list_means_one_of(make_event):
    rule = rule_with({"event_name": ["StopLogging", "DeleteTrail"]})
    assert matches(make_event(event_name="StopLogging"), rule)
    assert matches(make_event(event_name="DeleteTrail"), rule)
    assert not matches(make_event(event_name="CreateTrail"), rule)


def test_not_in_means_none_of(make_event):
    rule = rule_with({"region": {"not_in": ["eu-west-2", "us-east-1"]}})
    assert matches(make_event(region="ap-southeast-2"), rule)
    assert not matches(make_event(region="eu-west-2"), rule)


def test_every_condition_must_hold(make_event):
    rule = rule_with({"event_name": "ConsoleLogin", "outcome": "success"})
    assert matches(make_event(event_name="ConsoleLogin", outcome="success"), rule)
    assert not matches(make_event(event_name="ConsoleLogin", outcome="failure"), rule)
    assert not matches(make_event(event_name="CreateUser", outcome="success"), rule)


def test_unknown_value_does_not_match_false(make_event):
    # Strict matching: "we don't know if MFA was used" is not "MFA was not used".
    rule = rule_with({"mfa_used": False})
    assert matches(make_event(mfa_used=False), rule)
    assert not matches(make_event(mfa_used=None), rule)


def test_missing_field_does_not_match(make_event):
    rule = rule_with({"raw[requestParameters][policyArn]": "arn:example"})
    assert not matches(make_event(raw={}), rule)


def test_unknown_operator_raises(make_event):
    # A typo in an operator must fail loudly, not silently never match.
    rule = rule_with({"region": {"not_inn": ["eu-west-2"]}}, rule_id="typo_rule")
    with pytest.raises(ValueError, match="typo_rule"):
        matches(make_event(), rule)


# --- evaluate --------------------------------------------------------------

def test_evaluate_returns_alert_with_rule_details(make_event):
    event = make_event(event_name="StopLogging")
    rule = {
        "id": "cloudtrail_disabled",
        "description": "CloudTrail logging stopped",
        "mitre_attack": "T1562.008",
        "severity": "critical",
        "condition": {"event_name": "StopLogging"},
    }

    alerts = evaluate([event], [rule])

    assert alerts == [Alert(
        rule_id="cloudtrail_disabled",
        severity="critical",
        mitre_attack="T1562.008",
        description="CloudTrail logging stopped",
        event=event,
    )]


def test_evaluate_no_match_returns_empty_list(make_event):
    rule = rule_with({"event_name": "StopLogging"})
    assert evaluate([make_event()], [rule]) == []


def test_evaluate_one_event_can_raise_several_alerts(make_event):
    event = make_event(event_name="StopLogging", actor_type="Root")
    rules = [
        rule_with({"event_name": "StopLogging"}, rule_id="a"),
        rule_with({"actor_type": "Root"}, rule_id="b"),
        rule_with({"event_name": "CreateUser"}, rule_id="c"),
    ]
    assert [alert.rule_id for alert in evaluate([event], rules)] == ["a", "b"]


def test_evaluate_checks_every_event(make_event):
    events = [
        make_event(event_id="1", event_name="StopLogging"),
        make_event(event_id="2", event_name="DescribeInstances"),
        make_event(event_id="3", event_name="StopLogging"),
    ]
    alerts = evaluate(events, [rule_with({"event_name": "StopLogging"})])
    assert [alert.event.event_id for alert in alerts] == ["1", "3"]
