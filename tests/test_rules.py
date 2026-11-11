"""Tests for the real detection rules in rules/.

Every rule gets at least one event that must match (positive) and one
similar event that must not (negative). The negative tests matter as
much as the positive ones: they are what stops a rule turning into noise.
"""

import re
from pathlib import Path

import pytest

from src.detect.engine import matches
from src.detect.loader import load_rule

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

# Zero-byte files are placeholders for planned rules (the loader skips them
# with a warning), so they are left out of the checks below.
RULE_FILES = sorted(p for p in RULES_DIR.glob("*.yaml") if p.stat().st_size > 0)

EXPECTED_RULES = {
    "admin_policy_attached",
    "cloudtrail_disabled",
    "console_login_mfa",
    "guardduty_disabled",
    "root_account_usage",
    "unapproved_region",
}

ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"


# --- rule files ------------------------------------------------------------

def test_all_expected_rules_exist():
    # Fails if a rule file is deleted or renamed by accident.
    assert EXPECTED_RULES <= {path.stem for path in RULE_FILES}


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.stem)
def test_rule_file_is_valid(path):
    rule = load_rule(path)  # raises RuleError if the file is malformed
    assert rule["id"] == path.stem, "rule id should match its filename"
    assert re.fullmatch(r"T\d{4}(\.\d{3})?", rule["mitre_attack"]), "not an ATT&CK technique id"


# --- root_account_usage ----------------------------------------------------

def test_root_account_usage_fires_on_root(make_event, rule):
    event = make_event(actor_type="Root", actor_name="root", event_name="CreateUser")
    assert matches(event, rule("root_account_usage"))


def test_root_account_usage_ignores_iam_user(make_event, rule):
    event = make_event(actor_type="IAMUser", event_name="CreateUser")
    assert not matches(event, rule("root_account_usage"))


# --- console_login_mfa -----------------------------------------------------

def test_console_login_mfa_fires_on_successful_login_without_mfa(make_event, rule):
    event = make_event(event_name="ConsoleLogin", outcome="success", mfa_used=False)
    assert matches(event, rule("console_login_mfa"))


def test_console_login_mfa_ignores_login_with_mfa(make_event, rule):
    event = make_event(event_name="ConsoleLogin", outcome="success", mfa_used=True)
    assert not matches(event, rule("console_login_mfa"))


def test_console_login_mfa_ignores_failed_login(make_event, rule):
    # MFA is never reached when the password step fails.
    event = make_event(event_name="ConsoleLogin", outcome="failure", mfa_used=False)
    assert not matches(event, rule("console_login_mfa"))


def test_console_login_mfa_ignores_unknown_mfa(make_event, rule):
    event = make_event(event_name="ConsoleLogin", outcome="success", mfa_used=None)
    assert not matches(event, rule("console_login_mfa"))


# --- cloudtrail_disabled ---------------------------------------------------

@pytest.mark.parametrize("event_name", ["StopLogging", "DeleteTrail"])
def test_cloudtrail_disabled_fires(make_event, rule, event_name):
    assert matches(make_event(event_name=event_name), rule("cloudtrail_disabled"))


@pytest.mark.parametrize("event_name", ["StartLogging", "DescribeTrails"])
def test_cloudtrail_disabled_ignores_other_trail_calls(make_event, rule, event_name):
    assert not matches(make_event(event_name=event_name), rule("cloudtrail_disabled"))


# --- guardduty_disabled ----------------------------------------------------

def test_guardduty_disabled_fires_on_delete_detector(make_event, rule):
    assert matches(make_event(event_name="DeleteDetector"), rule("guardduty_disabled"))


def test_guardduty_disabled_ignores_create_detector(make_event, rule):
    assert not matches(make_event(event_name="CreateDetector"), rule("guardduty_disabled"))


# --- admin_policy_attached -------------------------------------------------

def test_admin_policy_attached_fires_on_administrator_access(make_event, rule):
    event = make_event(
        event_name="AttachUserPolicy",
        raw={"requestParameters": {"userName": "backup-svc", "policyArn": ADMIN_POLICY}},
    )
    assert matches(event, rule("admin_policy_attached"))


def test_admin_policy_attached_ignores_other_policies(make_event, rule):
    event = make_event(
        event_name="AttachUserPolicy",
        raw={"requestParameters": {"policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}},
    )
    assert not matches(event, rule("admin_policy_attached"))


def test_admin_policy_attached_ignores_event_without_request_parameters(make_event, rule):
    event = make_event(event_name="AttachUserPolicy", raw={"requestParameters": None})
    assert not matches(event, rule("admin_policy_attached"))


# --- unapproved_region -----------------------------------------------------

def test_unapproved_region_fires_outside_allowlist(make_event, rule):
    event = make_event(event_name="RunInstances", region="ap-southeast-2")
    assert matches(event, rule("unapproved_region"))


@pytest.mark.parametrize("region", ["eu-west-2", "us-east-1"])
def test_unapproved_region_ignores_approved_regions(make_event, rule, region):
    event = make_event(event_name="RunInstances", region=region)
    assert not matches(event, rule("unapproved_region"))


def test_unapproved_region_ignores_other_calls(make_event, rule):
    # Only launching instances counts; a read-only call elsewhere is not an alert.
    event = make_event(event_name="DescribeInstances", region="ap-southeast-2")
    assert not matches(event, rule("unapproved_region"))
