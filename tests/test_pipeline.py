"""Tests for ingestion and the pipeline end to end.

The end-to-end test is a regression check: the bundled sample logs must
keep producing exactly the same five alerts.
"""

import gzip
import json
import sys

from src import pipeline
from src.detect.engine import evaluate
from src.detect.loader import load_rules
from src.ingest.reader import read_directory, read_file
from src.normalise.cloudtrail import normalise


def cloudtrail_json(*event_ids):
    """The text of a CloudTrail file holding one record per id."""
    return json.dumps({"Records": [{"eventID": event_id} for event_id in event_ids]})


# --- ingestion -------------------------------------------------------------

def test_read_file_plain_json(tmp_path):
    path = tmp_path / "log.json"
    path.write_text(cloudtrail_json("a", "b"), encoding="utf-8")
    assert [r["eventID"] for r in read_file(path)] == ["a", "b"]


def test_read_file_gzip(tmp_path):
    path = tmp_path / "log.json.gz"
    with gzip.open(path, "wt", encoding="utf-8") as f:
        f.write(cloudtrail_json("a"))
    assert [r["eventID"] for r in read_file(path)] == ["a"]


def test_read_file_without_records_key(tmp_path):
    path = tmp_path / "log.json"
    path.write_text("{}", encoding="utf-8")
    assert read_file(path) == []


def test_read_directory_recurses_and_reads_both_formats(tmp_path):
    # CloudTrail in S3 nests files by account/region/date.
    nested = tmp_path / "123456789012" / "eu-west-2"
    nested.mkdir(parents=True)
    (tmp_path / "top.json").write_text(cloudtrail_json("plain"), encoding="utf-8")
    with gzip.open(nested / "deep.json.gz", "wt", encoding="utf-8") as f:
        f.write(cloudtrail_json("gzipped"))

    ids = {r["eventID"] for r in read_directory(tmp_path)}
    assert ids == {"plain", "gzipped"}


# --- end to end ------------------------------------------------------------

def test_sample_logs_raise_the_expected_alerts(sample_logs_dir, rules_dir):
    events = [normalise(r) for r in read_directory(sample_logs_dir)]
    alerts = evaluate(events, load_rules(rules_dir))

    assert len(events) == 8
    raised = sorted((a.rule_id, a.event.event_name, a.event.actor_name) for a in alerts)
    assert raised == [
        ("admin_policy_attached", "AttachUserPolicy", "DeployRole"),
        ("cloudtrail_disabled", "StopLogging", "backup-svc"),
        ("console_login_mfa", "ConsoleLogin", "contractor"),
        ("root_account_usage", "CreateUser", "root"),
        ("unapproved_region", "RunInstances", "backup-svc"),
    ]


def test_pipeline_main_prints_summary(sample_logs_dir, monkeypatch, capsys):
    # main() loads rules from ./rules, so run it from the repository root.
    monkeypatch.chdir(sample_logs_dir.parent)
    monkeypatch.setattr(sys, "argv", ["pipeline", "--input", str(sample_logs_dir)])

    pipeline.main()

    out = capsys.readouterr().out
    assert "[CRITICAL] cloudtrail_disabled" in out
    assert "8 events, 5 alerts" in out
