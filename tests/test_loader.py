"""Tests for the rule loader: load_rule validation and load_rules.

tmp_path is a built-in pytest fixture: a fresh empty folder for each
test, deleted afterwards. The tests write small rule files into it.
"""

import logging

import pytest

from src.detect.loader import RuleError, load_rule, load_rules

VALID_RULE = """\
id: example_rule
description: An example rule
mitre_attack: T1078.004
severity: high
condition:
  event_name: ConsoleLogin
"""


def write(folder, name, text):
    """Write a rule file into the temp folder and return its path."""
    path = folder / name
    path.write_text(text, encoding="utf-8")
    return path


# --- load_rule -------------------------------------------------------------

def test_valid_rule_loads(tmp_path):
    rule = load_rule(write(tmp_path, "example_rule.yaml", VALID_RULE))
    assert rule == {
        "id": "example_rule",
        "description": "An example rule",
        "mitre_attack": "T1078.004",
        "severity": "high",
        "condition": {"event_name": "ConsoleLogin"},
    }


def test_path_can_be_a_string(tmp_path):
    path = write(tmp_path, "example_rule.yaml", VALID_RULE)
    assert load_rule(str(path))["id"] == "example_rule"


def test_empty_file_rejected(tmp_path):
    with pytest.raises(RuleError, match="empty.yaml: file is empty"):
        load_rule(write(tmp_path, "empty.yaml", ""))


def test_non_mapping_rejected(tmp_path):
    with pytest.raises(RuleError, match="expected key/value pairs, got str"):
        load_rule(write(tmp_path, "scalar.yaml", "hello"))


def test_missing_keys_rejected_and_named(tmp_path):
    path = write(tmp_path, "partial.yaml", "id: partial\nseverity: low\n")
    with pytest.raises(RuleError, match="missing required keys: condition, description, mitre_attack"):
        load_rule(path)


def test_invalid_severity_rejected(tmp_path):
    path = write(tmp_path, "typo.yaml", VALID_RULE.replace("high", "hihg"))
    with pytest.raises(RuleError, match="invalid severity 'hihg'"):
        load_rule(path)


def test_empty_condition_rejected(tmp_path):
    # A rule with no conditions would match every single event.
    text = VALID_RULE.replace("condition:\n  event_name: ConsoleLogin\n", "condition: {}\n")
    with pytest.raises(RuleError, match="condition must be a non-empty"):
        load_rule(write(tmp_path, "no_condition.yaml", text))


def test_non_mapping_condition_rejected(tmp_path):
    text = VALID_RULE.replace("condition:\n  event_name: ConsoleLogin\n", "condition: ConsoleLogin\n")
    with pytest.raises(RuleError, match="condition must be a non-empty"):
        load_rule(write(tmp_path, "bad_condition.yaml", text))


def test_invalid_yaml_syntax_rejected(tmp_path):
    with pytest.raises(RuleError, match="broken.yaml: invalid YAML syntax"):
        load_rule(write(tmp_path, "broken.yaml", "id: [unclosed\n"))


# --- load_rules ------------------------------------------------------------

def test_load_rules_skips_broken_files_with_a_warning(tmp_path, caplog, capsys):
    write(tmp_path, "good.yaml", VALID_RULE)
    write(tmp_path, "empty.yaml", "")

    with caplog.at_level(logging.WARNING):
        rules = load_rules(tmp_path)

    assert [rule["id"] for rule in rules] == ["example_rule"]
    assert "empty.yaml: file is empty" in caplog.text
    assert "Loaded 1 rules, skipped 1" in capsys.readouterr().out


def test_load_rules_strict_stops_at_first_broken_file(tmp_path):
    write(tmp_path, "good.yaml", VALID_RULE)
    write(tmp_path, "empty.yaml", "")

    with pytest.raises(RuleError, match="empty.yaml"):
        load_rules(tmp_path, strict=True)


def test_load_rules_only_reads_yaml_files(tmp_path):
    write(tmp_path, "good.yaml", VALID_RULE)
    write(tmp_path, "notes.txt", "not a rule")

    assert len(load_rules(tmp_path, strict=True)) == 1


def test_load_rules_loads_in_filename_order(tmp_path):
    write(tmp_path, "b.yaml", VALID_RULE.replace("example_rule", "second"))
    write(tmp_path, "a.yaml", VALID_RULE.replace("example_rule", "first"))

    assert [rule["id"] for rule in load_rules(tmp_path)] == ["first", "second"]


def test_load_rules_empty_directory(tmp_path):
    assert load_rules(tmp_path) == []
