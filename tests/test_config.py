import re

import pytest

from conftest import ah


def test_defaults_and_one_level_merge_for_salt_and_llm(config_file):
    path = config_file(settings={"cooldown": 5, "salt": {"url": "http://salt:8000"}, "llm": {"model": "m"}}, rules=[])
    config = ah.load_config(path)
    assert config.settings["cooldown"] == 5
    assert config.settings["dry_run"] is False
    assert config.settings["workers"] == 4
    assert config.settings["salt"]["url"] == "http://salt:8000"
    assert config.settings["salt"]["eauth"] == "pam"  # kept from the defaults
    assert config.settings["llm"]["model"] == "m"
    assert config.settings["llm"]["max_tokens"] == 400
    assert config.rules == []


def test_empty_file_is_a_valid_config(workdir):
    path = workdir / "empty.yaml"
    path.write_text("")
    config = ah.load_config(str(path))
    assert config.rules == [] and config.settings["dry_run"] is False


def test_webhook_token_from_environment_wins(config_file, monkeypatch):
    path = config_file(settings={"auth_token": "from-file"}, rules=[])
    assert ah.load_config(path).settings["auth_token"] == "from-file"
    monkeypatch.setenv("WEBHOOK_TOKEN", "from-env")
    assert ah.load_config(path).settings["auth_token"] == "from-env"


def test_rules_are_normalised(config_file):
    path = config_file(
        settings={"cooldown": 42},
        rules=[
            {"actions": [{"type": "log", "message": "x"}]},
            {"name": "named", "match": {"alertname": "A"}, "match_re": {"severity": "warn.*"}, "status": "any",
             "cooldown": 1, "continue": False, "actions": [{"type": "http", "url": "http://x"}]},
        ],
    )
    first, second = ah.load_config(path).rules
    assert first["name"] == "rule-0"
    assert first["status"] == "firing" and first["cooldown"] == 42 and first["continue"] is True
    assert second["name"] == "named"
    assert isinstance(second["match_re"]["severity"], re.Pattern)
    assert second["status"] == "any" and second["cooldown"] == 1 and second["continue"] is False


def test_rule_without_actions_is_rejected(config_file):
    path = config_file(rules=[{"name": "empty"}])
    with pytest.raises(ValueError, match="'empty' has no actions"):
        ah.load_config(path)


def test_unknown_action_type_is_rejected_with_the_known_list(config_file):
    path = config_file(rules=[{"name": "r", "actions": [{"type": "teleport"}]}])
    with pytest.raises(ValueError, match="unknown action type 'teleport'") as error:
        ah.load_config(path)
    assert "k8s_rollout_restart" in str(error.value) and "llm" in str(error.value)


def test_broken_yaml_raises(workdir):
    path = workdir / "broken.yaml"
    path.write_text("settings: [unclosed\n")
    with pytest.raises(Exception):
        ah.load_config(str(path))


def _rule(**overrides):
    rule = {"name": "r", "match": {}, "match_re": {}, "status": "firing", "cooldown": 0, "continue": True, "actions": []}
    rule.update(overrides)
    return rule


def test_matches_status():
    firing = {"status": "firing", "labels": {}}
    resolved = {"status": "resolved", "labels": {}}
    assert ah.matches(_rule(), firing)
    assert not ah.matches(_rule(), resolved)
    assert ah.matches(_rule(status="any"), resolved)
    assert ah.matches(_rule(status="resolved"), resolved)


def test_matches_exact_labels_are_anded():
    rule = _rule(match={"alertname": "A", "team": "db"})
    assert ah.matches(rule, {"status": "firing", "labels": {"alertname": "A", "team": "db", "x": "y"}})
    assert not ah.matches(rule, {"status": "firing", "labels": {"alertname": "A"}})


def test_matches_regex_is_a_full_match():
    rule = _rule(match_re={"severity": re.compile("warning|critical")})
    assert ah.matches(rule, {"status": "firing", "labels": {"severity": "critical"}})
    assert not ah.matches(rule, {"status": "firing", "labels": {"severity": "critical-ish"}})
    assert not ah.matches(rule, {"status": "firing", "labels": {}})
