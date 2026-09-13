from conftest import ah, alert, metric, payload


def dispatcher(config_file, settings=None, rules=None):
    return ah.Dispatcher(ah.load_config(config_file(settings=settings, rules=rules)))


def test_matching_rules_queue_their_actions(config_file, pool):
    d = dispatcher(config_file, rules=[
        {"name": "everything", "status": "any", "cooldown": 0, "actions": [{"type": "log", "message": "{{ labels.alertname }}"}]},
        {"name": "critical-only", "match": {"severity": "critical"}, "cooldown": 0,
         "actions": [{"type": "log", "message": "a"}, {"type": "log", "message": "b"}]},
    ])
    before = metric("alert_handler_rule_matches_total", rule="critical-only")
    queued = d.handle_payload(payload(alert(severity="critical"), alert(severity="warning", alertname="Other")), pool)
    assert queued == 1 + 2 + 1  # everything x2, critical-only x1
    assert pool.submitted == 3
    assert metric("alert_handler_rule_matches_total", rule="critical-only") == before + 1


def test_continue_false_stops_at_the_first_match(config_file, pool):
    d = dispatcher(config_file, rules=[
        {"name": "first", "continue": False, "cooldown": 0, "actions": [{"type": "log", "message": "1"}]},
        {"name": "second", "cooldown": 0, "actions": [{"type": "log", "message": "2"}]},
    ])
    assert d.handle_payload(payload(alert()), pool) == 1


def test_cooldown_silences_a_repeated_alert(config_file, pool):
    d = dispatcher(config_file, rules=[{"name": "r", "cooldown": 600, "actions": [{"type": "log", "message": "x"}]}])
    before = metric("alert_handler_actions_total", rule="r", action="log", result="cooldown")
    assert d.handle_payload(payload(alert()), pool) == 1
    assert d.handle_payload(payload(alert()), pool) == 0
    assert metric("alert_handler_actions_total", rule="r", action="log", result="cooldown") == before + 1
    assert d.handle_payload(payload(alert(alertname="Different")), pool) == 1  # another fingerprint


def test_dry_run_counts_but_touches_nothing(config_file, pool, caplog):
    d = dispatcher(config_file, settings={"dry_run": True},
                   rules=[{"name": "r", "cooldown": 0, "actions": [{"type": "http", "url": "http://127.0.0.1:9/never"}]}])
    before = metric("alert_handler_actions_total", rule="r", action="http", result="dry_run")
    with caplog.at_level("INFO", logger="alert-handler"):
        d.handle_payload(payload(alert()), pool)
    assert metric("alert_handler_actions_total", rule="r", action="http", result="dry_run") == before + 1
    assert "[dry-run] rule r would run http" in caplog.text


def test_actions_chain_through_the_shared_namespace(config_file, pool, workdir, caplog):
    (workdir / "runbooks" / "collect.sh").write_text("#!/bin/sh\necho \"load is high on $ALERT_LABEL_POD\"\n")
    d = dispatcher(config_file, rules=[{"name": "chain", "cooldown": 0, "actions": [
        {"type": "runbook", "name": "collect.sh"},
        {"type": "log", "message": "context: {{ last.stdout }} (exit {{ last.exit_code }})"},
    ]}])
    with caplog.at_level("INFO", logger="alert-handler"):
        d.handle_payload(payload(alert(pod="p-1")), pool)
    assert "[action:log] context: load is high on p-1 (exit 0)" in caplog.text
    assert metric("alert_handler_actions_total", rule="chain", action="runbook", result="success") >= 1


def test_a_failed_action_stops_the_chain_unless_told_otherwise(config_file, pool, caplog):
    d = dispatcher(config_file, rules=[
        {"name": "stops", "cooldown": 0, "actions": [{"type": "exec", "command": "exit 1"}, {"type": "log", "message": "never"}]},
        {"name": "goes-on", "cooldown": 0, "actions": [{"type": "exec", "command": "exit 1", "continue_on_error": True}, {"type": "log", "message": "still"}]},
    ])
    skipped = metric("alert_handler_actions_total", rule="stops", action="log", result="skipped")
    with caplog.at_level("INFO", logger="alert-handler"):
        d.handle_payload(payload(alert()), pool)
    assert metric("alert_handler_actions_total", rule="stops", action="log", result="skipped") == skipped + 1
    assert "[action:log] never" not in caplog.text
    assert "[action:log] still" in caplog.text
    assert "stopped after exec failed, 1 action(s) skipped" in caplog.text


def test_secret_env_hands_credentials_by_name_and_redacts_them(config_file, pool, workdir, caplog):
    (workdir / "secrets" / "demo-token").write_text("s3cr3t-token-value\n")
    (workdir / "runbooks" / "show.sh").write_text("#!/bin/sh\necho \"token=$DEMO_TOKEN\"\n")
    d = dispatcher(config_file, rules=[{"name": "r", "cooldown": 0, "actions": [
        {"type": "runbook", "name": "show.sh", "secret_env": {"DEMO_TOKEN": "demo-token"}},
    ]}])
    with caplog.at_level("INFO", logger="alert-handler"):
        d.handle_payload(payload(alert()), pool)
    assert "token=***" in caplog.text and "s3cr3t-token-value" not in caplog.text
    assert d.secrets == {"demo-token": "s3cr3t-token-value"}


def test_missing_credential_fails_the_action(config_file, pool, workdir):
    (workdir / "runbooks" / "x.sh").write_text("#!/bin/sh\ntrue\n")
    d = dispatcher(config_file, rules=[{"name": "r", "cooldown": 0, "actions": [
        {"type": "runbook", "name": "x.sh", "secret_env": {"T": "absent"}},
    ]}])
    failures = metric("alert_handler_actions_total", rule="r", action="runbook", result="failure")
    d.handle_payload(payload(alert()), pool)
    assert metric("alert_handler_actions_total", rule="r", action="runbook", result="failure") == failures + 1


def test_reload_picks_up_new_rules_secrets_and_runbooks(config_file, workdir):
    d = dispatcher(config_file, rules=[{"name": "one", "actions": [{"type": "log", "message": "x"}]}])
    assert metric("alert_handler_config_rules") == 1
    (workdir / "secrets" / "k").write_text("value-123456")
    (workdir / "runbooks" / "r.sh").write_text("#!/bin/sh\n")
    d.set_config(ah.load_config(config_file(rules=[
        {"name": "one", "actions": [{"type": "log", "message": "x"}]},
        {"name": "two", "actions": [{"type": "log", "message": "y"}]},
    ], name="v2.yaml")))
    assert metric("alert_handler_config_rules") == 2
    assert metric("alert_handler_secrets_loaded") == 1
    assert metric("alert_handler_runbooks_available") == 1
    assert d.redact("value-123456") == "***"


def test_auth_token_from_settings_or_credential(config_file, workdir):
    d = dispatcher(config_file, settings={"auth_token": "inline"}, rules=[])
    assert d.auth_token == "inline"
    (workdir / "secrets" / "hook-token").write_text("from-secret")
    d = dispatcher(config_file, settings={"auth_token_secret": "hook-token"}, rules=[])
    assert d.auth_token == "from-secret"
