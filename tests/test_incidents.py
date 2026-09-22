"""Incidents, approvals, silences and tickets: the lifecycle end to end.

The recording server stands in for Alertmanager (/api/v2/...) and Jira
(/rest/api/{2,3}/...); every test drives the dispatcher the way a webhook
would and then looks at what reached them and what the store remembers.
"""
import base64
import json
import time

import pytest

from conftest import ah, alert, metric, payload


def resolved(a):
    return dict(a, status="resolved", endsAt="2026-09-14T01:00:00Z")


def settings_for(fake, **extra):
    base = {
        "public_url": "https://handler.example",
        "alertmanager": {"url": fake.url},
        "jira": {"url": fake.url, "user": "bot@example.com", "token_secret": "jira-token", "project": "OPS"},
    }
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = dict(base[key], **value)
        else:
            base[key] = value
    return base


@pytest.fixture
def lab(config_file, workdir, fake_server):
    """dispatcher(rules, **settings) against the fake Alertmanager + Jira, token in place."""
    (workdir / "secrets" / "jira-token").write_text("jira-api-token-123\n")
    fake_server.responses["/api/v2/silences"] = (200, {"silenceID": "sil-1"})
    fake_server.responses["/rest/api/3/search/jql"] = (200, {"issues": []})
    fake_server.responses["/rest/api/3/issue"] = (201, {"id": "10001", "key": "OPS-7"})

    def _dispatcher(rules, **settings):
        return ah.Dispatcher(ah.load_config(config_file(settings=settings_for(fake_server, **settings), rules=rules)))

    return _dispatcher


def calls(fake, method, path):
    return [c for c in fake.calls if c["method"] == method and c["path"].split("?", 1)[0] == path]


FULL = [{
    "name": "redis-memory",
    "incident": True,
    "cooldown": 0,
    "actions": [
        {"type": "am_silence", "duration": "4h", "labels": ["alertname", "namespace"]},
        {"type": "log", "message": "mitigating {{ labels.namespace }}"},
        {"type": "jira_create", "approval": "required", "summary": "{{ labels.alertname }} in {{ labels.namespace }}"},
        {"type": "log", "message": "ticket {{ jira.key }} approved by {{ approval.by }}"},
    ],
}]


# ------------------------------------------------------------------ silences
def test_silence_matches_the_alert_and_is_recorded_once(lab, pool, fake_server):
    d = lab(FULL)
    d.handle_payload(payload(alert(namespace="shop", pod="p-1")), pool)
    posted = calls(fake_server, "POST", "/api/v2/silences")
    assert len(posted) == 1
    body = posted[0]["json"]
    assert body["matchers"] == [
        {"name": "alertname", "value": "TestAlert", "isRegex": False, "isEqual": True},
        {"name": "namespace", "value": "shop", "isRegex": False, "isEqual": True},
    ]
    assert body["createdBy"] == "alert-handler" and "https://handler.example/incidents/" in body["comment"]
    ends = time.mktime(time.strptime(body["endsAt"], "%Y-%m-%dT%H:%M:%SZ"))
    starts = time.mktime(time.strptime(body["startsAt"], "%Y-%m-%dT%H:%M:%SZ"))
    assert ends - starts == 4 * 3600
    (incident,) = d.store.list_incidents()
    assert incident["silences"][0]["id"] == "sil-1" and incident["state"] == "open"
    # the same alert again: the live silence is reported, not stacked
    d.handle_payload(payload(alert(namespace="shop", pod="p-1")), pool)
    assert len(calls(fake_server, "POST", "/api/v2/silences")) == 1
    assert any("already silenced by sil-1" in e["text"] for e in d.store.get(incident["id"])["events"])


def test_silence_on_a_label_the_alert_lacks_fails(lab, pool):
    d = lab([{"name": "r", "incident": True, "cooldown": 0,
              "actions": [{"type": "am_silence", "labels": ["pod"]}]}])
    before = metric("alert_handler_actions_total", rule="r", action="am_silence", result="failure")
    d.handle_payload(payload(alert()), pool)
    assert metric("alert_handler_actions_total", rule="r", action="am_silence", result="failure") == before + 1


def test_mimir_tenant_and_bearer_token_reach_alertmanager(lab, pool, fake_server, workdir):
    (workdir / "secrets" / "am-token").write_text("am-bearer-token\n")
    d = lab([{"name": "r", "cooldown": 0, "actions": [{"type": "am_silence"}]}],
            alertmanager={"tenant": "komarek", "token_secret": "am-token"})
    d.handle_payload(payload(alert()), pool)
    headers = calls(fake_server, "POST", "/api/v2/silences")[0]["headers"]
    assert headers["x-scope-orgid"] == "komarek" and headers["authorization"] == "Bearer am-bearer-token"


def test_am_expire_lifts_the_incidents_silences(lab, pool, fake_server):
    d = lab([{"name": "r", "incident": True, "cooldown": 0, "actions": [
        {"type": "am_silence"}, {"type": "am_expire"}]}])
    d.handle_payload(payload(alert()), pool)
    assert len(calls(fake_server, "DELETE", "/api/v2/silence/sil-1")) == 1
    (incident,) = d.store.list_incidents()
    assert incident["silences"][0]["expired"]


# ------------------------------------------------------------------ jira
def test_jira_create_cloud_ticket(lab, pool, fake_server):
    d = lab([{"name": "r", "incident": True, "cooldown": 0, "actions": [
        {"type": "log", "message": "diagnosed"},
        {"type": "jira_create", "priority": "High", "labels": ["redis"]}]}])
    d.handle_payload(payload(alert(namespace="shop")), pool)
    search = calls(fake_server, "POST", "/rest/api/3/search/jql")[0]["json"]
    assert search["jql"].startswith('labels = "alertfp-') and "statusCategory != Done" in search["jql"]
    created = calls(fake_server, "POST", "/rest/api/3/issue")
    assert len(created) == 1
    request = created[0]
    auth = base64.b64decode(request["headers"]["authorization"].split(" ", 1)[1]).decode()
    assert auth == "bot@example.com:jira-api-token-123"
    fields = request["json"]["fields"]
    assert fields["project"] == {"key": "OPS"} and fields["issuetype"] == {"name": "Task"}
    assert fields["summary"] == "TestAlert: something is up" and fields["priority"] == {"name": "High"}
    assert "alert-handler" in fields["labels"] and "redis" in fields["labels"]
    assert any(label.startswith("alertfp-") for label in fields["labels"])
    assert fields["description"]["type"] == "doc"  # Atlassian Document Format on API 3
    text = json.dumps(fields["description"])
    assert "What alert-handler has done so far:" in text and "log: logged: diagnosed" in text
    (incident,) = d.store.list_incidents()
    assert incident["jira"] == {"key": "OPS-7", "url": fake_server.url + "/browse/OPS-7"}


def test_a_refiring_alert_comments_instead_of_duplicating(lab, pool, fake_server):
    fake_server.responses["/rest/api/3/search/jql"] = (200, {"issues": [{"key": "OPS-3"}]})
    d = lab([{"name": "r", "cooldown": 0, "actions": [{"type": "jira_create"}]}])
    d.handle_payload(payload(alert()), pool)
    assert not calls(fake_server, "POST", "/rest/api/3/issue")
    comment = calls(fake_server, "POST", "/rest/api/3/issue/OPS-3/comment")[0]["json"]
    assert "fired again" in json.dumps(comment)


def test_jira_server_uses_api_2_a_pat_and_plain_text(lab, pool, fake_server):
    fake_server.responses["/rest/api/2/search"] = (200, {"issues": []})
    fake_server.responses["/rest/api/2/issue"] = (201, {"key": "SRE-1"})
    d = lab([{"name": "r", "cooldown": 0, "actions": [{"type": "jira_create", "description": "plain words"}]}],
            jira={"api_version": "2", "user": ""})
    d.handle_payload(payload(alert()), pool)
    request = calls(fake_server, "POST", "/rest/api/2/issue")[0]
    assert request["headers"]["authorization"] == "Bearer jira-api-token-123"
    assert request["json"]["fields"]["description"] == "plain words"


def test_jira_transition_by_name_and_unknown_names(lab, pool, fake_server):
    fake_server.responses["/rest/api/3/issue/OPS-9/transitions"] = (200, {"transitions": [
        {"id": "21", "name": "Start", "to": {"name": "In Progress"}},
        {"id": "31", "name": "Mitigated", "to": {"name": "Waiting"}}]})
    d = lab([{"name": "ok", "cooldown": 0, "actions": [
                {"type": "jira_transition", "issue": "OPS-9", "transition": "mitigated", "comment": "restarted"}]},
             {"name": "bad", "cooldown": 0, "actions": [
                {"type": "jira_transition", "issue": "OPS-9", "transition": "Teleport"}]}])
    failures = metric("alert_handler_actions_total", rule="bad", action="jira_transition", result="failure")
    d.handle_payload(payload(alert()), pool)
    moved = [c for c in calls(fake_server, "POST", "/rest/api/3/issue/OPS-9/transitions")]
    assert [c["json"] for c in moved] == [{"transition": {"id": "31"}}]
    assert calls(fake_server, "POST", "/rest/api/3/issue/OPS-9/comment")
    assert metric("alert_handler_actions_total", rule="bad", action="jira_transition", result="failure") == failures + 1


def test_jira_not_configured_fails_with_a_clear_message(config_file, pool, caplog):
    d = ah.Dispatcher(ah.load_config(config_file(rules=[{"name": "r", "cooldown": 0, "actions": [{"type": "jira_create"}]}])))
    with caplog.at_level("INFO", logger="alert-handler"):
        d.handle_payload(payload(alert()), pool)
    assert "jira is not configured (set settings.jira.url)" in caplog.text


# ------------------------------------------------------------------ approvals
def test_a_gated_action_waits_then_runs_with_who_approved(lab, pool, fake_server, caplog):
    d = lab(FULL)
    with caplog.at_level("INFO", logger="alert-handler"):
        d.handle_payload(payload(alert(namespace="shop")), pool)
    assert "[action:log] mitigating shop" in caplog.text           # automatic steps ran
    assert not calls(fake_server, "POST", "/rest/api/3/issue")      # the ticket waits
    (record,) = d.store.list_approvals()
    assert record["state"] == "pending" and record["action"] == "jira_create"
    assert record["url"] == "https://handler.example/approvals/" + record["id"]
    assert "TestAlert in shop" in record["summary"]
    assert metric("alert_handler_approvals_pending") == 1
    # the same alert again does not ask twice
    d.handle_payload(payload(alert(namespace="shop")), pool)
    assert len(d.store.list_approvals()) == 1

    with caplog.at_level("INFO", logger="alert-handler"):
        d.decide(record["id"], True, "ana", pool)
    assert "[action:log] ticket OPS-7 approved by ana" in caplog.text
    description = json.dumps(calls(fake_server, "POST", "/rest/api/3/issue")[0]["json"]["fields"]["description"])
    assert "Approved by ana" in description and "am_silence: silenced" in description
    assert d.store.get_approval(record["id"])["state"] == "approved"
    assert metric("alert_handler_approvals_pending") == 0
    (incident,) = d.store.list_incidents()
    assert incident["jira"]["key"] == "OPS-7"
    assert any("ana approved" in e["text"] for e in incident["events"])


def test_rejecting_ends_the_chain_and_settled_approvals_stay_settled(lab, pool, fake_server):
    d = lab(FULL)
    d.handle_payload(payload(alert(namespace="shop")), pool)
    (record,) = d.store.list_approvals()
    d.decide(record["id"], False, "ana", pool, note="not worth a ticket")
    assert not calls(fake_server, "POST", "/rest/api/3/issue")
    assert d.store.get_approval(record["id"])["note"] == "not worth a ticket"
    with pytest.raises(ValueError):
        d.decide(record["id"], True, "bob", pool)
    with pytest.raises(KeyError):
        d.decide("nope", True, "bob", pool)


def test_approvals_expire(lab, pool):
    d = lab(FULL, approvals={"ttl": "1h"})
    d.handle_payload(payload(alert(namespace="shop")), pool)
    (record,) = d.store.list_approvals()
    before = metric("alert_handler_approval_decisions_total", decision="expired")
    d.housekeeping(now=time.time() + 3601)
    assert d.store.get_approval(record["id"])["state"] == "expired"
    assert metric("alert_handler_approval_decisions_total", decision="expired") == before + 1


def test_notify_tells_somebody_where_to_decide(lab, pool, fake_server):
    d = lab(FULL, approvals={"notify": {"type": "http", "url": fake_server.url + "/chat",
                                        "body": {"text": "{{ approval.summary }} - decide at {{ approval.url }}"}}})
    d.handle_payload(payload(alert(namespace="shop")), pool)
    (record,) = d.store.list_approvals()
    (chat,) = calls(fake_server, "POST", "/chat")
    assert chat["json"]["text"].endswith("decide at https://handler.example/approvals/" + record["id"])


def test_a_second_gate_pauses_again_after_the_first_is_approved(lab, pool, caplog):
    d = lab([{"name": "two-gates", "incident": True, "cooldown": 0, "actions": [
        {"type": "log", "message": "first", "approval": "required"},
        {"type": "log", "message": "second", "approval": "required"}]}])
    d.handle_payload(payload(alert()), pool)
    (first,) = d.store.list_approvals()
    d.decide(first["id"], True, "ana", pool)
    pending = [r for r in d.store.list_approvals() if r["state"] == "pending"]
    assert len(pending) == 1 and pending[0]["index"] == 1
    with caplog.at_level("INFO", logger="alert-handler"):
        d.decide(pending[0]["id"], True, "bob", pool)
    assert "[action:log] second" in caplog.text


# ------------------------------------------------------------------ resolution
def test_resolved_alert_withdraws_approvals_and_tells_the_ticket(lab, pool, fake_server):
    rules = [{"name": "r", "incident": True, "cooldown": 0, "actions": [
        {"type": "jira_create"}, {"type": "log", "message": "later", "approval": "required"}]}]
    d = lab(rules)
    firing = alert()
    d.handle_payload(payload(firing), pool)
    (record,) = d.store.list_approvals()
    d.handle_payload(payload(resolved(firing)), pool)
    assert d.store.get_approval(record["id"])["state"] == "cancelled"
    (incident,) = d.store.list_incidents()
    assert incident["state"] == "alert_resolved"
    comment = json.dumps(calls(fake_server, "POST", "/rest/api/3/issue/OPS-7/comment")[-1]["json"])
    assert "The alert resolved" in comment and "stays open until a person closes it" in comment
    # firing again reopens the same incident
    d.handle_payload(payload(firing), pool)
    assert d.store.get(incident["id"])["state"] == "open"


def test_a_silenced_alert_that_left_alertmanager_counts_as_resolved(lab, pool, fake_server):
    d = lab([{"name": "r", "incident": True, "cooldown": 0, "actions": [{"type": "am_silence"}]}])
    d.handle_payload(payload(alert()), pool)
    fake_server.responses["/api/v2/alerts"] = (200, [{"fingerprint": "someone-else", "labels": {}}])
    d.check_silenced()
    (incident,) = d.store.list_incidents()
    assert incident["state"] == "alert_resolved"
    query = calls(fake_server, "GET", "/api/v2/alerts")[0]["path"]
    assert "silenced=true" in query and "alertname%3D%22TestAlert%22" in query


def test_a_person_closes_from_the_handler(lab, pool, fake_server):
    fake_server.responses["/rest/api/3/issue/OPS-7/transitions"] = (200, {"transitions": [{"id": "41", "name": "Done"}]})
    d = lab([{"name": "r", "incident": True, "cooldown": 0, "actions": [
        {"type": "am_silence"}, {"type": "jira_create"}, {"type": "log", "message": "x", "approval": "required"}]}],
        incidents={"resolve_transition": "Done"})
    d.handle_payload(payload(alert()), pool)
    (incident,) = d.store.list_incidents()
    closed = d.close_incident(incident["id"], "ana", "raised maxmemory")
    assert closed["state"] == "closed" and closed["closed_by"] == "ana"
    assert calls(fake_server, "DELETE", "/api/v2/silence/sil-1")
    assert closed["silences"][0]["expired"]
    assert [r["state"] for r in d.store.list_approvals()] == ["cancelled"]
    comment = json.dumps(calls(fake_server, "POST", "/rest/api/3/issue/OPS-7/comment")[-1]["json"])
    assert "Closed by ana: raised maxmemory" in comment and "lifted silence sil-1" in comment
    assert calls(fake_server, "POST", "/rest/api/3/issue/OPS-7/transitions")[0]["json"] == {"transition": {"id": "41"}}
    assert d.close_incident(incident["id"], "bob", "again")["closed_by"] == "ana"  # idempotent


def test_a_person_closes_the_ticket_in_jira(lab, pool, fake_server):
    d = lab([{"name": "r", "incident": True, "cooldown": 0, "actions": [{"type": "am_silence"}, {"type": "jira_create"}]}])
    d.handle_payload(payload(alert()), pool)
    fake_server.responses["/rest/api/3/issue/OPS-7"] = (200, {"fields": {
        "status": {"name": "Done", "statusCategory": {"key": "done"}}, "assignee": {"displayName": "Ana"}}})
    d.poll_jira()
    (incident,) = d.store.list_incidents()
    assert incident["state"] == "closed" and incident["closed_by"] == "Ana"
    assert "OPS-7 moved to Done" in incident["close_reason"]
    assert calls(fake_server, "DELETE", "/api/v2/silence/sil-1")
    assert not calls(fake_server, "POST", "/rest/api/3/issue/OPS-7/transitions")  # Jira already did


def test_jira_still_open_keeps_the_incident(lab, pool, fake_server):
    d = lab([{"name": "r", "incident": True, "cooldown": 0, "actions": [{"type": "jira_create"}]}])
    d.handle_payload(payload(alert()), pool)
    fake_server.responses["/rest/api/3/issue/OPS-7"] = (200, {"fields": {
        "status": {"name": "In Progress", "statusCategory": {"key": "indeterminate"}}}})
    d.poll_jira()
    assert d.store.list_incidents()[0]["state"] == "open"


# ------------------------------------------------------------------ persistence and config
def test_state_survives_a_restart_without_credentials(config_file, workdir, pool):
    (workdir / "secrets" / "demo-token").write_text("very-secret-value\n")
    (workdir / "runbooks" / "leak.sh").write_text("#!/bin/sh\necho token=$DEMO_TOKEN\n")
    state = workdir / "state" / "state.json"
    rules = [{"name": "r", "incident": True, "cooldown": 0, "actions": [
        {"type": "runbook", "name": "leak.sh", "secret_env": {"DEMO_TOKEN": "demo-token"}},
        {"type": "log", "message": "{{ last.stdout }}", "approval": "required"}]}]
    d = ah.Dispatcher(ah.load_config(config_file(settings={"state_file": str(state)}, rules=rules)))
    d.handle_payload(payload(alert()), pool)
    raw = state.read_text()
    assert "very-secret-value" not in raw and "token=***" in raw
    again = ah.Dispatcher(ah.load_config(config_file(settings={"state_file": str(state)}, rules=rules, name="v2.yaml")))
    assert len(again.store.list_incidents()) == 1
    (record,) = again.store.list_approvals()
    assert record["state"] == "pending" and "secrets" not in record["namespace"]


def test_closed_incidents_are_forgotten_after_retention(lab, pool):
    d = lab([{"name": "r", "incident": True, "cooldown": 0, "actions": [{"type": "log", "message": "x"}]}],
            incidents={"retention": "1d"}, jira={"url": ""}, alertmanager={"url": ""})
    d.handle_payload(payload(alert()), pool)
    (incident,) = d.store.list_incidents()
    d.close_incident(incident["id"], "ana", "done")
    d.housekeeping(now=time.time() + 86401)
    assert d.store.list_incidents() == []


@pytest.mark.parametrize("settings, rules, message", [
    ({}, [{"name": "r", "actions": [{"type": "log", "approval": "maybe"}]}], "approval 'maybe'"),
    ({"approvals": {"ttl": "soon"}}, [], "settings.approvals.ttl"),
    ({"approvals": {"notify": {"type": "carrier-pigeon"}}}, [], "settings.approvals.notify"),
])
def test_bad_config_is_refused(config_file, settings, rules, message):
    with pytest.raises(ValueError, match=message):
        ah.load_config(config_file(settings=settings, rules=rules))


@pytest.mark.parametrize("value, seconds", [(90, 90), ("90", 90), ("30m", 1800), ("4h", 14400), ("2d", 172800)])
def test_parse_duration(value, seconds):
    assert ah.parse_duration(value) == seconds


def test_adf_paragraphs_and_line_breaks():
    doc = ah.adf("one\ntwo\n\nthree")
    assert doc["content"][0]["content"] == [
        {"type": "text", "text": "one"}, {"type": "hardBreak"}, {"type": "text", "text": "two"}]
    assert doc["content"][1]["content"] == [{"type": "text", "text": "three"}]
