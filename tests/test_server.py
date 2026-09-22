import json

from conftest import alert, call, payload


RULES = [{"name": "log", "status": "any", "cooldown": 0, "actions": [{"type": "log", "message": "{{ labels.alertname }}"}]}]


def test_read_endpoints(serve, workdir):
    (workdir / "runbooks" / "recycle.sh").write_text("#!/bin/sh\n")
    base = serve(rules=RULES)
    assert call(base + "/")[0] == 200
    assert call(base + "/healthz")[:2] == (200, "ok\n")
    assert call(base + "/-/healthy")[0] == 200
    assert call(base + "/-/ready")[:2] == (200, "ready\n")
    status, body, ctype = call(base + "/rules")
    assert status == 200 and ctype == "application/json"
    assert json.loads(body) == [{"name": "log", "match": {}, "match_re": {}, "status": "any", "cooldown": 0,
                                 "incident": False, "actions": ["log"], "gated": []}]
    assert json.loads(call(base + "/runbooks")[1]) == ["recycle.sh"]
    status, body, ctype = call(base + "/metrics")
    assert status == 200 and "alert_handler_config_valid 1.0" in body
    assert call(base + "/nope")[0] == 404


def test_not_ready_without_rules(serve):
    base = serve(rules=[])
    assert call(base + "/-/ready")[:2] == (503, "no rules loaded\n")


def test_webhook_accepts_and_counts(serve):
    base = serve(rules=RULES)
    status, body, ctype = call(base + "/alert", "POST", payload(alert(), alert(alertname="B")))
    assert status == 202 and json.loads(body) == {"queued": 2} and ctype == "application/json"
    assert call(base + "/webhook", "POST", payload())[0] == 202
    assert call(base + "/elsewhere", "POST", payload())[0] == 404
    metrics = call(base + "/metrics")[1]
    assert 'alert_handler_webhook_requests_total{result="accepted"}' in metrics
    assert 'alert_handler_alerts_total{status="firing"}' in metrics


def test_webhook_rejects_bad_json(serve):
    base = serve(rules=RULES)
    status, body, _ = call(base + "/alert", "POST", b"{not json", {"Content-Type": "application/json"})
    assert status == 400 and body.startswith("invalid JSON")


def test_webhook_bearer_token(serve):
    base = serve(settings={"auth_token": "t0ken"}, rules=RULES)
    assert call(base + "/alert", "POST", payload(alert()))[0] == 401
    assert call(base + "/alert", "POST", payload(alert()), {"Authorization": "Bearer wrong"})[0] == 401
    assert call(base + "/alert", "POST", payload(alert()), {"Authorization": "Bearer t0ken"})[0] == 202
    assert call(base + "/metrics")[0] == 200  # reads stay open
