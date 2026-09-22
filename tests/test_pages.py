"""The pages for people, through the real HTTP server: who decided, where the
browser goes next, and what is refused (another site's form, a missing token,
a decision on something already decided)."""
import base64
import json
import time
import urllib.parse

from conftest import alert, call, payload

GATED = [{"name": "gated", "incident": True, "cooldown": 0, "actions": [
    {"type": "log", "message": "diagnose"},
    {"type": "log", "message": "restart {{ labels.pod }}", "approval": "required"}]}]


def form(**fields):
    return urllib.parse.urlencode(fields).encode()


def basic(user):
    return "Basic " + base64.b64encode(("%s:pw" % user).encode()).decode()


def wait_for_approval(base):
    for _ in range(50):
        records = json.loads(call(base + "/approvals?format=json")[1])
        if records:
            return records[0]
        time.sleep(0.05)
    raise AssertionError("no approval appeared")


def test_pages_render_and_json_is_there_for_scripts(serve):
    base = serve(rules=GATED)
    call(base + "/alert", "POST", payload(alert(pod="p-1")))
    record = wait_for_approval(base)
    status, page, ctype = call(base + "/approvals")
    assert status == 200 and ctype.startswith("text/html")
    assert "/approvals/%s/approve" % record["id"] in page and "restart p-1" in page
    status, page, _ = call(base + "/approvals/" + record["id"])
    assert status == 200 and "diagnose" in page  # what already ran
    incidents = json.loads(call(base + "/incidents", headers={"Accept": "application/json"})[1])
    assert len(incidents) == 1 and incidents[0]["state"] == "open"
    status, page, _ = call(base + "/incidents/" + incidents[0]["id"])
    assert status == 200 and "Resolve" in page and "waiting for approval" in page
    assert call(base + "/incidents/nope")[0] == 404
    assert call(base + "/approvals/nope")[0] == 404


def test_approve_records_the_login_and_redirects_the_browser(serve, caplog):
    base = serve(rules=GATED)
    call(base + "/alert", "POST", payload(alert(pod="p-2")))
    record = wait_for_approval(base)
    with caplog.at_level("INFO", logger="alert-handler"):
        status, _, _ = call(base + "/approvals/%s/approve" % record["id"], "POST", form(),
                            {"Authorization": basic("ana"), "Content-Type": "application/x-www-form-urlencoded"})
        for _ in range(50):
            if "[action:log] restart p-2" in caplog.text:
                break
            time.sleep(0.05)
    assert status == 200  # urllib follows the 303 to the approval page
    assert "[action:log] restart p-2" in caplog.text
    settled = json.loads(call(base + "/approvals/%s?format=json" % record["id"])[1])
    assert settled["state"] == "approved" and settled["decided_by"] == "ana"
    status, body, _ = call(base + "/approvals/%s/reject" % record["id"], "POST", {"by": "bob"},
                           {"Content-Type": "application/json"})
    assert status == 409 and "not pending" in body


def test_json_clients_get_the_record_back(serve):
    base = serve(rules=GATED)
    call(base + "/alert", "POST", payload(alert(pod="p-3")))
    record = wait_for_approval(base)
    status, body, ctype = call(base + "/approvals/%s/reject" % record["id"], "POST", {"by": "bob", "note": "no"},
                               {"Content-Type": "application/json"})
    assert status == 200 and ctype == "application/json"
    assert json.loads(body)["decided_by"] == "bob" and json.loads(body)["note"] == "no"


def test_another_sites_form_is_refused(serve):
    base = serve(rules=GATED)
    call(base + "/alert", "POST", payload(alert(pod="p-4")))
    record = wait_for_approval(base)
    status, body, _ = call(base + "/approvals/%s/approve" % record["id"], "POST", form(),
                           {"Origin": "https://evil.example", "Content-Type": "application/x-www-form-urlencoded"})
    assert status == 403 and "another site" in body
    host = base.split("//", 1)[1]
    status, _, _ = call(base + "/approvals/%s/approve" % record["id"], "POST", form(),
                        {"Origin": "http://" + host, "Content-Type": "application/x-www-form-urlencoded"})
    assert status == 200


def test_the_webhook_token_guards_decisions_too(serve):
    base = serve(settings={"auth_token": "t0ken"}, rules=GATED)
    call(base + "/alert", "POST", payload(alert(pod="p-5")), {"Authorization": "Bearer t0ken"})
    record = wait_for_approval(base)
    assert 'name="token"' in call(base + "/approvals")[1]  # the form asks for it
    url = base + "/approvals/%s/approve" % record["id"]
    assert call(url, "POST", form(), {"Content-Type": "application/x-www-form-urlencoded"})[0] == 401
    assert call(url, "POST", form(token="t0ken"), {"Content-Type": "application/x-www-form-urlencoded"})[0] == 200


def test_resolve_from_the_incident_page(serve):
    base = serve(rules=GATED)
    call(base + "/alert", "POST", payload(alert(pod="p-6")))
    wait_for_approval(base)
    incident = json.loads(call(base + "/incidents?format=json")[1])[0]
    status, _, _ = call(base + "/incidents/%s/resolve" % incident["id"], "POST", form(reason="scaled up"),
                        {"Authorization": basic("ana"), "Content-Type": "application/x-www-form-urlencoded"})
    assert status == 200
    closed = json.loads(call(base + "/incidents/%s?format=json" % incident["id"])[1])
    assert closed["state"] == "closed" and closed["closed_by"] == "ana" and closed["close_reason"] == "scaled up"
    assert json.loads(call(base + "/approvals?format=json")[1])[0]["state"] == "cancelled"
    assert call(base + "/incidents/nope/resolve", "POST", form(), {"Content-Type": "application/x-www-form-urlencoded"})[0] == 404
