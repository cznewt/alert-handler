import json

from conftest import ah


def test_render_substitutes_nested_paths():
    context = {"labels": {"alertname": "X", "severity": "warning"}, "status": "firing"}
    assert ah.render("{{ status }} {{labels.alertname}} ({{ labels.severity }})", context) == "firing X (warning)"


def test_render_recurses_into_lists_and_dicts():
    context = {"labels": {"ns": "demo"}}
    spec = {"args": ["{{ labels.ns }}", 3], "headers": {"X-Ns": "{{ labels.ns }}"}, "flag": True}
    assert ah.render(spec, context) == {"args": ["demo", 3], "headers": {"X-Ns": "demo"}, "flag": True}


def test_render_unknown_placeholder_renders_empty(caplog):
    with caplog.at_level("WARNING", logger="alert-handler"):
        assert ah.render("[{{ labels.missing }}]", {"labels": {}}) == "[]"
    assert "labels.missing" in caplog.text


def test_render_serialises_non_string_values_as_json():
    context = {"labels": {"a": "1"}, "last": {"exit_code": 0}}
    assert ah.render("{{ labels }}", context) == json.dumps({"a": "1"})
    assert ah.render("{{ last.exit_code }}", context) == "0"


def test_render_allows_hyphens_in_credential_names():
    assert ah.render("Bearer {{ secrets.chat-token }}", {"secrets": {"chat-token": "abc"}}) == "Bearer abc"


def test_alert_context_flattens_alert_and_group():
    context = ah.alert_context(
        {"labels": {"alertname": "A"}, "annotations": {"summary": "s"}, "status": "resolved", "fingerprint": "fp"},
        {"receiver": "r", "externalURL": "http://am", "groupKey": "g"},
        {"tok": "value"},
    )
    assert context["labels"] == {"alertname": "A"}
    assert context["status"] == "resolved"
    assert context["fingerprint"] == "fp"
    assert context["receiver"] == "r"
    assert context["externalURL"] == "http://am"
    assert context["groupKey"] == "g"
    assert context["secrets"] == {"tok": "value"}
    assert context["endsAt"] == ""


def test_alert_env_exposes_labels_as_variables():
    context = ah.alert_context({"labels": {"alertname": "A", "pod": "p-1", "not-an-identifier": "x"}, "status": "firing"}, {})
    env = ah._alert_env(context)
    assert env["ALERT_STATUS"] == "firing"
    assert env["ALERT_LABEL_ALERTNAME"] == "A"
    assert env["ALERT_LABEL_POD"] == "p-1"
    assert json.loads(env["ALERT_LABELS"])["pod"] == "p-1"
    assert not any(key.endswith("NOT-AN-IDENTIFIER") for key in env)


def test_alert_id_is_stable_and_sorted():
    assert ah._alert_id({"labels": {"b": "2", "alertname": "A", "a": "1"}}) == "A{a=1,b=2}"
    assert ah._alert_id({}) == "?{}"


def test_summarise_hides_private_keys():
    assert json.loads(ah._summarise({"url": "u", "_rule": "r"})) == {"url": "u"}


def test_preview_keeps_what_is_not_known_yet(caplog):
    from conftest import ah
    with caplog.at_level("WARNING", logger="alert-handler"):
        text = ah.render("{{ labels.pod }} approved by {{ approval.by }}", {"labels": {"pod": "p-1"}}, preview=True)
    assert text == "p-1 approved by {{ approval.by }}"
    assert "not set" not in caplog.text
