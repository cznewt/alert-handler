import json
import os
import stat
import time

import pytest

from conftest import ah


@pytest.fixture
def settings():
    return dict(ah.DEFAULT_SETTINGS, salt=dict(ah.DEFAULT_SETTINGS["salt"]), llm=dict(ah.DEFAULT_SETTINGS["llm"]))


@pytest.fixture
def actx():
    return ah.ActionContext({}, {"labels": {"alertname": "A", "namespace": "demo", "pod": "p-1"}, "status": "firing",
                                 "fingerprint": "fp", "startsAt": "now", "annotations": {}})


# --- log / http ------------------------------------------------------------- #

def test_action_log(settings, actx, caplog):
    with caplog.at_level("INFO", logger="alert-handler"):
        assert ah.action_log({"message": "hello demo"}, settings, actx) == "logged"
    assert "[action:log] hello demo" in caplog.text


def test_action_http_posts_json_with_headers(fake_server, settings, actx):
    fake_server.responses["/hook"] = (201, {"received": True})
    outcome = ah.action_http(
        {"url": fake_server.url + "/hook", "body": {"text": "hi"}, "headers": {"Authorization": "Bearer t"}},
        settings, actx,
    )
    assert outcome.endswith("-> 201") and outcome.startswith("POST")
    call = fake_server.calls[-1]
    assert call["method"] == "POST" and call["json"] == {"text": "hi"}
    assert call["headers"]["authorization"] == "Bearer t"
    assert call["headers"]["content-type"] == "application/json"


def test_action_http_get_and_custom_content_type(fake_server, settings, actx):
    assert ah.action_http({"url": fake_server.url + "/status", "method": "get"}, settings, actx) == "GET %s/status -> 200" % fake_server.url
    assert fake_server.calls[-1]["body"] == ""
    ah.action_http({"url": fake_server.url + "/raw", "body": "a=b", "headers": {"content-type": "text/plain"}}, settings, actx)
    assert fake_server.calls[-1]["headers"]["content-type"] == "text/plain" and fake_server.calls[-1]["body"] == "a=b"


def test_action_http_error_status_raises(fake_server, settings, actx):
    fake_server.responses["/down"] = (503, {"error": "no"})
    with pytest.raises(Exception):
        ah.action_http({"url": fake_server.url + "/down"}, settings, actx)


# --- exec / runbook --------------------------------------------------------- #

def test_action_exec_runs_a_shell_string_with_the_alert_environment(settings, actx, workdir):
    spec = {"command": "echo pod=$ALERT_LABEL_POD; echo two", "env": {"ALERT_LABEL_POD": "p-1", "EXTRA": "1"}}
    assert ah.action_exec(spec, settings, actx) == "exec: exit 0: two"
    assert actx.namespace["last"] == {"action": "exec", "stdout": "pod=p-1\ntwo", "stderr": "", "exit_code": 0}


def test_action_exec_failure_reports_stderr(settings, actx):
    with pytest.raises(RuntimeError, match="exit 3: boom"):
        ah.action_exec({"command": "echo boom >&2; exit 3"}, settings, actx)
    assert actx.namespace["last"]["exit_code"] == 3 and actx.namespace["last"]["stderr"] == "boom"


def test_action_exec_times_out(settings, actx):
    with pytest.raises(Exception):
        ah.action_exec({"command": "sleep 5", "timeout": 1}, settings, actx)


def test_action_runbook_runs_non_executable_scripts_through_sh(workdir, settings, actx):
    script = workdir / "runbooks" / "recycle.sh"
    script.write_text('#!/bin/sh\necho "would recycle $2 in $1 (dir=$RUNBOOK_DIR)"\n')
    os.chmod(script, stat.S_IRUSR | stat.S_IWUSR)  # a ConfigMap mounts 0644
    outcome = ah.action_runbook({"name": "recycle.sh", "args": ["demo", "p-1"]}, settings, actx)
    assert outcome == "runbook recycle.sh: exit 0: would recycle p-1 in demo (dir=%s)" % ah.RUNBOOK_DIR


def test_action_runbook_runs_executable_scripts_directly(workdir, settings, actx):
    script = workdir / "runbooks" / "x.sh"
    script.write_text("#!/bin/sh\necho direct\n")
    os.chmod(script, 0o755)
    assert ah.action_runbook({"name": "x.sh"}, settings, actx).endswith("exit 0: direct")


def test_action_runbook_unknown_script(workdir, settings, actx):
    with pytest.raises(RuntimeError, match="no runbook 'nope.sh'"):
        ah.action_runbook({"name": "nope.sh"}, settings, actx)


# --- kubernetes ------------------------------------------------------------- #

@pytest.fixture
def kube(fake_server, tmp_path, monkeypatch):
    token = tmp_path / "token"
    token.write_text("sa-token\n")
    client = ah.KubeClient(fake_server.url, str(token), str(tmp_path / "no-ca.crt"))
    monkeypatch.setattr(ah, "KUBE", client)
    return client


def test_kube_unavailable_without_api(tmp_path):
    client = ah.KubeClient(None, str(tmp_path / "token"), str(tmp_path / "ca"))
    assert not client.available
    with pytest.raises(ah.KubeError, match="no Kubernetes API"):
        client.request("GET", "api/v1/nodes")


def test_kube_request_sends_the_token_and_reports_http_errors(fake_server, kube):
    assert kube.request("GET", "/api/v1/namespaces") == {"ok": True}
    assert fake_server.calls[-1]["headers"]["authorization"] == "Bearer sa-token"
    fake_server.responses["/api/v1/nope"] = (404, {"message": "not found"})
    with pytest.raises(ah.KubeError, match="GET api/v1/nope -> 404"):
        kube.request("GET", "api/v1/nope")


def test_kube_workload_path_rejects_unknown_kinds(kube):
    assert kube.workload_path("statefulset", "ns", "db") == "apis/apps/v1/namespaces/ns/statefulsets/db"
    with pytest.raises(ah.KubeError, match="unsupported workload kind 'job'"):
        kube.workload_path("job", "ns", "x")


def test_k8s_rollout_restart_patches_the_pod_template(fake_server, kube, settings, actx):
    outcome = ah.action_k8s_rollout_restart({"namespace": "demo", "name": "app", "_rule": "r"}, settings, actx)
    assert outcome == "restarted deployment demo/app"
    call = fake_server.calls[-1]
    assert call["method"] == "PATCH" and call["path"] == "/apis/apps/v1/namespaces/demo/deployments/app"
    annotations = call["json"]["spec"]["template"]["metadata"]["annotations"]
    assert "kubectl.kubernetes.io/restartedAt" in annotations
    assert annotations["alert-handler.monitor/restarted-by"] == "r"
    assert call["headers"]["content-type"] == "application/strategic-merge-patch+json"


def test_k8s_scale_uses_the_scale_subresource_with_merge_patch(fake_server, kube, settings, actx):
    assert ah.action_k8s_scale({"namespace": "demo", "name": "w", "kind": "statefulset", "replicas": "3"}, settings, actx) == "scaled statefulset demo/w to 3"
    call = fake_server.calls[-1]
    assert call["path"] == "/apis/apps/v1/namespaces/demo/statefulsets/w/scale"
    assert call["json"] == {"spec": {"replicas": 3}}
    assert call["headers"]["content-type"] == "application/merge-patch+json"


def test_k8s_delete_pod_cordon_and_annotate(fake_server, kube, settings, actx):
    assert ah.action_k8s_delete_pod({"namespace": "demo", "name": "p"}, settings, actx) == "deleted pod demo/p"
    assert fake_server.calls[-1]["method"] == "DELETE" and fake_server.calls[-1]["path"] == "/api/v1/namespaces/demo/pods/p"
    assert ah.action_k8s_cordon_node({"name": "n1"}, settings, actx) == "cordoned node n1"
    assert fake_server.calls[-1]["json"] == {"spec": {"unschedulable": True}}
    assert ah.action_k8s_cordon_node({"name": "n1", "unschedulable": False}, settings, actx) == "uncordoned node n1"
    assert ah.action_k8s_annotate({"node": "n1", "annotations": {"a": "b"}}, settings, actx) == "annotated node n1"
    assert fake_server.calls[-1]["path"] == "/api/v1/nodes/n1" and fake_server.calls[-1]["json"] == {"metadata": {"annotations": {"a": "b"}}}
    assert ah.action_k8s_annotate({"namespace": "demo", "name": "d", "annotations": {"a": "b"}}, settings, actx) == "annotated deployment demo/d"


def test_allowed_namespaces_fence_every_namespaced_write(fake_server, kube, settings, actx):
    settings["allowed_namespaces"] = ["prod"]
    for action, spec in (
        (ah.action_k8s_rollout_restart, {"namespace": "demo", "name": "a"}),
        (ah.action_k8s_scale, {"namespace": "demo", "name": "a", "replicas": 1}),
        (ah.action_k8s_delete_pod, {"namespace": "demo", "name": "a"}),
        (ah.action_k8s_annotate, {"namespace": "demo", "name": "a", "annotations": {}}),
    ):
        with pytest.raises(ah.KubeError, match="not in allowed_namespaces"):
            action(spec, settings, actx)
    assert fake_server.calls == []
    ah.action_k8s_delete_pod({"namespace": "prod", "name": "a"}, settings, actx)
    assert len(fake_server.calls) == 1


# --- salt ------------------------------------------------------------------- #

@pytest.fixture
def salt(fake_server, settings, monkeypatch):
    settings["salt"].update({"url": fake_server.url, "username": "handler", "password_secret": "salt-pass"})
    fake_server.responses["/login"] = (200, {"return": [{"token": "tok-1", "expire": time.time() + 600}]})
    fake_server.responses["/"] = (200, {"return": [{"web01": "ok"}]})
    client = ah.SaltClient()
    monkeypatch.setattr(ah, "SALT", client)
    return client


def test_salt_unconfigured_fails_plainly(settings, actx):
    with pytest.raises(ah.SaltError, match="not configured"):
        ah.action_salt_cmd({"tgt": "*", "fun": "test.ping"}, settings, actx)


def test_salt_login_is_cached_across_calls(fake_server, salt, settings):
    secrets = {"salt-pass": "hunter22"}
    assert salt.token(settings, secrets) == "tok-1"
    assert salt.token(settings, secrets) == "tok-1"
    logins = [c for c in fake_server.calls if c["path"] == "/login"]
    assert len(logins) == 1 and logins[0]["json"] == {"eauth": "pam", "username": "handler", "password": "hunter22"}


def test_salt_missing_password_credential(salt, settings):
    with pytest.raises(ah.SaltError, match="no credential 'salt-pass'"):
        salt.token(settings, {})


def test_salt_pre_issued_token(salt, settings):
    settings["salt"]["token_secret"] = "salt-token"
    assert salt.token(settings, {"salt-token": "pre"}) == "pre"


def test_salt_cmd_builds_a_lowstate_and_summarises(fake_server, salt, settings):
    actx = ah.ActionContext({"salt-pass": "hunter22"}, {})
    outcome = ah.action_salt_cmd({"tgt": "web*", "fun": "cmd.run", "arg": "uptime", "kwarg": {"shell": "/bin/sh"}, "salt_timeout": 5}, settings, actx)
    assert outcome == "salt web* cmd.run: web01: ok"
    call = fake_server.calls[-1]
    assert call["headers"]["x-auth-token"] == "tok-1"
    assert call["json"] == {"client": "local", "tgt": "web*", "tgt_type": "glob", "fun": "cmd.run", "arg": ["uptime"], "kwarg": {"shell": "/bin/sh"}, "timeout": 5}


def test_salt_state_apply_and_runner(fake_server, salt, settings):
    actx = ah.ActionContext({"salt-pass": "x"}, {})
    ah.action_salt_state_apply({"tgt": "db01", "state": "redis", "pillar": {"maxmemory": "2g"}, "test": True}, settings, actx)
    call = fake_server.calls[-1]["json"]
    assert call["fun"] == "state.apply" and call["arg"] == ["redis"] and call["kwarg"] == {"pillar": {"maxmemory": "2g"}, "test": True}
    fake_server.responses["/"] = (200, {"return": [{"up": ["db01"]}]})
    assert ah.action_salt_run({"fun": "manage.up"}, settings, actx).startswith("salt-run manage.up:")
    assert fake_server.calls[-1]["json"]["client"] == "runner"


def test_salt_failed_states_fail_the_action(fake_server, salt, settings):
    fake_server.responses["/"] = (200, {"return": [{"db01": {"pkg_|-redis_|-redis_|-installed": {"result": False}}}]})
    with pytest.raises(ah.SaltError, match="db01: 1 states, 1 failed"):
        ah.action_salt_cmd({"tgt": "db01", "fun": "state.apply"}, settings, ah.ActionContext({"salt-pass": "x"}, {}))


def test_salt_target_fence(settings):
    settings["salt"]["allowed_targets"] = ["web*", "db0[1-3]"]
    ah.guard_target(settings, "web12")
    ah.guard_target(settings, "db02")
    with pytest.raises(ah.SaltError, match="not in allowed_targets"):
        ah.guard_target(settings, "*")


def test_salt_summary_shapes():
    assert ah._salt_summary({}) == "no minions matched"
    assert ah._salt_summary("plain") == "plain"
    many = {"m%d" % i: "ok" for i in range(7)}
    assert ah._salt_summary(many).endswith("... 2 more")
    assert ah._salt_failed({"m": "The minion function caused an exception: boom"})
    assert not ah._salt_failed({"m": True})


# --- llm -------------------------------------------------------------------- #

def test_llm_unconfigured(settings, actx):
    with pytest.raises(RuntimeError, match="llm is not configured"):
        ah.action_llm({"prompt": "why"}, settings, actx)


def test_llm_asks_and_keeps_the_answer(fake_server, settings, actx):
    settings["llm"].update({"url": fake_server.url + "/v1/chat/completions", "model": "sre-small", "api_key_secret": "llm-key"})
    actx.secrets = {"llm-key": "sk-123456"}
    fake_server.responses["/v1/chat/completions"] = (200, {
        "model": "sre-small", "choices": [{"message": {"content": "  Check the disk.  "}}], "usage": {"total_tokens": 42},
    })
    outcome = ah.action_llm({"prompt": "Alert A fired. What first?", "max_tokens": 50}, settings, actx)
    assert outcome == "llm sre-small: 15 chars, 42 tokens"
    call = fake_server.calls[-1]
    assert call["headers"]["authorization"] == "Bearer sk-123456"
    assert call["json"]["model"] == "sre-small" and call["json"]["max_tokens"] == 50
    assert call["json"]["messages"][0]["role"] == "system" and call["json"]["messages"][1]["content"] == "Alert A fired. What first?"
    assert actx.namespace["llm"] == {"answer": "Check the disk.", "model": "sre-small", "tokens": "42"}


def test_llm_missing_key_and_empty_answer(fake_server, settings, actx):
    settings["llm"].update({"url": fake_server.url + "/v1", "api_key_secret": "llm-key"})
    with pytest.raises(RuntimeError, match="no credential 'llm-key'"):
        ah.action_llm({"prompt": "q"}, settings, actx)
    settings["llm"]["api_key_secret"] = ""
    fake_server.responses["/v1"] = (200, {"choices": []})
    with pytest.raises(RuntimeError, match="no choices"):
        ah.action_llm({"prompt": "q"}, settings, actx)
    fake_server.responses["/v1"] = (500, {"error": "overloaded"})
    with pytest.raises(RuntimeError, match="-> 500"):
        ah.action_llm({"prompt": "q"}, settings, actx)
