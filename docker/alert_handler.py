#!/usr/bin/env python3
"""Alertmanager webhook handler that runs actions.

Alertmanager posts a group of alerts to `/alert`; every alert is matched against
an ordered list of rules from the config file, and each matching rule runs its
actions: an outbound HTTP call, a command from the image, a log line, or a write
against the Kubernetes API (rollout restart, scale, delete pod, cordon node,
annotate).

The point is self-healing and enrichment that does not deserve its own operator:
"restart the deployment that is crash-looping", "scale the worker pool when the
queue alert fires", "post the runbook link to chat". Everything an action does is
counted in Prometheus metrics on :8080/metrics, so the handler itself is
monitored like any other service.

Actions run on a small thread pool: the webhook answers Alertmanager immediately
(it retries aggressively on slow receivers) and the work happens in the
background.
"""

import fnmatch
import json
import logging
import os
import re
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import yaml
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

log = logging.getLogger("alert-handler")


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
def _env(name, default=None):
    return os.environ.get(name, default)


CONFIG_FILE = _env("CONFIG_FILE", "/etc/alert-handler/config.yaml")
# Runbooks: a directory of scripts, typically a mounted ConfigMap. Credentials:
# a directory of files, typically a mounted Secret, one file per credential.
RUNBOOK_DIR = _env("RUNBOOK_DIR", "/etc/alert-handler/runbooks")
SECRETS_DIR = _env("SECRETS_DIR", "/etc/alert-handler/secrets")
HTTP_PORT = int(_env("HTTP_PORT", "8080"))
LOG_LEVEL = _env("LOG_LEVEL", "INFO").upper()

# In-cluster Kubernetes access. Overridable so the handler can talk to an API
# server through a local proxy (`kubectl proxy`) while you develop.
SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
K8S_API_URL = _env("K8S_API_URL") or (
    "https://%s:%s" % (os.environ["KUBERNETES_SERVICE_HOST"], os.environ.get("KUBERNETES_SERVICE_PORT", "443"))
    if os.environ.get("KUBERNETES_SERVICE_HOST")
    else None
)
K8S_TOKEN_FILE = _env("K8S_TOKEN_FILE", os.path.join(SA_DIR, "token"))
K8S_CA_FILE = _env("K8S_CA_FILE", os.path.join(SA_DIR, "ca.crt"))
K8S_NAMESPACE_FILE = os.path.join(SA_DIR, "namespace")


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #
WEBHOOKS = Counter(
    "alert_handler_webhook_requests_total",
    "Webhook requests received, by outcome.",
    ["result"],
)
ALERTS = Counter(
    "alert_handler_alerts_total",
    "Alerts unpacked from webhook payloads, by alert status.",
    ["status"],
)
MATCHES = Counter(
    "alert_handler_rule_matches_total",
    "Alerts matched by a rule.",
    ["rule"],
)
ACTIONS = Counter(
    "alert_handler_actions_total",
    "Actions dispatched, by rule, action type and result.",
    ["rule", "action", "result"],
)
ACTION_SECONDS = Histogram(
    "alert_handler_action_duration_seconds",
    "Wall-clock duration of an action.",
    ["rule", "action"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60),
)
CONFIG_RULES = Gauge(
    "alert_handler_config_rules",
    "Rules in the loaded configuration.",
)
CONFIG_LOADED = Gauge(
    "alert_handler_config_loaded_timestamp_seconds",
    "Unix time the configuration was last loaded.",
)
CONFIG_VALID = Gauge(
    "alert_handler_config_valid",
    "1 if the configuration currently in effect parsed cleanly.",
)
INFLIGHT = Gauge(
    "alert_handler_actions_inflight",
    "Actions currently executing.",
)
SECRETS_LOADED = Gauge(
    "alert_handler_secrets_loaded",
    "Credentials read from the secrets directory.",
)
RUNBOOKS_AVAILABLE = Gauge(
    "alert_handler_runbooks_available",
    "Scripts present in the runbook directory.",
)


# --------------------------------------------------------------------------- #
# Templating: `{{ labels.foo }}` / `{{ annotations.bar }}` / `{{ status }}`
#
# Deliberately not Jinja: an action argument that silently executes arbitrary
# template logic is a footgun in a component that can delete pods. Substitution
# only, unknown keys render empty and are logged.
# --------------------------------------------------------------------------- #
# Hyphens are allowed because credential names are file names (and Kubernetes
# Secret keys are routinely hyphenated); Prometheus label names never are.
_TEMPLATE_RE = re.compile(r"{{\s*([a-zA-Z0-9_.-]+)\s*}}")


def render(value, context):
    """Render {{ path }} placeholders in strings, recursing into lists/dicts."""
    if isinstance(value, str):
        return _TEMPLATE_RE.sub(lambda match: _lookup(match.group(1), context), value)
    if isinstance(value, list):
        return [render(item, context) for item in value]
    if isinstance(value, dict):
        return {key: render(item, context) for key, item in value.items()}
    return value


def _lookup(path, context):
    node = context
    for part in path.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            log.warning("template placeholder {{ %s }} is not set on this alert", path)
            return ""
    return node if isinstance(node, str) else json.dumps(node)


# --------------------------------------------------------------------------- #
# Credentials and runbooks
#
# Credentials are files in a directory (mount a Secret there), one per
# credential: the file name is the key, its stripped contents the value. They
# reach actions only through `{{ secrets.<name> }}` or an explicit `secret_env`,
# never as blanket environment variables, and never through the logs.
# --------------------------------------------------------------------------- #
def load_secrets(path=None):
    path = path or SECRETS_DIR
    secrets = {}
    if not os.path.isdir(path):
        return secrets
    for entry in sorted(os.listdir(path)):
        # Kubernetes Secret mounts carry a `..data` symlink farm; skip dotfiles.
        if entry.startswith("."):
            continue
        full = os.path.join(path, entry)
        if not os.path.isfile(full):
            continue
        try:
            with open(full, "r", encoding="utf-8") as handle:
                value = handle.read().strip()
        except OSError as error:
            log.error("cannot read credential %s: %s", entry, error)
            continue
        if value:
            secrets[entry] = value
    return secrets


class Redactor:
    """Replaces credential values with *** anywhere they would be logged."""

    def __init__(self, secrets):
        # Short values would redact half the log; they are not credentials.
        self._values = sorted(
            (value for value in secrets.values() if len(value) >= 6),
            key=len,
            reverse=True,
        )

    def __call__(self, text):
        text = str(text)
        for value in self._values:
            text = text.replace(value, "***")
        return text


def list_runbooks(path=None):
    path = path or RUNBOOK_DIR
    if not os.path.isdir(path):
        return []
    return sorted(
        entry
        for entry in os.listdir(path)
        if not entry.startswith(".") and os.path.isfile(os.path.join(path, entry))
    )


def resolve_runbook(name):
    """Absolute path of a runbook, refusing anything outside the directory."""
    base = os.path.realpath(RUNBOOK_DIR)
    path = os.path.realpath(os.path.join(base, name))
    if path != base and os.path.commonpath([base, path]) != base:
        raise RuntimeError("runbook %r escapes %s" % (name, RUNBOOK_DIR))
    if not os.path.isfile(path):
        available = ", ".join(list_runbooks()) or "none"
        raise RuntimeError("no runbook %r in %s (available: %s)" % (name, RUNBOOK_DIR, available))
    return path


class ActionContext:
    """What an action is given beyond its own spec.

    `namespace` is the template namespace for this (rule, alert) run, and it is
    mutable on purpose: actions in a rule run in order and add to it, so a later
    action can use what an earlier one produced - {{ last.stdout }} from a
    diagnostic runbook, {{ llm.answer }} from an analysis.
    """

    def __init__(self, secrets, namespace):
        self.secrets = secrets
        self.namespace = namespace


def alert_context(alert, payload, secrets=None):
    """Flatten one alert plus its group envelope into the template namespace."""
    return {
        "secrets": secrets or {},
        "labels": alert.get("labels", {}),
        "annotations": alert.get("annotations", {}),
        "status": alert.get("status", ""),
        "fingerprint": alert.get("fingerprint", ""),
        "startsAt": alert.get("startsAt", ""),
        "endsAt": alert.get("endsAt", ""),
        "generatorURL": alert.get("generatorURL", ""),
        "receiver": payload.get("receiver", ""),
        "externalURL": payload.get("externalURL", ""),
        "groupKey": payload.get("groupKey", ""),
    }


# --------------------------------------------------------------------------- #
# Configuration file
# --------------------------------------------------------------------------- #
DEFAULT_SETTINGS = {
    "dry_run": False,          # log what would happen, touch nothing
    "cooldown": 300,           # seconds a (rule, alert) pair stays silent after firing
    "action_timeout": 30,      # per-action wall-clock budget
    "workers": 4,              # concurrent actions
    "allowed_namespaces": [],  # empty = every namespace; otherwise an allow-list
    "auth_token": "",          # when set, require `Authorization: Bearer <token>`
    "auth_token_secret": "",   # ... or name a credential to read it from
    # salt-api, for the machines that are not pods. Empty url = not configured,
    # and the salt_* actions fail with that message rather than half-trying.
    "salt": {
        "url": "",
        "eauth": "pam",
        "username": "",
        "password_secret": "",     # credential holding the password
        "token_secret": "",        # ... or a pre-issued token, instead
        "verify_tls": True,
        "timeout": 60,
        "allowed_targets": [],     # empty = any target; globs allowed
    },
    # An OpenAI-compatible chat endpoint - LiteLLM, vLLM, Ollama's /v1 shim,
    # a gateway. Empty url = not configured, same as salt.
    "llm": {
        "url": "",
        "model": "",
        "api_key_secret": "",
        "system": "You are an SRE assistant. Be concrete and brief.",
        "max_tokens": 400,
        "temperature": 0.2,
        "timeout": 60,
    },
}


class Config:
    def __init__(self, settings, rules):
        self.settings = settings
        self.rules = rules


def load_config(path):
    with open(path, "r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    settings = dict(DEFAULT_SETTINGS, **(raw.get("settings") or {}))
    # One level of depth is enough: `salt:` in a config usually sets url and
    # credentials only, and should keep the rest of the defaults.
    settings["salt"] = dict(DEFAULT_SETTINGS["salt"], **(settings.get("salt") or {}))
    settings["llm"] = dict(DEFAULT_SETTINGS["llm"], **(settings.get("llm") or {}))
    # A token in the file is convenient; a token in the environment keeps it out
    # of the ConfigMap. The environment wins.
    settings["auth_token"] = _env("WEBHOOK_TOKEN", settings["auth_token"])

    rules = []
    for index, rule in enumerate(raw.get("rules") or []):
        name = rule.get("name") or "rule-%d" % index
        actions = rule.get("actions") or []
        if not actions:
            raise ValueError("rule %r has no actions" % name)
        for action in actions:
            if action.get("type") not in ACTION_TYPES:
                raise ValueError(
                    "rule %r uses unknown action type %r (known: %s)"
                    % (name, action.get("type"), ", ".join(sorted(ACTION_TYPES)))
                )
        rules.append(
            {
                "name": name,
                "match": rule.get("match") or {},
                "match_re": {key: re.compile(pattern) for key, pattern in (rule.get("match_re") or {}).items()},
                "status": rule.get("status", "firing"),
                "cooldown": int(rule.get("cooldown", settings["cooldown"])),
                "continue": bool(rule.get("continue", True)),
                "actions": actions,
            }
        )
    return Config(settings, rules)


def matches(rule, alert):
    if rule["status"] != "any" and alert.get("status") != rule["status"]:
        return False
    labels = alert.get("labels", {})
    for key, value in rule["match"].items():
        if labels.get(key) != value:
            return False
    for key, pattern in rule["match_re"].items():
        if not pattern.fullmatch(labels.get(key, "")):
            return False
    return True


# --------------------------------------------------------------------------- #
# Kubernetes API client (in-cluster ServiceAccount, no vendored SDK)
# --------------------------------------------------------------------------- #
class KubeError(RuntimeError):
    pass


class KubeClient:
    """Just enough of the API to patch, scale and delete named objects."""

    WORKLOAD_PATHS = {
        "deployment": "apis/apps/v1/namespaces/%(namespace)s/deployments/%(name)s",
        "statefulset": "apis/apps/v1/namespaces/%(namespace)s/statefulsets/%(name)s",
        "daemonset": "apis/apps/v1/namespaces/%(namespace)s/daemonsets/%(name)s",
    }

    def __init__(self, api_url, token_file, ca_file):
        self.api_url = (api_url or "").rstrip("/")
        self.token_file = token_file
        self.ca_file = ca_file

    @property
    def available(self):
        return bool(self.api_url) and os.path.exists(self.token_file)

    def _token(self):
        # Projected ServiceAccount tokens are rotated in place, so re-read.
        with open(self.token_file, "r", encoding="utf-8") as handle:
            return handle.read().strip()

    def request(self, method, path, body=None, content_type="application/strategic-merge-patch+json", timeout=30):
        if not self.available:
            raise KubeError(
                "no Kubernetes API available (set K8S_API_URL/K8S_TOKEN_FILE, or run in-cluster with a ServiceAccount)"
            )
        url = "%s/%s" % (self.api_url, path.lstrip("/"))
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("Authorization", "Bearer %s" % self._token())
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", content_type)

        context = ssl.create_default_context(cafile=self.ca_file if os.path.exists(self.ca_file) else None)
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                return json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")[:400]
            raise KubeError("%s %s -> %s %s" % (method, path, error.code, detail)) from error
        except urllib.error.URLError as error:
            raise KubeError("%s %s -> %s" % (method, path, error.reason)) from error

    def workload_path(self, kind, namespace, name):
        try:
            template = self.WORKLOAD_PATHS[kind]
        except KeyError:
            raise KubeError("unsupported workload kind %r (use %s)" % (kind, ", ".join(self.WORKLOAD_PATHS)))
        return template % {"namespace": namespace, "name": name}


KUBE = KubeClient(K8S_API_URL, K8S_TOKEN_FILE, K8S_CA_FILE)


def guard_namespace(settings, namespace):
    allowed = settings["allowed_namespaces"]
    if allowed and namespace not in allowed:
        raise KubeError("namespace %r is not in allowed_namespaces %s" % (namespace, allowed))


# --------------------------------------------------------------------------- #
# Salt (salt-api), for the estate that is not in Kubernetes
#
# The netapi REST client: POST /login for a token, then POST / with a lowstate.
# Tokens are cached until they expire, so a burst of alerts is one login.
# --------------------------------------------------------------------------- #
class SaltError(RuntimeError):
    pass


class SaltClient:
    def __init__(self):
        self._lock = threading.Lock()
        self._token = None
        self._expires = 0.0

    def configured(self, settings):
        return bool(settings["salt"]["url"])

    def _request(self, settings, path, payload, token=None):
        salt = settings["salt"]
        url = "%s/%s" % (salt["url"].rstrip("/"), path.lstrip("/"))
        request = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), method="POST"
        )
        request.add_header("Content-Type", "application/json")
        request.add_header("Accept", "application/json")
        if token:
            request.add_header("X-Auth-Token", token)

        context = None
        if url.startswith("https://") and not salt["verify_tls"]:
            # Self-signed salt-api is the norm on a private network; make the
            # decision explicit in the config rather than silently trusting.
            context = ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(
                request, timeout=int(salt["timeout"]), context=context
            ) as response:
                return json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")[:400]
            raise SaltError("POST %s -> %s %s" % (url, error.code, detail)) from error
        except urllib.error.URLError as error:
            raise SaltError("POST %s -> %s" % (url, error.reason)) from error

    def token(self, settings, secrets):
        salt = settings["salt"]
        if salt["token_secret"]:
            token = secrets.get(salt["token_secret"])
            if not token:
                raise SaltError("no credential %r for the salt token" % salt["token_secret"])
            return token

        # The login happens under the lock on purpose: a group of alerts hits
        # several workers at once, and without it each one would open its own
        # session. The request has the configured timeout, so waiting is bounded.
        with self._lock:
            if self._token and time.time() < self._expires - 30:
                return self._token

            password = secrets.get(salt["password_secret"])
            if not password:
                raise SaltError(
                    "no credential %r in %s for the salt password" % (salt["password_secret"], SECRETS_DIR)
                )
            answer = self._request(
                settings,
                "login",
                {"eauth": salt["eauth"], "username": salt["username"], "password": password},
            )
            try:
                session = answer["return"][0]
                token, expires = session["token"], float(session.get("expire", time.time() + 600))
            except (KeyError, IndexError, TypeError, ValueError) as error:
                raise SaltError("salt-api login returned no token: %s" % error) from error
            self._token, self._expires = token, expires
            return token

    def call(self, settings, secrets, payload):
        if not self.configured(settings):
            raise SaltError("salt is not configured (set settings.salt.url)")
        answer = self._request(settings, "/", payload, token=self.token(settings, secrets))
        return (answer.get("return") or [{}])[0]


SALT = SaltClient()


def guard_target(settings, target):
    """Blast-radius fence for Salt, the counterpart of allowed_namespaces."""
    allowed = settings["salt"]["allowed_targets"]
    if allowed and not any(fnmatch.fnmatch(target, pattern) for pattern in allowed):
        raise SaltError("target %r is not in allowed_targets %s" % (target, allowed))


def _salt_summary(result):
    """One line: who answered, and the first bit of what they said."""
    if not isinstance(result, dict):
        return str(result)[:200]
    if not result:
        return "no minions matched"
    parts = []
    for minion in sorted(result)[:5]:
        value = result[minion]
        if isinstance(value, dict):
            failed = [
                key for key, state in value.items()
                if isinstance(state, dict) and state.get("result") is False
            ]
            parts.append("%s: %d states, %d failed" % (minion, len(value), len(failed)))
        else:
            parts.append("%s: %s" % (minion, str(value).strip().splitlines()[0][:80] if str(value).strip() else "ok"))
    if len(result) > 5:
        parts.append("... %d more" % (len(result) - 5))
    return "; ".join(parts)


def _salt_failed(result):
    """True when any minion reported a failed state, so the action counts as failed."""
    if not isinstance(result, dict):
        return False
    for value in result.values():
        if isinstance(value, dict):
            for state in value.values():
                if isinstance(state, dict) and state.get("result") is False:
                    return True
        elif isinstance(value, str) and value.startswith("The minion function caused an exception"):
            return True
    return False


# --------------------------------------------------------------------------- #
# Actions
#
# Each takes the rendered action spec plus the runtime settings and returns a
# short string for the log. Raising marks the action failed in the metrics.
# --------------------------------------------------------------------------- #
def action_log(spec, settings, actx):
    log.info("[action:log] %s", spec.get("message", ""))
    return "logged"


def action_http(spec, settings, actx):
    url = spec["url"]
    method = spec.get("method", "POST").upper()
    body = spec.get("body")
    if isinstance(body, (dict, list)):
        body = json.dumps(body)
    data = body.encode("utf-8") if body is not None else None

    request = urllib.request.Request(url, data=data, method=method)
    for key, value in (spec.get("headers") or {}).items():
        request.add_header(key, value)
    if data is not None and not any(key.lower() == "content-type" for key in (spec.get("headers") or {})):
        request.add_header("Content-Type", "application/json")

    timeout = int(spec.get("timeout", settings["action_timeout"]))
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return "%s %s -> %s" % (method, url, response.status)


def _run_command(command, spec, settings, actx, label):
    """Shared runner for `exec` and `runbook`: same env contract, same reporting."""
    env = dict(os.environ)
    env["RUNBOOK_DIR"] = RUNBOOK_DIR
    # Alert fields reach the script as ALERT_* so scripts need no JSON parsing,
    # and credentials only through the action's explicit `secret_env`; both are
    # merged into spec["env"] by the dispatcher.
    for key, value in (spec.get("env") or {}).items():
        env[key] = str(value)

    timeout = int(spec.get("timeout", settings["action_timeout"]))
    completed = subprocess.run(
        command,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    stdout = (completed.stdout or "").strip()
    # The next action in the rule can read this as {{ last.stdout }} - that is
    # what makes "collect diagnostics, then explain them" a two-line rule.
    actx.namespace["last"] = {
        "action": label,
        "stdout": stdout[:4000],
        "stderr": (completed.stderr or "").strip()[:2000],
        "exit_code": completed.returncode,
    }
    output = stdout.splitlines()
    tail = output[-1] if output else ""
    if completed.returncode != 0:
        raise RuntimeError(
            "%s: exit %d: %s" % (label, completed.returncode, (completed.stderr or tail).strip()[:400])
        )
    return "%s: exit 0: %s" % (label, tail[:200])


def action_exec(spec, settings, actx):
    command = spec["command"]
    if isinstance(command, str):
        command = ["/bin/sh", "-c", command]
    return _run_command(command, spec, settings, actx, "exec")


def action_runbook(spec, settings, actx):
    """Run a named script from the runbook directory (typically a ConfigMap).

    Keeping runbooks in a mounted directory means a new procedure is a config
    change, not a rebuilt image.
    """
    path = resolve_runbook(spec["name"])
    # ConfigMap keys mount 0644, so fall back to the shell when the bit is off.
    command = [path] if os.access(path, os.X_OK) else ["/bin/sh", path]
    command += [str(argument) for argument in (spec.get("args") or [])]
    return _run_command(command, spec, settings, actx, "runbook %s" % spec["name"])


def action_k8s_rollout_restart(spec, settings, actx):
    namespace, name, kind = spec["namespace"], spec["name"], spec.get("kind", "deployment")
    guard_namespace(settings, namespace)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    patch = {
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "kubectl.kubernetes.io/restartedAt": stamp,
                        "alert-handler.monitor/restarted-by": spec.get("_rule", "alert-handler"),
                    }
                }
            }
        }
    }
    KUBE.request("PATCH", KUBE.workload_path(kind, namespace, name), patch,
                 timeout=int(spec.get("timeout", settings["action_timeout"])))
    return "restarted %s %s/%s" % (kind, namespace, name)


def action_k8s_scale(spec, settings, actx):
    namespace, name, kind = spec["namespace"], spec["name"], spec.get("kind", "deployment")
    guard_namespace(settings, namespace)
    replicas = int(spec["replicas"])
    path = KUBE.workload_path(kind, namespace, name) + "/scale"
    KUBE.request("PATCH", path, {"spec": {"replicas": replicas}},
                 content_type="application/merge-patch+json",
                 timeout=int(spec.get("timeout", settings["action_timeout"])))
    return "scaled %s %s/%s to %d" % (kind, namespace, name, replicas)


def action_k8s_delete_pod(spec, settings, actx):
    namespace, name = spec["namespace"], spec["name"]
    guard_namespace(settings, namespace)
    path = "api/v1/namespaces/%s/pods/%s" % (namespace, name)
    KUBE.request("DELETE", path, timeout=int(spec.get("timeout", settings["action_timeout"])))
    return "deleted pod %s/%s" % (namespace, name)


def action_k8s_cordon_node(spec, settings, actx):
    name = spec["name"]
    unschedulable = bool(spec.get("unschedulable", True))
    KUBE.request("PATCH", "api/v1/nodes/%s" % name, {"spec": {"unschedulable": unschedulable}},
                 timeout=int(spec.get("timeout", settings["action_timeout"])))
    return "%s node %s" % ("cordoned" if unschedulable else "uncordoned", name)


def action_k8s_annotate(spec, settings, actx):
    """Annotate any namespaced workload or a node (the object it names, not its pods)."""
    annotations = spec["annotations"]
    if "node" in spec:
        path = "api/v1/nodes/%s" % spec["node"]
        target = "node %s" % spec["node"]
    else:
        namespace, name = spec["namespace"], spec["name"]
        guard_namespace(settings, namespace)
        kind = spec.get("kind", "deployment")
        path = KUBE.workload_path(kind, namespace, name)
        target = "%s %s/%s" % (kind, namespace, name)
    KUBE.request("PATCH", path, {"metadata": {"annotations": annotations}},
                 timeout=int(spec.get("timeout", settings["action_timeout"])))
    return "annotated %s" % target


def action_salt_cmd(spec, settings, actx):
    """Any execution module on any target: the generic escape hatch."""
    target = spec["tgt"]
    guard_target(settings, target)
    payload = {
        "client": "local",
        "tgt": target,
        "tgt_type": spec.get("tgt_type", "glob"),
        "fun": spec["fun"],
    }
    if spec.get("arg") is not None:
        payload["arg"] = spec["arg"] if isinstance(spec["arg"], list) else [spec["arg"]]
    if spec.get("kwarg"):
        payload["kwarg"] = spec["kwarg"]
    if spec.get("salt_timeout"):
        payload["timeout"] = int(spec["salt_timeout"])

    result = SALT.call(settings, actx.secrets, payload)
    summary = "salt %s %s: %s" % (target, spec["fun"], _salt_summary(result))
    if _salt_failed(result):
        raise SaltError(summary)
    return summary


def action_salt_state_apply(spec, settings, actx):
    """state.apply <state> on a target, with optional pillar and test=True."""
    state = spec.get("state")
    call = dict(spec)
    call["fun"] = "state.apply"
    call["arg"] = [state] if state else []
    kwarg = dict(spec.get("kwarg") or {})
    if spec.get("pillar"):
        kwarg["pillar"] = spec["pillar"]
    if spec.get("test") is not None:
        kwarg["test"] = bool(spec["test"])
    if kwarg:
        call["kwarg"] = kwarg
    return action_salt_cmd(call, settings, actx)


def action_salt_run(spec, settings, actx):
    """A runner on the master itself - manage.up, state.orchestrate, ..."""
    payload = {"client": "runner", "fun": spec["fun"]}
    if spec.get("arg") is not None:
        payload["arg"] = spec["arg"] if isinstance(spec["arg"], list) else [spec["arg"]]
    if spec.get("kwarg"):
        payload["kwarg"] = spec["kwarg"]
    result = SALT.call(settings, actx.secrets, payload)
    return "salt-run %s: %s" % (spec["fun"], str(result)[:200])




def action_llm(spec, settings, actx):
    """Ask an OpenAI-compatible endpoint about the alert, keep the answer.

    The answer lands in the namespace as {{ llm.answer }}, so the rule's next
    action can post it to chat, annotate the object, or hand it to a runbook.
    Nothing is decided by the model: it writes text, the rule decides what
    happens to it.
    """
    llm = settings["llm"]
    url = spec.get("url") or llm["url"]
    if not url:
        raise RuntimeError("llm is not configured (set settings.llm.url)")

    messages = []
    system = spec.get("system", llm["system"])
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": spec["prompt"]})

    body = {
        "model": spec.get("model") or llm["model"],
        "messages": messages,
        "max_tokens": int(spec.get("max_tokens", llm["max_tokens"])),
        "temperature": float(spec.get("temperature", llm["temperature"])),
    }
    request = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), method="POST"
    )
    request.add_header("Content-Type", "application/json")
    key_name = spec.get("api_key_secret") or llm["api_key_secret"]
    if key_name:
        key = actx.secrets.get(key_name)
        if not key:
            raise RuntimeError("no credential %r in %s for the llm api key" % (key_name, SECRETS_DIR))
        request.add_header("Authorization", "Bearer %s" % key)

    timeout = int(spec.get("timeout", llm["timeout"]))
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            answer = json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")[:300]
        raise RuntimeError("llm %s -> %s %s" % (url, error.code, detail)) from error
    except urllib.error.URLError as error:
        raise RuntimeError("llm %s -> %s" % (url, error.reason)) from error

    try:
        text = answer["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, TypeError) as error:
        raise RuntimeError("llm returned no choices: %s" % str(answer)[:200]) from error

    usage = answer.get("usage") or {}
    actx.namespace["llm"] = {
        "answer": text,
        "model": answer.get("model", body["model"]),
        "tokens": str(usage.get("total_tokens", "")),
    }
    return "llm %s: %d chars, %s tokens" % (
        answer.get("model", body["model"]), len(text), usage.get("total_tokens", "?")
    )


ACTION_TYPES = {
    "log": action_log,
    "http": action_http,
    "exec": action_exec,
    "runbook": action_runbook,
    "k8s_rollout_restart": action_k8s_rollout_restart,
    "k8s_scale": action_k8s_scale,
    "k8s_delete_pod": action_k8s_delete_pod,
    "k8s_cordon_node": action_k8s_cordon_node,
    "k8s_annotate": action_k8s_annotate,
    "salt_cmd": action_salt_cmd,
    "salt_state_apply": action_salt_state_apply,
    "salt_run": action_salt_run,
    "llm": action_llm,
}


# --------------------------------------------------------------------------- #
# Dispatcher
# --------------------------------------------------------------------------- #
class Dispatcher:
    def __init__(self, config):
        self._lock = threading.Lock()
        self._last_run = {}      # (rule name, fingerprint) -> unix time
        self.set_config(config)

    def set_config(self, config):
        # Credentials and runbooks are re-read with the config, so SIGHUP picks
        # up a rotated Secret or a new script without a restart.
        secrets = load_secrets()
        with self._lock:
            self.config = config
            self.secrets = secrets
            self.redact = Redactor(secrets)
        CONFIG_RULES.set(len(config.rules))
        CONFIG_LOADED.set(time.time())
        CONFIG_VALID.set(1)
        SECRETS_LOADED.set(len(secrets))
        RUNBOOKS_AVAILABLE.set(len(list_runbooks()))

    @property
    def settings(self):
        return self.config.settings

    @property
    def auth_token(self):
        """Webhook token, either inline in settings or named as a credential."""
        credential = self.settings.get("auth_token_secret")
        if credential:
            return self.secrets.get(credential, "")
        return self.settings["auth_token"]

    def handle_payload(self, payload, pool):
        """Match every alert in the group and queue the actions of each hit."""
        queued = 0
        for alert in payload.get("alerts") or []:
            ALERTS.labels(status=alert.get("status", "unknown")).inc()
            context = alert_context(alert, payload, self.secrets)
            for rule in self.config.rules:
                if not matches(rule, alert):
                    continue
                MATCHES.labels(rule=rule["name"]).inc()
                if self._cooling_down(rule, alert):
                    for action in rule["actions"]:
                        ACTIONS.labels(rule=rule["name"], action=action["type"], result="cooldown").inc()
                    log.info("rule %s matched %s but is in cooldown", rule["name"], _alert_id(alert))
                else:
                    # One task per (rule, alert): the actions run in order and
                    # share a namespace, so a later action can use what an
                    # earlier one produced.
                    pool.submit(self.run_rule, rule, dict(context), alert)
                    queued += len(rule["actions"])
                if not rule["continue"]:
                    break
        return queued

    def _cooling_down(self, rule, alert):
        if rule["cooldown"] <= 0:
            return False
        key = (rule["name"], alert.get("fingerprint") or json.dumps(alert.get("labels", {}), sort_keys=True))
        now = time.time()
        with self._lock:
            last = self._last_run.get(key, 0)
            if now - last < rule["cooldown"]:
                return True
            self._last_run[key] = now
        return False

    def prepare_command_env(self, spec, context):
        """Alert fields plus the credentials this action asked for, by name."""
        env = spec.setdefault("env", {})
        env.update(_alert_env(context))
        for variable, credential in (spec.pop("secret_env", None) or {}).items():
            if credential not in self.secrets:
                raise RuntimeError("no credential %r in %s" % (credential, SECRETS_DIR))
            env[variable] = self.secrets[credential]

    def run_rule(self, rule, namespace, alert):
        """Run a rule's actions in order, sharing one namespace.

        A failed action stops the rest of the chain: if the diagnostic did not
        run there is nothing to explain, and nothing to announce. An action that
        should not stop it sets `continue_on_error: true`.
        """
        actx = ActionContext(self.secrets, namespace)
        stopped = False
        for index, action in enumerate(rule["actions"]):
            if stopped:
                ACTIONS.labels(rule=rule["name"], action=action["type"], result="skipped").inc()
                continue
            if not self.run_action(rule, action, actx, alert) and not action.get("continue_on_error"):
                stopped = True
                if index + 1 < len(rule["actions"]):
                    log.warning(
                        "rule %s stopped after %s failed, %d action(s) skipped",
                        rule["name"], action["type"], len(rule["actions"]) - index - 1,
                    )

    def run_action(self, rule, action, actx, alert):
        """Run one action. Returns True on success, False on failure."""
        kind = action["type"]
        # Rendered here rather than up front: an earlier action in this rule may
        # have added to the namespace ({{ last.stdout }}, {{ llm.answer }}).
        spec = render({key: value for key, value in action.items() if key != "type"}, actx.namespace)
        spec["_rule"] = rule["name"]

        settings = self.settings
        if settings["dry_run"]:
            ACTIONS.labels(rule=rule["name"], action=kind, result="dry_run").inc()
            log.info("[dry-run] rule %s would run %s: %s", rule["name"], kind, self.redact(_summarise(spec)))
            return True

        INFLIGHT.inc()
        started = time.time()
        try:
            if kind in ("exec", "runbook"):
                self.prepare_command_env(spec, actx.namespace)
            outcome = ACTION_TYPES[kind](spec, settings, actx)
            ACTIONS.labels(rule=rule["name"], action=kind, result="success").inc()
            log.info("rule %s ran %s for %s: %s", rule["name"], kind, _alert_id(alert), self.redact(outcome))
            return True
        except Exception as error:  # noqa: BLE001 - an action must never kill the worker
            ACTIONS.labels(rule=rule["name"], action=kind, result="failure").inc()
            log.error("rule %s failed %s for %s: %s", rule["name"], kind, _alert_id(alert), self.redact(error))
            return False
        finally:
            ACTION_SECONDS.labels(rule=rule["name"], action=kind).observe(time.time() - started)
            INFLIGHT.dec()


def _alert_env(context):
    env = {
        "ALERT_STATUS": context["status"],
        "ALERT_FINGERPRINT": context["fingerprint"],
        "ALERT_STARTS_AT": context["startsAt"],
        "ALERT_LABELS": json.dumps(context["labels"]),
        "ALERT_ANNOTATIONS": json.dumps(context["annotations"]),
    }
    for key, value in context["labels"].items():
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            env["ALERT_LABEL_" + key.upper()] = str(value)
    return env


def _alert_id(alert):
    labels = alert.get("labels", {})
    return "%s{%s}" % (
        labels.get("alertname", "?"),
        ",".join("%s=%s" % (key, labels[key]) for key in sorted(labels) if key != "alertname"),
    )


def _summarise(spec):
    return json.dumps({key: value for key, value in spec.items() if not key.startswith("_")}, sort_keys=True)[:300]


# --------------------------------------------------------------------------- #
# HTTP server
# --------------------------------------------------------------------------- #
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    dispatcher = None
    pool = None

    def _respond(self, status, body=b"", content_type="text/plain; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _authorised(self):
        token = self.dispatcher.auth_token
        if not token:
            return True
        return self.headers.get("Authorization", "") == "Bearer %s" % token

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        path = self.path.split("?", 1)[0]
        if path == "/metrics":
            self._respond(200, generate_latest(), CONTENT_TYPE_LATEST)
        elif path in ("/healthz", "/-/healthy"):
            self._respond(200, b"ok\n")
        elif path in ("/-/ready", "/readyz"):
            self._respond(200 if self.dispatcher.config.rules else 503,
                          b"ready\n" if self.dispatcher.config.rules else b"no rules loaded\n")
        elif path == "/rules":
            rules = [
                {
                    "name": rule["name"],
                    "match": rule["match"],
                    "match_re": {key: pattern.pattern for key, pattern in rule["match_re"].items()},
                    "status": rule["status"],
                    "cooldown": rule["cooldown"],
                    "actions": [action["type"] for action in rule["actions"]],
                }
                for rule in self.dispatcher.config.rules
            ]
            self._respond(200, json.dumps(rules, indent=2).encode(), "application/json")
        elif path == "/runbooks":
            # Names only: a runbook may well contain a hostname you would rather
            # not hand out, and the contents are in the ConfigMap anyway.
            self._respond(200, json.dumps(list_runbooks(), indent=2).encode(), "application/json")
        elif path == "/":
            self._respond(200, b"alert-handler: POST Alertmanager webhooks to /alert\n")
        else:
            self._respond(404, b"not found\n")

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
        path = self.path.split("?", 1)[0]
        if path not in ("/alert", "/alerts", "/webhook", "/"):
            self._respond(404, b"not found\n")
            return
        if not self._authorised():
            WEBHOOKS.labels(result="unauthorised").inc()
            self._respond(401, b"unauthorised\n")
            return

        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw)
        except ValueError as error:
            WEBHOOKS.labels(result="bad_request").inc()
            self._respond(400, ("invalid JSON: %s\n" % error).encode())
            return

        try:
            queued = self.dispatcher.handle_payload(payload, self.pool)
        except Exception as error:  # noqa: BLE001 - never 500 a webhook into a retry storm
            WEBHOOKS.labels(result="error").inc()
            log.exception("failed to handle payload: %s", error)
            self._respond(500, b"error\n")
            return

        WEBHOOKS.labels(result="accepted").inc()
        # 202: the alerts are ours now, the actions are still running.
        self._respond(202, json.dumps({"queued": queued}).encode(), "application/json")

    def log_message(self, format, *args):  # noqa: A002 - BaseHTTPRequestHandler API
        log.debug("%s - %s", self.address_string(), format % args)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def main():
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    try:
        config = load_config(CONFIG_FILE)
    except (OSError, ValueError, yaml.YAMLError) as error:
        CONFIG_VALID.set(0)
        sys.exit("FATAL: cannot load %s: %s" % (CONFIG_FILE, error))

    dispatcher = Dispatcher(config)
    pool = ThreadPoolExecutor(max_workers=config.settings["workers"], thread_name_prefix="action")

    def reload_config(signum, frame):
        """SIGHUP: pick up a rewritten ConfigMap without dropping the listener."""
        try:
            dispatcher.set_config(load_config(CONFIG_FILE))
            log.info(
                "reloaded %s (%d rules, %d runbooks, %d credentials)",
                CONFIG_FILE,
                len(dispatcher.config.rules),
                len(list_runbooks()),
                len(dispatcher.secrets),
            )
        except (OSError, ValueError, yaml.YAMLError) as error:
            CONFIG_VALID.set(0)
            log.error("keeping previous configuration, %s is broken: %s", CONFIG_FILE, error)

    signal.signal(signal.SIGHUP, reload_config)

    Handler.dispatcher = dispatcher
    Handler.pool = pool
    server = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Handler)
    log.info(
        "listening on :%d with %d rules, dry_run=%s, kubernetes=%s, salt=%s, llm=%s, runbooks=%d, credentials=%d",
        HTTP_PORT,
        len(config.rules),
        config.settings["dry_run"],
        "in-cluster" if KUBE.available else "unavailable",
        config.settings["salt"]["url"] or "unconfigured",
        config.settings["llm"]["url"] or "unconfigured",
        len(list_runbooks()),
        len(dispatcher.secrets),
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        pool.shutdown(wait=False)


if __name__ == "__main__":
    main()
