#!/usr/bin/env python3
"""Alertmanager webhook handler that runs actions.

Alertmanager posts a group of alerts to `/alert`; every alert is matched against
an ordered list of rules from the config file, and each matching rule runs its
actions: an outbound HTTP call, a command from the image, a log line, or a write
against the Kubernetes API (rollout restart, scale, delete pod, cordon node,
annotate).

Rules with `incident: true` also open an incident per firing alert: the
silence the handler set, the mitigations it ran, the ticket, and the person who
closed it. Any action can wait for a person (`approval: required`) on the
/approvals page, and an incident is closed by a person - in Jira, or on the
/incidents page - which lifts the silences again.

The point is self-healing and enrichment that does not deserve its own operator:
"restart the deployment that is crash-looping", "scale the worker pool when the
queue alert fires", "post the runbook link to chat". Everything an action does is
counted in Prometheus metrics on :8080/metrics, so the handler itself is
monitored like any other service.

Actions run on a small thread pool: the webhook answers Alertmanager immediately
(it retries aggressively on slow receivers) and the work happens in the
background.
"""

import base64
import binascii
import copy
import fnmatch
import functools
import hashlib
import html
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
import urllib.parse
import urllib.request
import uuid
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
INCIDENTS = Gauge(
    "alert_handler_incidents",
    "Incidents the handler tracks, by state.",
    ["state"],
)
APPROVALS_PENDING = Gauge(
    "alert_handler_approvals_pending",
    "Actions waiting for a person to approve them.",
)
APPROVAL_DECISIONS = Counter(
    "alert_handler_approval_decisions_total",
    "What became of approvals: approved, rejected, expired, cancelled.",
    ["decision"],
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


def render(value, context, preview=False):
    """Render {{ path }} placeholders in strings, recursing into lists/dicts.

    `preview` is for showing a step before it runs (the approvals page): what
    is not known yet - {{ approval.by }}, {{ jira.key }} - stays as written
    instead of rendering empty, and nothing is logged about it.
    """
    if isinstance(value, str):
        return _TEMPLATE_RE.sub(lambda match: _lookup(match, context, preview), value)
    if isinstance(value, list):
        return [render(item, context, preview) for item in value]
    if isinstance(value, dict):
        return {key: render(item, context, preview) for key, item in value.items()}
    return value


def _lookup(match, context, preview=False):
    path = match.group(1)
    node = context
    for part in path.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            if preview:
                return match.group(0)
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

    def __init__(self, secrets, namespace, store=None, alert=None):
        self.secrets = secrets
        self.namespace = namespace
        self.store = store
        self.alert = alert or {}

    @property
    def incident_id(self):
        """The incident this run belongs to, when its rule tracks incidents."""
        incident = self.namespace.get("incident")
        return incident.get("id", "") if isinstance(incident, dict) else ""


def alert_fingerprint(alert):
    """Alertmanager's fingerprint, or a stable hash of the labels when it sent none."""
    return alert.get("fingerprint") or hashlib.sha1(
        json.dumps(alert.get("labels", {}), sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]


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
    # How people reach this handler (its ingress); approval and incident links
    # in notifications and tickets are built on it. Empty = relative links.
    "public_url": "",
    # Incidents and pending approvals survive a restart when this names a file
    # on a volume. Empty keeps them in memory only.
    "state_file": "",
    # The Alertmanager am_silence/am_expire talk to: a plain one
    # (http://alertmanager:9093) or a Mimir tenant's
    # (http://mimir:9009/alertmanager with `tenant`). Actions may override both.
    "alertmanager": {
        "url": "",
        "tenant": "",              # X-Scope-OrgID
        "token_secret": "",        # credential holding a bearer token, if it wants one
        "verify_tls": True,
        "timeout": 10,
    },
    # Jira Cloud (api_version 3: bodies in Atlassian Document Format, the
    # account email in `user` plus an API token) or Server/Data Center
    # (api_version 2, a personal access token and no `user`). Empty url = the
    # jira_* actions fail with that message.
    "jira": {
        "url": "",
        "api_version": "3",
        "user": "",
        "token_secret": "",
        "project": "",
        "issue_type": "Task",
        "labels": ["alert-handler"],
        "verify_tls": True,
        "timeout": 15,
        "poll_interval": 120,      # seconds between checks of open incidents' tickets; 0 = never
    },
    "approvals": {
        "ttl": "24h",              # a pending approval expires after this
        "cancel_on_resolve": True,  # the alert resolving first withdraws it
        "notify": None,            # an action run when something starts to wait
    },
    "incidents": {
        "retention": "7d",         # closed incidents and settled approvals stay listed this long
        "check_interval": 60,      # housekeeping: expiries, silenced alerts, tickets
        "comment_on_resolve": True,  # tell the ticket when the alert resolves
        "resolve_transition": "",  # Jira transition run when a person closes on /incidents
    },
}

_NESTED_SETTINGS = ("salt", "llm", "alertmanager", "jira", "approvals", "incidents")
_APPROVAL_VALUES = {"auto": False, "none": False, "required": True, "human": True, "manual": True}


def _gated(action):
    """Does this action wait for a person? `approval: required` (or `true`)."""
    value = action.get("approval", "auto")
    if isinstance(value, bool):
        return value
    return _APPROVAL_VALUES.get(str(value).lower(), False)


_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$")


def parse_duration(value, default=0):
    """Seconds from 90, "90", "30m", "4h" or "2d"."""
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        raise ValueError("not a duration: %r" % value)
    if isinstance(value, (int, float)):
        return int(value)
    match = _DURATION_RE.match(str(value))
    if not match:
        raise ValueError("not a duration: %r (use 90, 30m, 4h or 2d)" % value)
    return int(match.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]


def _iso(timestamp=None):
    moment = time.time() if timestamp is None else timestamp
    return datetime.fromtimestamp(moment, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
    for section in _NESTED_SETTINGS:
        settings[section] = dict(DEFAULT_SETTINGS[section], **(settings.get(section) or {}))
    for section, key in (("approvals", "ttl"), ("incidents", "retention"), ("incidents", "check_interval")):
        try:
            parse_duration(settings[section][key])
        except ValueError as error:
            raise ValueError("settings.%s.%s: %s" % (section, key, error)) from error
    notify = settings["approvals"].get("notify")
    if notify and (not isinstance(notify, dict) or notify.get("type") not in ACTION_TYPES):
        raise ValueError("settings.approvals.notify must be an action with a known type (known: %s)"
                         % ", ".join(sorted(ACTION_TYPES)))
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
            approval = action.get("approval", "auto")
            if not isinstance(approval, bool) and str(approval).lower() not in _APPROVAL_VALUES:
                raise ValueError(
                    "rule %r: approval %r on %s (use auto or required)" % (name, approval, action["type"])
                )
        rules.append(
            {
                "name": name,
                "match": rule.get("match") or {},
                "match_re": {key: re.compile(pattern) for key, pattern in (rule.get("match_re") or {}).items()},
                "status": rule.get("status", "firing"),
                "cooldown": int(rule.get("cooldown", settings["cooldown"])),
                "continue": bool(rule.get("continue", True)),
                # One incident per firing alert: its silences, ticket and timeline.
                "incident": bool(rule.get("incident", False)),
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
    message = spec.get("message", "")
    log.info("[action:log] %s", message)
    # The message itself, so an incident's timeline says what was noted.
    return "logged: %s" % message[:200] if message else "logged"


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

# --------------------------------------------------------------------------- #
# JSON over HTTP, shared by the Alertmanager and Jira clients
# --------------------------------------------------------------------------- #
def _http_json(method, url, body=None, headers=None, timeout=10, verify_tls=True, error=RuntimeError):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    context = ssl._create_unverified_context() if url.startswith("https://") and not verify_tls else None
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            raw = response.read()
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as failure:
        detail = failure.read().decode("utf-8", "replace")[:400]
        raise error("%s %s -> %s %s" % (method, url.split("?", 1)[0], failure.code, detail)) from failure
    except urllib.error.URLError as failure:
        raise error("%s %s -> %s" % (method, url.split("?", 1)[0], failure.reason)) from failure


# --------------------------------------------------------------------------- #
# Alertmanager: silences, and asking whether a silenced alert still fires
#
# A silenced alert is muted in Alertmanager's pipeline, its resolution
# included, so while an incident holds a silence the handler hears nothing
# more about it by webhook and asks Alertmanager itself instead.
# --------------------------------------------------------------------------- #
class AlertmanagerError(RuntimeError):
    pass


def _am_target(settings, spec=None):
    """url, tenant and token credential for a call: the action's own, else settings."""
    am, spec = settings["alertmanager"], spec or {}
    url = (spec.get("url") or am["url"] or "").rstrip("/")
    if not url:
        raise AlertmanagerError("alertmanager is not configured (set settings.alertmanager.url or the action's url)")
    return {
        "url": url,
        "tenant": spec.get("tenant") if spec.get("tenant") is not None else am["tenant"],
        "token_secret": spec.get("token_secret") or am["token_secret"],
    }


def am_request(settings, secrets, target, method, path, body=None):
    headers = {}
    if target.get("tenant"):
        headers["X-Scope-OrgID"] = target["tenant"]
    if target.get("token_secret"):
        token = secrets.get(target["token_secret"])
        if not token:
            raise AlertmanagerError("no credential %r in %s for the alertmanager token" % (target["token_secret"], SECRETS_DIR))
        headers["Authorization"] = "Bearer %s" % token
    am = settings["alertmanager"]
    return _http_json(method, target["url"] + path, body, headers, int(am["timeout"]), am["verify_tls"], AlertmanagerError)


def am_expire_silence(settings, secrets, silence):
    """Expire one recorded silence; one that is already gone counts as done."""
    try:
        am_request(settings, secrets, silence, "DELETE", "/api/v2/silence/%s" % silence["id"])
    except AlertmanagerError as error:
        if "already expired" in str(error) or " 404 " in str(error):
            return
        raise


def am_alert_active(settings, secrets, silence, incident):
    """Does that Alertmanager still hold the incident's alert, silenced or not?"""
    query = urllib.parse.urlencode([
        ("active", "true"), ("silenced", "true"), ("inhibited", "true"), ("unprocessed", "true"),
        ("filter", 'alertname="%s"' % incident["alertname"]),
    ])
    alerts = am_request(settings, secrets, silence, "GET", "/api/v2/alerts?" + query)
    for alert in alerts if isinstance(alerts, list) else []:
        if alert.get("fingerprint") == incident["fingerprint"] or alert.get("labels") == incident["labels"]:
            return True
    return False


def _alert_labels(actx):
    return (actx.alert or {}).get("labels") or actx.namespace.get("labels") or {}


def action_am_silence(spec, settings, actx):
    """Silence this alert for a while, so it stops paging while it is handled.

    Matches the alert's labels exactly (all of them, or the ones listed in
    `labels`). An incident holds at most one live silence: a repeated run
    reports the one it has instead of stacking another.
    """
    labels = _alert_labels(actx)
    names = spec.get("labels") or sorted(labels)
    missing = [name for name in names if name not in labels]
    if missing:
        raise AlertmanagerError("the alert has no label %s to silence on" % ", ".join(missing))
    if not names:
        raise AlertmanagerError("nothing to silence on: the alert has no labels")
    now = time.time()
    if actx.incident_id and actx.store is not None:
        live = actx.store.active_silence(actx.incident_id, now)
        if live:
            actx.namespace["silence"] = {"id": live["id"], "until": _iso(live["ends_at"])}
            return "already silenced by %s until %s" % (live["id"], _iso(live["ends_at"]))

    duration = parse_duration(spec.get("duration"), 7200)
    target = _am_target(settings, spec)
    incident = actx.namespace.get("incident") if isinstance(actx.namespace.get("incident"), dict) else {}
    comment = spec.get("comment") or "alert-handler, rule %s%s" % (
        spec.get("_rule", "?"), (" - " + incident["url"]) if incident.get("url") else ""
    )
    body = {
        "matchers": [{"name": name, "value": labels[name], "isRegex": False, "isEqual": True} for name in names],
        "startsAt": _iso(now),
        "endsAt": _iso(now + duration),
        "createdBy": spec.get("created_by", "alert-handler"),
        "comment": comment,
    }
    answer = am_request(settings, actx.secrets, target, "POST", "/api/v2/silences", body)
    silence_id = answer.get("silenceID") or answer.get("silenceId") or ""
    if not silence_id:
        raise AlertmanagerError("alertmanager returned no silence id: %s" % str(answer)[:200])
    actx.namespace["silence"] = {"id": silence_id, "until": _iso(now + duration)}
    if actx.incident_id and actx.store is not None:
        actx.store.add_silence(actx.incident_id, dict(target, id=silence_id, created=now, ends_at=now + duration, expired=None))
    return "silenced %s for %ds as %s" % (",".join(names), duration, silence_id)


def action_am_expire(spec, settings, actx):
    """Expire a named silence, or every live silence this incident set."""
    if spec.get("id"):
        target = _am_target(settings, spec)
        am_expire_silence(settings, actx.secrets, dict(target, id=spec["id"]))
        if actx.incident_id and actx.store is not None:
            actx.store.silence_expired(actx.incident_id, spec["id"])
        return "expired silence %s" % spec["id"]
    if not actx.incident_id or actx.store is None:
        raise AlertmanagerError("am_expire needs an `id`, or a rule with `incident: true` whose silences to expire")
    done = []
    for silence in (actx.store.get(actx.incident_id) or {}).get("silences", []):
        if silence.get("expired"):
            continue
        am_expire_silence(settings, actx.secrets, silence)
        actx.store.silence_expired(actx.incident_id, silence["id"])
        done.append(silence["id"])
    return "expired %s" % (", ".join(done) or "nothing: no live silences")


# --------------------------------------------------------------------------- #
# Jira: open a ticket per alert, comment on it, move it
#
# One ticket per alert: every ticket carries the label alertfp-<fingerprint>,
# and jira_create looks for an open one before it opens another, so a
# re-firing alert comments on its ticket instead of opening a duplicate.
# --------------------------------------------------------------------------- #
class JiraError(RuntimeError):
    pass


def jira_configured(settings):
    return bool(settings["jira"]["url"])


def jira_request(settings, secrets, method, path, body=None):
    jira = settings["jira"]
    if not jira["url"]:
        raise JiraError("jira is not configured (set settings.jira.url)")
    headers = {}
    if jira["token_secret"]:
        token = secrets.get(jira["token_secret"])
        if not token:
            raise JiraError("no credential %r in %s for the jira token" % (jira["token_secret"], SECRETS_DIR))
        if jira["user"]:
            # Jira Cloud: the account email and an API token, as basic auth.
            pair = ("%s:%s" % (jira["user"], token)).encode("utf-8")
            headers["Authorization"] = "Basic %s" % base64.b64encode(pair).decode("ascii")
        else:
            # Server / Data Center: a personal access token.
            headers["Authorization"] = "Bearer %s" % token
    url = "%s/rest/api/%s/%s" % (jira["url"].rstrip("/"), jira["api_version"], path.lstrip("/"))
    return _http_json(method, url, body, headers, int(jira["timeout"]), jira["verify_tls"], JiraError)


def adf(text):
    """Plain text as Atlassian Document Format: blank lines split paragraphs."""
    content = []
    for block in str(text).split("\n\n"):
        nodes = []
        for number, line in enumerate(block.split("\n")):
            if number:
                nodes.append({"type": "hardBreak"})
            if line:
                nodes.append({"type": "text", "text": line})
        content.append({"type": "paragraph", "content": nodes} if nodes else {"type": "paragraph"})
    return {"type": "doc", "version": 1, "content": content}


def jira_text(settings, text):
    """A description or comment body: plain text for API 2, ADF for API 3."""
    return text if str(settings["jira"]["api_version"]) == "2" else adf(text)


def jira_issue_url(settings, key):
    return "%s/browse/%s" % (settings["jira"]["url"].rstrip("/"), key)


def jira_fingerprint_label(fingerprint):
    return "alertfp-%s" % re.sub(r"[^A-Za-z0-9_-]", "", str(fingerprint))[:40]


def jira_open_issue(settings, secrets, fingerprint):
    """The key of this alert's ticket while it is not done, else None."""
    jql = 'labels = "%s" AND statusCategory != Done ORDER BY created DESC' % jira_fingerprint_label(fingerprint)
    # Cloud retired /search for /search/jql; Server/DC still has /search.
    path = "search/jql" if str(settings["jira"]["api_version"]) == "3" else "search"
    answer = jira_request(settings, secrets, "POST", path, {"jql": jql, "fields": ["status"], "maxResults": 1})
    issues = answer.get("issues") or []
    return issues[0]["key"] if issues else None


def jira_add_comment(settings, secrets, key, text):
    jira_request(settings, secrets, "POST", "issue/%s/comment" % key, {"body": jira_text(settings, text)})


def jira_transition_issue(settings, secrets, key, name):
    """Move an issue by transition name (or target status name), case-insensitively."""
    available = jira_request(settings, secrets, "GET", "issue/%s/transitions" % key).get("transitions") or []
    for transition in available:
        target = (transition.get("to") or {}).get("name", "")
        if name.lower() in (transition.get("name", "").lower(), target.lower()):
            jira_request(settings, secrets, "POST", "issue/%s/transitions" % key, {"transition": {"id": transition["id"]}})
            return transition.get("name") or target
    raise JiraError("%s has no transition %r (available: %s)" % (
        key, name, ", ".join(transition.get("name", "?") for transition in available) or "none"))


def jira_get_issue(settings, secrets, key, fields="status,assignee"):
    return jira_request(settings, secrets, "GET", "issue/%s?fields=%s" % (key, fields))


def default_description(namespace):
    """What a ticket says when the rule gives no `description`."""
    labels = namespace.get("labels") or {}
    annotations = namespace.get("annotations") or {}
    lines = [annotations[key] for key in ("summary", "description") if annotations.get(key)]
    lines += ["", "Alert: %s" % labels.get("alertname", "?"),
              "Labels: %s" % ", ".join("%s=%s" % (key, labels[key]) for key in sorted(labels))]
    if namespace.get("startsAt"):
        lines.append("Firing since: %s" % namespace["startsAt"])
    if namespace.get("generatorURL"):
        lines.append("Source: %s" % namespace["generatorURL"])
    if annotations.get("runbook_url"):
        lines.append("Runbook: %s" % annotations["runbook_url"])
    if namespace.get("steps"):
        lines += ["", "What alert-handler has done so far:", namespace["steps"]]
    approval = namespace.get("approval") if isinstance(namespace.get("approval"), dict) else {}
    if approval.get("by"):
        lines += ["", "Approved by %s at %s." % (approval["by"], approval.get("at", "?"))]
    incident = namespace.get("incident") if isinstance(namespace.get("incident"), dict) else {}
    if incident.get("url"):
        lines += ["", "Incident: %s" % incident["url"]]
    lines += ["", "Close this ticket once the problem is solved: alert-handler then lifts the silences "
                  "it set, and if the alert still fires it pages again."]
    return "\n".join(lines).strip()


def _remember_issue(actx, settings, key, created):
    url = jira_issue_url(settings, key)
    actx.namespace["jira"] = {"key": key, "url": url, "created": "true" if created else "false"}
    if actx.incident_id and actx.store is not None:
        actx.store.set_jira(actx.incident_id, key, url)


def _alert_fp(actx):
    if actx.alert:
        return alert_fingerprint(actx.alert)
    return alert_fingerprint({"fingerprint": actx.namespace.get("fingerprint"), "labels": actx.namespace.get("labels", {})})


def action_jira_create(spec, settings, actx):
    """Open a ticket for the alert, or comment on its open one."""
    jira = settings["jira"]
    fingerprint = _alert_fp(actx)
    if spec.get("dedup", True):
        key = jira_open_issue(settings, actx.secrets, fingerprint)
        if key:
            text = spec.get("refire_comment") or "The alert fired again at %s.%s" % (
                _iso(), ("\n\n" + actx.namespace["steps"]) if actx.namespace.get("steps") else "")
            jira_add_comment(settings, actx.secrets, key, text)
            _remember_issue(actx, settings, key, created=False)
            return "commented on open %s instead of opening a duplicate" % key

    project = spec.get("project") or jira["project"]
    if not project:
        raise JiraError("no project: set settings.jira.project or the action's project")
    labels = _alert_labels(actx)
    annotations = actx.namespace.get("annotations") or {}
    summary = spec.get("summary") or "%s%s" % (
        labels.get("alertname", "alert"), (": " + annotations["summary"]) if annotations.get("summary") else "")
    fields = {
        "project": {"key": project},
        "issuetype": {"name": spec.get("issue_type") or jira["issue_type"]},
        "summary": summary.replace("\n", " ")[:250],
        "description": jira_text(settings, spec.get("description") or default_description(actx.namespace)),
        "labels": sorted(set(list(jira["labels"] or []) + list(spec.get("labels") or [])
                             + [jira_fingerprint_label(fingerprint)])),
    }
    if spec.get("priority"):
        fields["priority"] = {"name": spec["priority"]}
    if spec.get("components"):
        fields["components"] = [{"name": name} for name in spec["components"]]
    fields.update(spec.get("fields") or {})
    answer = jira_request(settings, actx.secrets, "POST", "issue", {"fields": fields})
    key = answer.get("key")
    if not key:
        raise JiraError("jira opened no issue: %s" % str(answer)[:200])
    _remember_issue(actx, settings, key, created=True)
    return "opened %s" % key


def _issue_key(spec, settings, actx):
    """The ticket to act on: named, from this chain, the incident's, or found by fingerprint."""
    key = spec.get("issue") or ""
    if not key and isinstance(actx.namespace.get("jira"), dict):
        key = actx.namespace["jira"].get("key", "")
    if not key and actx.incident_id and actx.store is not None:
        key = ((actx.store.get(actx.incident_id) or {}).get("jira") or {}).get("key")
    if not key:
        key = jira_open_issue(settings, actx.secrets, _alert_fp(actx))
    if not key:
        raise JiraError("no ticket for this alert: give the action an `issue`, or run jira_create first")
    return key


def action_jira_comment(spec, settings, actx):
    key = _issue_key(spec, settings, actx)
    jira_add_comment(settings, actx.secrets, key, spec["body"])
    _remember_issue(actx, settings, key, created=False)
    return "commented on %s" % key


def action_jira_transition(spec, settings, actx):
    key = _issue_key(spec, settings, actx)
    if spec.get("comment"):
        jira_add_comment(settings, actx.secrets, key, spec["comment"])
    moved = jira_transition_issue(settings, actx.secrets, key, spec["transition"])
    _remember_issue(actx, settings, key, created=False)
    return "moved %s through %s" % (key, moved)


# --------------------------------------------------------------------------- #
# Incidents and approvals
# --------------------------------------------------------------------------- #
INCIDENT_STATES = ("open", "alert_resolved", "closed")


class IncidentStore:
    """Incidents, and the approvals that wait on people.

    An incident is one firing alert a rule with `incident: true` matched: what
    the handler did about it, its ticket, the silences it set, and who closed
    it. Everything lives in memory and, when `settings.state_file` names a file
    on a volume, is written through after every change, so a restart loses
    nothing. No credential reaches the file: a paused chain is saved without
    `secrets`, and with every credential value redacted from the rest.
    """

    def __init__(self, path=""):
        self.path = path or ""
        self._lock = threading.RLock()
        self.incidents = {}
        self.approvals = {}
        self._load()
        self._refresh_gauges()

    # -- persistence --------------------------------------------------------
    def _load(self):
        if not self.path or not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError) as error:
            log.error("cannot read state file %s, starting empty: %s", self.path, error)
            return
        self.incidents = data.get("incidents") or {}
        self.approvals = data.get("approvals") or {}
        log.info("state: %d incidents and %d approvals from %s", len(self.incidents), len(self.approvals), self.path)

    def _save(self):
        """Write through; the caller holds the lock."""
        self._refresh_gauges()
        if not self.path:
            return
        data = json.dumps({"incidents": self.incidents, "approvals": self.approvals}, indent=1, sort_keys=True)
        temporary = self.path + ".tmp"
        try:
            if os.path.dirname(self.path):
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(temporary, "w", encoding="utf-8") as handle:
                handle.write(data)
            os.replace(temporary, self.path)
        except OSError as error:
            log.error("cannot write state file %s: %s", self.path, error)

    def _refresh_gauges(self):
        counts = dict.fromkeys(INCIDENT_STATES, 0)
        for incident in self.incidents.values():
            counts[incident["state"]] = counts.get(incident["state"], 0) + 1
        for state, count in counts.items():
            INCIDENTS.labels(state=state).set(count)
        APPROVALS_PENDING.set(sum(1 for record in self.approvals.values() if record["state"] == "pending"))

    # -- incidents ------------------------------------------------------------
    def _open_for(self, fingerprint):
        for incident in self.incidents.values():
            if incident["fingerprint"] == fingerprint and incident["state"] != "closed":
                return incident
        return None

    @staticmethod
    def _note(incident, kind, text):
        incident["events"].append({"at": time.time(), "kind": kind, "text": str(text)[:1000]})
        del incident["events"][:-200]

    def open(self, alert, rule_name):
        """The alert's open incident, created on first sight; a re-fire reopens a resolved one."""
        fingerprint = alert_fingerprint(alert)
        labels = alert.get("labels", {})
        with self._lock:
            incident = self._open_for(fingerprint)
            if incident is None:
                incident = {
                    "id": uuid.uuid4().hex[:10],
                    "fingerprint": fingerprint,
                    "alertname": labels.get("alertname", "?"),
                    "labels": dict(labels),
                    "annotations": dict(alert.get("annotations", {})),
                    "startsAt": alert.get("startsAt", ""),
                    "generatorURL": alert.get("generatorURL", ""),
                    "rules": [rule_name],
                    "state": "open",
                    "opened": time.time(),
                    "alert_resolved": None,
                    "closed": None,
                    "closed_by": "",
                    "close_reason": "",
                    "jira": None,
                    "silences": [],
                    "events": [],
                }
                self.incidents[incident["id"]] = incident
                self._note(incident, "opened", "%s fired, rule %s took it" % (_alert_id(alert), rule_name))
            else:
                if rule_name not in incident["rules"]:
                    incident["rules"].append(rule_name)
                if incident["state"] == "alert_resolved":
                    incident.update(state="open", alert_resolved=None)
                    self._note(incident, "refired", "the alert fired again")
            self._save()
            return incident["id"]

    def get(self, incident_id):
        with self._lock:
            incident = self.incidents.get(incident_id)
            return copy.deepcopy(incident) if incident else None

    def list_incidents(self):
        with self._lock:
            return sorted((copy.deepcopy(incident) for incident in self.incidents.values()),
                          key=lambda incident: incident["opened"], reverse=True)

    def event(self, incident_id, kind, text):
        with self._lock:
            incident = self.incidents.get(incident_id)
            if incident:
                self._note(incident, kind, text)
                self._save()

    def set_jira(self, incident_id, key, url):
        with self._lock:
            incident = self.incidents.get(incident_id)
            if incident and (incident.get("jira") or {}).get("key") != key:
                incident["jira"] = {"key": key, "url": url}
                self._note(incident, "ticket", "ticket %s" % key)
                self._save()

    def add_silence(self, incident_id, record):
        with self._lock:
            incident = self.incidents.get(incident_id)
            if incident:
                incident["silences"].append(dict(record))
                self._save()

    def active_silence(self, incident_id, now=None):
        now = now or time.time()
        with self._lock:
            for silence in (self.incidents.get(incident_id) or {}).get("silences", []):
                if not silence.get("expired") and silence.get("ends_at", 0) > now:
                    return dict(silence)
        return None

    def silence_expired(self, incident_id, silence_id):
        with self._lock:
            incident = self.incidents.get(incident_id)
            for silence in (incident or {}).get("silences", []):
                if silence["id"] == silence_id and not silence.get("expired"):
                    silence["expired"] = time.time()
                    self._note(incident, "silence", "silence %s expired" % silence_id)
                    self._save()

    def alert_resolved(self, fingerprint, how):
        with self._lock:
            incident = self._open_for(fingerprint)
            if incident is None or incident["state"] != "open":
                return None
            incident.update(state="alert_resolved", alert_resolved=time.time())
            self._note(incident, "resolved", how)
            self._save()
            return incident["id"]

    def close(self, incident_id, by, reason, notes=()):
        with self._lock:
            incident = self.incidents.get(incident_id)
            if incident is None or incident["state"] == "closed":
                return
            for note in notes:
                self._note(incident, "closing", note)
            incident.update(state="closed", closed=time.time(), closed_by=by, close_reason=reason)
            self._note(incident, "closed", "closed by %s: %s" % (by, reason))
            self._save()

    def purge(self, retention, now=None):
        """Forget closed incidents and settled approvals older than `retention` seconds."""
        now = now or time.time()
        with self._lock:
            before = len(self.incidents) + len(self.approvals)
            self.incidents = {key: value for key, value in self.incidents.items()
                              if not (value["state"] == "closed" and now - value["closed"] > retention)}
            self.approvals = {key: value for key, value in self.approvals.items()
                              if not (value["state"] != "pending" and now - (value["decided"] or value["created"]) > retention)}
            if len(self.incidents) + len(self.approvals) != before:
                self._save()

    # -- approvals ------------------------------------------------------------
    def add_approval(self, record):
        with self._lock:
            self.approvals[record["id"]] = record
            self._save()

    def get_approval(self, approval_id):
        with self._lock:
            record = self.approvals.get(approval_id)
            return copy.deepcopy(record) if record else None

    def list_approvals(self):
        with self._lock:
            return sorted((copy.deepcopy(record) for record in self.approvals.values()),
                          key=lambda record: record["created"], reverse=True)

    def pending_for(self, fingerprint, rule_name, index):
        with self._lock:
            for record in self.approvals.values():
                if (record["state"] == "pending" and record["fingerprint"] == fingerprint
                        and record["rule"] == rule_name and record["index"] == index):
                    return record["id"]
        return None

    def decide(self, approval_id, state, by, note="", now=None):
        """Settle a pending approval. KeyError: unknown; ValueError: no longer pending."""
        now = now or time.time()
        with self._lock:
            record = self.approvals.get(approval_id)
            if record is None:
                raise KeyError(approval_id)
            if record["state"] == "pending" and now > record["expires"]:
                record.update(state="expired", decided=now, decided_by="alert-handler", note="nobody decided in time")
                self._save()
            if record["state"] != "pending":
                raise ValueError("approval %s is %s, not pending" % (approval_id, record["state"]))
            record.update(state=state, decided=now, decided_by=by, note=note)
            self._save()
            return copy.deepcopy(record)

    def withdraw(self, fingerprint, reason, state="cancelled"):
        """Settle every pending approval of an alert without running it."""
        withdrawn = []
        with self._lock:
            for record in self.approvals.values():
                if record["state"] == "pending" and record["fingerprint"] == fingerprint:
                    record.update(state=state, decided=time.time(), decided_by="alert-handler", note=reason)
                    withdrawn.append(copy.deepcopy(record))
            if withdrawn:
                self._save()
        return withdrawn

    def expire(self, now=None):
        now = now or time.time()
        expired = []
        with self._lock:
            for record in self.approvals.values():
                if record["state"] == "pending" and now > record["expires"]:
                    record.update(state="expired", decided=now, decided_by="alert-handler", note="nobody decided in time")
                    expired.append(copy.deepcopy(record))
            if expired:
                self._save()
        return expired


def _redact_tree(value, redact):
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [_redact_tree(item, redact) for item in value]
    if isinstance(value, dict):
        return {key: _redact_tree(item, redact) for key, item in value.items()}
    return value


def _spec_of(action):
    return {key: value for key, value in action.items() if key not in ("type", "approval")}


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
    "am_silence": action_am_silence,
    "am_expire": action_am_expire,
    "jira_create": action_jira_create,
    "jira_comment": action_jira_comment,
    "jira_transition": action_jira_transition,
}


# --------------------------------------------------------------------------- #
# Dispatcher
# --------------------------------------------------------------------------- #
class Dispatcher:
    def __init__(self, config, store=None):
        self._lock = threading.Lock()
        self._last_run = {}      # (rule name, fingerprint) -> unix time
        self._jira_polled = 0.0
        # The state file is read once, at start: a reload changes rules, not history.
        self.store = store if store is not None else IncidentStore(config.settings.get("state_file") or "")
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

    def link(self, path):
        """An absolute link on settings.public_url, or the bare path without one."""
        return (self.settings.get("public_url") or "").rstrip("/") + path

    def handle_payload(self, payload, pool):
        """Match every alert in the group and queue the actions of each hit."""
        queued = 0
        for alert in payload.get("alerts") or []:
            ALERTS.labels(status=alert.get("status", "unknown")).inc()
            context = alert_context(alert, payload, self.secrets)
            if alert.get("status") == "resolved":
                self.alert_resolved(alert, pool)
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
                    namespace = dict(context)
                    if rule["incident"] and alert.get("status") == "firing":
                        incident_id = self.store.open(alert, rule["name"])
                        namespace["incident"] = {"id": incident_id, "url": self.link("/incidents/" + incident_id)}
                    pool.submit(self.run_rule, rule, namespace, alert)
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

    def run_rule(self, rule, namespace, alert, start=0, approved=None):
        """Run a rule's actions in order, sharing one namespace.

        A failed action stops the rest of the chain: if the diagnostic did not
        run there is nothing to explain, and nothing to announce. An action that
        should not stop it sets `continue_on_error: true`.

        An action with `approval: required` pauses the chain before it runs; the
        rest waits on /approvals until a person approves it (the chain goes on
        from that action, `approved` marking it) or rejects it.
        """
        actx = ActionContext(self.secrets, namespace, store=self.store, alert=alert)
        stopped = False
        for index in range(start, len(rule["actions"])):
            action = rule["actions"][index]
            if stopped:
                ACTIONS.labels(rule=rule["name"], action=action["type"], result="skipped").inc()
                continue
            if _gated(action) and index != approved:
                self.pause(rule, index, namespace, alert)
                return
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
        spec = render(_spec_of(action), actx.namespace)
        spec["_rule"] = rule["name"]

        settings = self.settings
        if settings["dry_run"]:
            ACTIONS.labels(rule=rule["name"], action=kind, result="dry_run").inc()
            log.info("[dry-run] rule %s would run %s: %s", rule["name"], kind, self.redact(_summarise(spec)))
            self._record(actx, "%s (dry run): %s" % (kind, self.redact(_summarise(spec))), True)
            return True

        INFLIGHT.inc()
        started = time.time()
        try:
            if kind in ("exec", "runbook"):
                self.prepare_command_env(spec, actx.namespace)
            outcome = ACTION_TYPES[kind](spec, settings, actx)
            ACTIONS.labels(rule=rule["name"], action=kind, result="success").inc()
            log.info("rule %s ran %s for %s: %s", rule["name"], kind, _alert_id(alert), self.redact(outcome))
            self._record(actx, "%s: %s" % (kind, self.redact(outcome)), True)
            return True
        except Exception as error:  # noqa: BLE001 - an action must never kill the worker
            ACTIONS.labels(rule=rule["name"], action=kind, result="failure").inc()
            log.error("rule %s failed %s for %s: %s", rule["name"], kind, _alert_id(alert), self.redact(error))
            self._record(actx, "%s failed: %s" % (kind, self.redact(error)), False)
            return False
        finally:
            ACTION_SECONDS.labels(rule=rule["name"], action=kind).observe(time.time() - started)
            INFLIGHT.dec()

    def _record(self, actx, line, ok):
        """Keep what an action did: {{ steps }} for later actions, and the incident's timeline."""
        steps = actx.namespace.get("steps", "")
        actx.namespace["steps"] = (steps + "\n" if steps else "") + "- " + line[:500]
        if actx.incident_id:
            self.store.event(actx.incident_id, "action" if ok else "failure", line)

    # -- approvals ------------------------------------------------------------
    def pause(self, rule, index, namespace, alert):
        """Hold the rest of a chain for a person; returns the approval id."""
        absolute = rule.get("offset", 0) + index
        fingerprint = alert_fingerprint(alert)
        action = rule["actions"][index]
        existing = self.store.pending_for(fingerprint, rule["name"], absolute)
        if existing:
            log.info("rule %s: %s for %s already waits for approval %s",
                     rule["name"], action["type"], _alert_id(alert), existing)
            return existing

        summary = "%s %s" % (action["type"], self.redact(_summarise(render(_spec_of(action), namespace, preview=True))))
        now = time.time()
        approval_id = uuid.uuid4().hex[:10]
        incident = namespace.get("incident") if isinstance(namespace.get("incident"), dict) else {}
        record = {
            "id": approval_id,
            "state": "pending",
            "rule": rule["name"],
            "index": absolute,
            "action": action["type"],
            "summary": summary,
            # Exactly what the person approves, even if the config changes meanwhile.
            "actions": copy.deepcopy(rule["actions"][index:]),
            "namespace": _redact_tree({key: value for key, value in namespace.items() if key != "secrets"}, self.redact),
            "alert": {key: alert.get(key) for key in
                      ("status", "labels", "annotations", "fingerprint", "startsAt", "endsAt", "generatorURL")},
            "fingerprint": fingerprint,
            "incident": incident.get("id", ""),
            "created": now,
            "expires": now + parse_duration(self.settings["approvals"]["ttl"]),
            "decided": None,
            "decided_by": "",
            "note": "",
            "url": self.link("/approvals/" + approval_id),
        }
        self.store.add_approval(record)
        ACTIONS.labels(rule=rule["name"], action=action["type"], result="awaiting_approval").inc()
        log.info("rule %s paused before %s for %s: approval %s", rule["name"], action["type"], _alert_id(alert), approval_id)
        if record["incident"]:
            self.store.event(record["incident"], "approval", "waiting for approval %s: %s" % (approval_id, summary))
        self.notify_approval(record)
        return approval_id

    def notify_approval(self, record):
        """Run settings.approvals.notify with {{ approval.* }}, so somebody hears about it."""
        spec = self.settings["approvals"].get("notify")
        if not spec:
            return
        namespace = dict(record["namespace"], secrets=self.secrets)
        namespace["approval"] = {
            "id": record["id"], "url": record["url"], "summary": record["summary"],
            "rule": record["rule"], "action": record["action"], "expires": _iso(record["expires"]),
        }
        actx = ActionContext(self.secrets, namespace, store=self.store, alert=record["alert"])
        self.run_action({"name": record["rule"]}, spec, actx, record["alert"])

    def decide(self, approval_id, approve, by, pool=None, note=""):
        """A person approves (the chain goes on) or rejects (it ends here)."""
        state = "approved" if approve else "rejected"
        record = self.store.decide(approval_id, state, by, note)
        APPROVAL_DECISIONS.labels(decision=state).inc()
        log.info("approval %s %s by %s: %s", approval_id, state, by, record["summary"])
        if record["incident"]:
            self.store.event(record["incident"], "approval", "%s %s %s" % (by, state, record["summary"]))
        if approve:
            namespace = dict(record["namespace"], secrets=self.secrets)
            namespace["approval"] = {"id": record["id"], "by": by, "at": _iso(record["decided"]), "url": record["url"]}
            rule = {"name": record["rule"], "actions": record["actions"], "offset": record["index"]}
            task = functools.partial(self.run_rule, rule, namespace, record["alert"], 0, 0)
            if pool is not None:
                pool.submit(task)
            else:
                task()
        return record

    # -- the incident lifecycle ------------------------------------------------
    def alert_resolved(self, alert, pool=None, how="Alertmanager reported it resolved"):
        """The alert is gone: withdraw what waits on people, tell the ticket, keep it open."""
        fingerprint = alert_fingerprint(alert)
        if self.settings["approvals"]["cancel_on_resolve"]:
            for record in self.store.withdraw(fingerprint, "the alert resolved before anyone decided"):
                APPROVAL_DECISIONS.labels(decision="cancelled").inc()
                if record["incident"]:
                    self.store.event(record["incident"], "approval", "withdrew approval %s: the alert resolved" % record["id"])
        incident_id = self.store.alert_resolved(fingerprint, how)
        if not incident_id:
            return None
        incident = self.store.get(incident_id)
        if incident.get("jira") and self.settings["incidents"]["comment_on_resolve"]:
            text = ("The alert resolved at %s (%s). This ticket stays open until a person closes it; "
                    "alert-handler then lifts the silences it set." % (_iso(), how))
            task = functools.partial(self.jira_note, incident_id, text)
            if pool is not None:
                pool.submit(task)
            else:
                task()
        return incident_id

    def jira_note(self, incident_id, text):
        incident = self.store.get(incident_id)
        if not incident or not incident.get("jira"):
            return
        key = incident["jira"]["key"]
        try:
            jira_add_comment(self.settings, self.secrets, key, text)
            self.store.event(incident_id, "ticket", "commented on %s" % key)
        except Exception as error:  # noqa: BLE001 - a comment must not break the lifecycle
            log.error("cannot comment on %s: %s", key, self.redact(error))
            self.store.event(incident_id, "failure", "comment on %s failed: %s" % (key, self.redact(error)))

    def close_incident(self, incident_id, by, reason, source="handler"):
        """A person closed it: lift its silences, withdraw its approvals, tell the ticket.

        `source` is where the person closed it: "handler" (the /incidents page,
        which also runs incidents.resolve_transition on the ticket) or "jira".
        """
        incident = self.store.get(incident_id)
        if incident is None:
            raise KeyError(incident_id)
        if incident["state"] == "closed":
            return incident
        notes = []
        for silence in incident["silences"]:
            if silence.get("expired"):
                continue
            try:
                am_expire_silence(self.settings, self.secrets, silence)
                self.store.silence_expired(incident_id, silence["id"])
                notes.append("lifted silence %s" % silence["id"])
            except Exception as error:  # noqa: BLE001
                notes.append("could not lift silence %s: %s" % (silence["id"], self.redact(error)))
        for record in self.store.withdraw(incident["fingerprint"], "the incident was closed"):
            APPROVAL_DECISIONS.labels(decision="cancelled").inc()
            notes.append("withdrew approval %s" % record["id"])
        if incident.get("jira") and jira_configured(self.settings):
            key = incident["jira"]["key"]
            try:
                jira_add_comment(self.settings, self.secrets, key, "Closed by %s: %s. %s" % (
                    by, reason, "; ".join(notes) or "Nothing to undo."))
                transition = self.settings["incidents"]["resolve_transition"]
                if source == "handler" and transition:
                    notes.append("moved %s through %s" % (key, jira_transition_issue(self.settings, self.secrets, key, transition)))
            except Exception as error:  # noqa: BLE001
                notes.append("jira %s: %s" % (key, self.redact(error)))
        self.store.close(incident_id, by, reason, notes)
        log.info("incident %s (%s) closed by %s: %s", incident_id, incident["alertname"], by, reason)
        return self.store.get(incident_id)

    def housekeeping(self, now=None):
        """Periodic: expire approvals, forget old history, watch silenced alerts and tickets."""
        now = now or time.time()
        for record in self.store.expire(now):
            APPROVAL_DECISIONS.labels(decision="expired").inc()
            if record["incident"]:
                self.store.event(record["incident"], "approval", "approval %s expired: nobody decided" % record["id"])
        self.store.purge(parse_duration(self.settings["incidents"]["retention"]), now)
        self.check_silenced(now)
        interval = parse_duration(self.settings["jira"]["poll_interval"])
        if jira_configured(self.settings) and interval > 0 and now - self._jira_polled >= interval:
            self._jira_polled = now
            self.poll_jira()

    def check_silenced(self, now=None):
        """A silenced alert's resolution never reaches the webhook: ask its Alertmanager."""
        now = now or time.time()
        for incident in self.store.list_incidents():
            if incident["state"] != "open":
                continue
            silence = next((item for item in incident["silences"]
                            if not item.get("expired") and item.get("ends_at", 0) > now), None)
            if not silence:
                continue
            try:
                active = am_alert_active(self.settings, self.secrets, silence, incident)
            except Exception as error:  # noqa: BLE001
                log.warning("cannot ask %s about %s: %s", silence["url"], incident["alertname"], self.redact(error))
                continue
            if not active:
                self.alert_resolved({"fingerprint": incident["fingerprint"], "labels": incident["labels"]},
                                    how="gone from Alertmanager while silenced")

    def poll_jira(self):
        """A ticket a person moved to done closes its incident."""
        for incident in self.store.list_incidents():
            if incident["state"] == "closed" or not incident.get("jira"):
                continue
            key = incident["jira"]["key"]
            try:
                fields = jira_get_issue(self.settings, self.secrets, key).get("fields") or {}
            except Exception as error:  # noqa: BLE001
                log.warning("cannot read %s: %s", key, self.redact(error))
                continue
            status = fields.get("status") or {}
            if (status.get("statusCategory") or {}).get("key") == "done":
                who = (fields.get("assignee") or {}).get("displayName") or "a person in Jira"
                self.close_incident(incident["id"], who, "%s moved to %s" % (key, status.get("name", "done")), source="jira")


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
# Pages for people: /approvals and /incidents
#
# Plain server-rendered HTML with two forms, no scripts. Every value is
# escaped; nothing on these pages carries a credential (paused chains are
# stored redacted).
# --------------------------------------------------------------------------- #
_STYLE = """
body{font:14px/1.45 system-ui,-apple-system,sans-serif;margin:0 auto;max-width:1120px;padding:16px;color:#1d2330;background:#fafbfc}
nav{margin-bottom:8px} nav a{margin-right:16px} h1{font-size:20px;margin:12px 0} h2{font-size:15px;margin:22px 0 8px}
table{border-collapse:collapse;width:100%;background:#fff} td,th{border-bottom:1px solid #e3e6ea;padding:6px 8px;text-align:left;vertical-align:top}
th{font-weight:600;background:#f1f3f5} code,pre{font:12px ui-monospace,SFMono-Regular,monospace}
pre{white-space:pre-wrap;background:#fff;border:1px solid #e3e6ea;padding:8px;margin:0}
.state{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;background:#e9ecef}
.pending,.open{background:#fff3cd}.approved,.closed{background:#d1e7dd}.rejected,.expired,.cancelled{background:#f8d7da}.alert_resolved{background:#cfe2ff}
form{display:inline} button{padding:3px 12px;margin:2px 6px 2px 0;cursor:pointer} input{padding:3px 6px}
.muted{color:#6c757d}
"""


def _e(value):
    return html.escape(str(value if value is not None else ""), quote=True)


def _when(timestamp):
    return _iso(timestamp).replace("T", " ").replace("Z", " UTC") if timestamp else ""


def _state(state):
    return '<span class="state %s">%s</span>' % (_e(state), _e(state.replace("_", " ")))


def _page(title, body):
    return ("<!doctype html><html><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<title>%s - alert-handler</title><style>%s</style></head><body>"
            "<nav><a href=\"/incidents\">Incidents</a><a href=\"/approvals\">Approvals</a>"
            "<a href=\"/rules\">Rules</a><a href=\"/metrics\">Metrics</a></nav>"
            "<h1>%s</h1>%s</body></html>" % (_e(title), _STYLE, _e(title), body)).encode("utf-8")


def _labels_table(labels):
    return "<table>%s</table>" % "".join(
        "<tr><th>%s</th><td><code>%s</code></td></tr>" % (_e(key), _e(labels[key])) for key in sorted(labels or {}))


def _decision_forms(record, token_field):
    if record["state"] != "pending":
        return ""
    return ("<form method=\"post\" action=\"/approvals/%(id)s/approve\">%(token)s<button>Approve</button></form>"
            "<form method=\"post\" action=\"/approvals/%(id)s/reject\">%(token)s<button>Reject</button></form>"
            % {"id": _e(record["id"]), "token": token_field})


def page_approvals(records, token_field):
    pending = [record for record in records if record["state"] == "pending"]
    settled = [record for record in records if record["state"] != "pending"][:50]
    rows = "".join(
        "<tr><td><a href=\"/approvals/%s\">%s</a><br><span class=\"muted\">%s</span></td><td>%s</td>"
        "<td><code>%s</code></td><td>%s</td><td>%s</td></tr>" % (
            _e(r["id"]), _e(_alert_id(r["alert"])), _when(r["created"]), _e(r["rule"]),
            _e(r["summary"]), _when(r["expires"]), _decision_forms(r, token_field))
        for r in pending) or "<tr><td colspan=\"5\" class=\"muted\">Nothing waits for a decision.</td></tr>"
    done = "".join(
        "<tr><td><a href=\"/approvals/%s\">%s</a></td><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s %s</td></tr>" % (
            _e(r["id"]), _e(_alert_id(r["alert"])), _state(r["state"]), _e(r["summary"]),
            _when(r["decided"]), _e(r["decided_by"]), ("- " + _e(r["note"])) if r.get("note") else "")
        for r in settled) or "<tr><td colspan=\"5\" class=\"muted\">None yet.</td></tr>"
    body = ("<h2>Waiting</h2><table><tr><th>Alert</th><th>Rule</th><th>Would run</th><th>Expires</th><th></th></tr>%s</table>"
            "<h2>Decided</h2><table><tr><th>Alert</th><th>State</th><th>Action</th><th>When</th><th>By</th></tr>%s</table>"
            % (rows, done))
    return _page("Approvals", body)


def page_approval(record, token_field):
    remaining = record["actions"][1:]
    body = ("<p>%s rule <b>%s</b> paused before <code>%s</code>. %s</p>"
            "<p>%s</p><h2>Would run</h2><pre>%s</pre>"
            "<h2>Then</h2><pre>%s</pre><h2>Alert</h2>%s<h2>So far</h2><pre>%s</pre>" % (
                _state(record["state"]), _e(record["rule"]), _e(record["action"]),
                ("Waiting until %s." % _when(record["expires"])) if record["state"] == "pending" else
                ("%s by %s at %s %s" % (_e(record["state"]), _e(record["decided_by"]), _when(record["decided"]),
                                         _e(record.get("note", "")))),
                _decision_forms(record, token_field) + ((" <a href=\"/incidents/%s\">incident</a>" % _e(record["incident"]))
                                                        if record["incident"] else ""),
                _e(record["summary"]),
                _e("\n".join("%s %s" % (a["type"], "(approval required)" if _gated(a) else "") for a in remaining) or "nothing"),
                _labels_table(record["alert"].get("labels")),
                _e(record["namespace"].get("steps") or "nothing yet")))
    return _page("Approval %s" % record["id"], body)


def page_incidents(incidents):
    rows = "".join(
        "<tr><td><a href=\"/incidents/%s\">%s</a></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            _e(i["id"]), _e(_alert_id(i)), _state(i["state"]), _when(i["opened"]),
            ("<a href=\"%s\">%s</a>" % (_e(i["jira"]["url"]), _e(i["jira"]["key"]))) if i.get("jira") else "",
            _e(", ".join(s["id"] for s in i["silences"] if not s.get("expired")) or ""),
            _e(i["events"][-1]["text"]) if i["events"] else "")
        for i in incidents) or "<tr><td colspan=\"6\" class=\"muted\">No incidents.</td></tr>"
    return _page("Incidents", "<table><tr><th>Alert</th><th>State</th><th>Opened</th><th>Ticket</th>"
                              "<th>Live silences</th><th>Last</th></tr>%s</table>" % rows)


def page_incident(incident, approvals, token_field):
    silences = "".join(
        "<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            _e(s["id"]), _e(s["url"] + ((" (tenant %s)" % s["tenant"]) if s.get("tenant") else "")),
            _when(s.get("ends_at")), ("lifted " + _when(s["expired"])) if s.get("expired") else "live")
        for s in incident["silences"]) or "<tr><td colspan=\"4\" class=\"muted\">None.</td></tr>"
    waiting = "".join("<tr><td><a href=\"/approvals/%s\">%s</a></td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>" % (
        _e(r["id"]), _e(r["id"]), _state(r["state"]), _e(r["summary"]), _decision_forms(r, token_field))
        for r in approvals) or "<tr><td colspan=\"4\" class=\"muted\">None.</td></tr>"
    timeline = "".join("<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (_when(e["at"]), _e(e["kind"]), _e(e["text"]))
                       for e in incident["events"])
    resolve = "" if incident["state"] == "closed" else (
        "<h2>Resolve</h2><form method=\"post\" action=\"/incidents/%s/resolve\">%s"
        "<input name=\"reason\" size=\"50\" placeholder=\"what fixed it\"> <button>Resolve</button></form>"
        "<p class=\"muted\">Lifts the silences the handler set, withdraws what still waits for approval and "
        "notes it on the ticket. If the alert still fires, it pages again.</p>" % (_e(incident["id"]), token_field))
    ticket = ("<a href=\"%s\">%s</a>" % (_e(incident["jira"]["url"]), _e(incident["jira"]["key"]))) if incident.get("jira") else "none"
    closed = (" Closed %s by %s: %s." % (_when(incident["closed"]), _e(incident["closed_by"]), _e(incident["close_reason"]))
              if incident["state"] == "closed" else "")
    body = ("<p>%s opened %s, rules %s. Ticket: %s.%s</p>%s<h2>Alert</h2>%s<h2>Silences</h2>"
            "<table><tr><th>Id</th><th>Alertmanager</th><th>Until</th><th></th></tr>%s</table>"
            "<h2>Approvals</h2><table><tr><th>Id</th><th>State</th><th>Action</th><th></th></tr>%s</table>"
            "<h2>Timeline</h2><table>%s</table>" % (
                _state(incident["state"]), _when(incident["opened"]), _e(", ".join(incident["rules"])), ticket, closed,
                resolve, _labels_table(incident["labels"]), silences, waiting, timeline))
    return _page("%s - incident %s" % (incident["alertname"], incident["id"]), body)


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

    def _wants_json(self):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        if query.get("format", [""])[0] == "json":
            return True
        accept = self.headers.get("Accept", "")
        return "application/json" in accept and "text/html" not in accept

    def _json(self, status, value):
        self._respond(status, json.dumps(value, indent=2, sort_keys=True, default=str).encode(), "application/json")

    def _html(self, body):
        self._respond(200, body, "text/html; charset=utf-8")

    def _token_field(self):
        """Extra form fields: the webhook token when one is set (a browser sends no
        bearer), and a name when nothing in front of the handler says who this is."""
        fields = ""
        if self._actor({}) == "anonymous":
            fields += "<input name=\"by\" placeholder=\"your name\" size=\"12\"> "
        if self.dispatcher.auth_token:
            fields += "<input type=\"password\" name=\"token\" placeholder=\"token\" size=\"10\"> "
        return fields

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        path = self.path.split("?", 1)[0]
        parts = [part for part in path.split("/") if part]
        if parts[:1] in (["incidents"], ["approvals"]) and len(parts) <= 2:
            self._people_page(parts)
        elif path == "/metrics":
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
                    "incident": rule["incident"],
                    "actions": [action["type"] for action in rule["actions"]],
                    "gated": [action["type"] for action in rule["actions"] if _gated(action)],
                }
                for rule in self.dispatcher.config.rules
            ]
            self._respond(200, json.dumps(rules, indent=2).encode(), "application/json")
        elif path == "/runbooks":
            # Names only: a runbook may well contain a hostname you would rather
            # not hand out, and the contents are in the ConfigMap anyway.
            self._respond(200, json.dumps(list_runbooks(), indent=2).encode(), "application/json")
        elif path == "/":
            self._respond(200, b"alert-handler: POST Alertmanager webhooks to /alert\n"
                               b"people: /incidents, /approvals\n")
        else:
            self._respond(404, b"not found\n")

    def _people_page(self, parts):
        store, token = self.dispatcher.store, self._token_field()
        if parts[0] == "approvals":
            if len(parts) == 1:
                records = store.list_approvals()
                return self._json(200, records) if self._wants_json() else self._html(page_approvals(records, token))
            record = store.get_approval(parts[1])
            if record is None:
                return self._respond(404, b"no such approval\n")
            return self._json(200, record) if self._wants_json() else self._html(page_approval(record, token))
        if len(parts) == 1:
            incidents = store.list_incidents()
            return self._json(200, incidents) if self._wants_json() else self._html(page_incidents(incidents))
        incident = store.get(parts[1])
        if incident is None:
            return self._respond(404, b"no such incident\n")
        if self._wants_json():
            return self._json(200, incident)
        approvals = [r for r in store.list_approvals() if r["incident"] == incident["id"]]
        return self._html(page_incident(incident, approvals, token))

    def _read_form(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if "json" in self.headers.get("Content-Type", ""):
            try:
                data = json.loads(raw or b"{}")
            except ValueError:
                return None
            return {key: str(value) for key, value in data.items()} if isinstance(data, dict) else None
        return {key: values[0] for key, values in urllib.parse.parse_qs(raw.decode("utf-8", "replace")).items()}

    def _same_origin(self):
        """Refuse a browser POST that another site's page made (the login would ride along)."""
        origin = self.headers.get("Origin") or self.headers.get("Referer") or ""
        if not origin or origin == "null":
            return not origin
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or ""
        return urllib.parse.urlsplit(origin).netloc == host

    def _actor(self, form):
        """Who decided: the login in front of the handler, else a `by` field."""
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Basic "):
            try:
                user = base64.b64decode(auth[6:]).decode("utf-8", "replace").split(":", 1)[0]
            except (ValueError, binascii.Error):
                user = ""
            if user:
                return user
        for header in ("X-Forwarded-User", "X-Auth-Request-User", "X-Remote-User", "X-Forwarded-Email"):
            if self.headers.get(header):
                return self.headers[header][:80]
        return (form.get("by") or "").strip()[:80] or "anonymous"

    def _person_allowed(self, form):
        token = self.dispatcher.auth_token
        if not token:
            return True
        return self.headers.get("Authorization", "") == "Bearer %s" % token or form.get("token") == token

    def _person_post(self, act, back):
        form = self._read_form()
        if form is None:
            return self._respond(400, b"bad request body\n")
        if not self._same_origin():
            return self._respond(403, b"refused: the request came from another site\n")
        if not self._person_allowed(form):
            return self._respond(401, b"unauthorised\n")
        try:
            result = act(form, self._actor(form))
        except KeyError:
            return self._respond(404, b"not found\n")
        except ValueError as error:
            return self._respond(409, ("%s\n" % error).encode())
        if self._wants_json() or "json" in self.headers.get("Content-Type", ""):
            return self._json(200, result)
        self.send_response(303)
        self.send_header("Location", back)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
        path = self.path.split("?", 1)[0]
        parts = [part for part in path.split("/") if part]
        if len(parts) == 3 and parts[0] == "approvals" and parts[2] in ("approve", "reject"):
            return self._person_post(
                lambda form, by: self.dispatcher.decide(parts[1], parts[2] == "approve", by, self.pool, form.get("note", "")),
                "/approvals/" + parts[1])
        if len(parts) == 3 and parts[0] == "incidents" and parts[2] == "resolve":
            return self._person_post(
                lambda form, by: self.dispatcher.close_incident(parts[1], by, form.get("reason") or "resolved by a person"),
                "/incidents/" + parts[1])
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

    def housekeeping():
        """Approval expiry, retention, silenced alerts, tickets - on its own thread."""
        while True:
            time.sleep(max(5, parse_duration(dispatcher.settings["incidents"]["check_interval"], 60)))
            try:
                dispatcher.housekeeping()
            except Exception as error:  # noqa: BLE001 - keep the loop alive
                log.exception("housekeeping failed: %s", error)

    threading.Thread(target=housekeeping, name="housekeeping", daemon=True).start()

    Handler.dispatcher = dispatcher
    Handler.pool = pool
    server = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Handler)
    log.info(
        "listening on :%d with %d rules, dry_run=%s, kubernetes=%s, salt=%s, llm=%s, alertmanager=%s, jira=%s, "
        "state=%s, runbooks=%d, credentials=%d",
        HTTP_PORT,
        len(config.rules),
        config.settings["dry_run"],
        "in-cluster" if KUBE.available else "unavailable",
        config.settings["salt"]["url"] or "unconfigured",
        config.settings["llm"]["url"] or "unconfigured",
        config.settings["alertmanager"]["url"] or "unconfigured",
        config.settings["jira"]["url"] or "unconfigured",
        config.settings["state_file"] or "memory",
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
