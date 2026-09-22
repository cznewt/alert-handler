"""Test fixtures: the module under test, throwaway runbook/secret directories,
and a recording HTTP server that stands in for Alertmanager's neighbours -
a chat webhook, an OpenAI-compatible endpoint, salt-api, the Kubernetes API."""
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker"))

import alert_handler as ah  # noqa: E402


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    """Runbook and secret directories the module reads, under tmp."""
    runbooks = tmp_path / "runbooks"
    secrets = tmp_path / "secrets"
    runbooks.mkdir()
    secrets.mkdir()
    monkeypatch.setattr(ah, "RUNBOOK_DIR", str(runbooks))
    monkeypatch.setattr(ah, "SECRETS_DIR", str(secrets))
    return tmp_path


def write_config(path, settings=None, rules=None):
    import yaml

    doc = {}
    if settings is not None:
        doc["settings"] = settings
    if rules is not None:
        doc["rules"] = rules
    path.write_text(yaml.safe_dump(doc))
    return str(path)


@pytest.fixture
def config_file(workdir):
    """A config writer bound to the tmp dir: config_file(settings=..., rules=...) -> path."""

    def _write(settings=None, rules=None, name="config.yaml"):
        return write_config(workdir / name, settings, rules)

    return _write


class SyncPool:
    """A thread pool that runs the task inline, so tests see the outcome at once."""

    def __init__(self):
        self.submitted = 0

    def submit(self, fn, *args, **kwargs):
        self.submitted += 1
        fn(*args, **kwargs)


@pytest.fixture
def pool():
    return SyncPool()


class Recorder(BaseHTTPRequestHandler):
    """Records every request; answers from `responses` (path -> (status, json))."""

    calls = []
    responses = {}

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        path = self.path.split("?", 1)[0]
        try:
            parsed = json.loads(body) if body else None
        except ValueError:
            parsed = None  # a plain-text body, kept in "body"
        self.calls.append({
            "method": self.command, "path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
            "body": body.decode("utf-8"), "json": parsed,
        })
        status, payload = self.responses.get(path, (200, {"ok": True}))
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PATCH = do_DELETE = do_PUT = _handle

    def log_message(self, *args):  # noqa: A002
        pass


class FakeServer:
    def __init__(self, server, handler):
        self.server = server
        self.handler = handler
        self.url = "http://127.0.0.1:%d" % server.server_address[1]

    @property
    def calls(self):
        return self.handler.calls

    @property
    def responses(self):
        return self.handler.responses


@pytest.fixture
def fake_server():
    """A live HTTP server on a random port; fake_server.responses['/path'] = (status, json)."""

    class Handler(Recorder):
        calls = []
        responses = {}

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield FakeServer(server, Handler)
    finally:
        server.shutdown()
        server.server_close()


def metric(name, **labels):
    """Current value of a counter/gauge sample, 0 when it has never been touched."""
    from prometheus_client import REGISTRY

    value = REGISTRY.get_sample_value(name, labels or None)
    return value or 0.0


def alert(**labels):
    """A firing alert with an annotation, as Alertmanager would send it."""
    labels.setdefault("alertname", "TestAlert")
    labels.setdefault("severity", "warning")
    return {
        "status": "firing",
        "labels": labels,
        "annotations": {"summary": "something is up"},
        "fingerprint": "f" + "".join(sorted(labels.values()))[:12],
        "startsAt": "2026-09-14T00:00:00Z",
        "endsAt": "0001-01-01T00:00:00Z",
        "generatorURL": "http://prometheus/graph",
    }


def payload(*alerts):
    return {
        "receiver": "alert-handler",
        "status": "firing",
        "alerts": list(alerts),
        "groupKey": '{}:{alertname="TestAlert"}',
        "externalURL": "http://alertmanager:9093",
    }


@pytest.fixture
def serve(config_file):
    """Start the real HTTP server for a config; serve(settings=..., rules=...) -> base url."""
    started = []

    def _start(settings=None, rules=None):
        dispatcher = ah.Dispatcher(ah.load_config(config_file(settings=settings, rules=rules)))
        pool = ThreadPoolExecutor(max_workers=2)
        ah.Handler.dispatcher = dispatcher
        ah.Handler.pool = pool
        server = ThreadingHTTPServer(("127.0.0.1", 0), ah.Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        started.append((server, pool))
        return "http://127.0.0.1:%d" % server.server_address[1]

    yield _start
    for server, pool in started:
        server.shutdown()
        server.server_close()
        pool.shutdown(wait=True)


def call(url, method="GET", body=None, headers=None):
    data = json.dumps(body).encode() if isinstance(body, dict) else body
    request = urllib.request.Request(url, data=data, method=method)
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read().decode(), response.headers.get("Content-Type", "")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode(), error.headers.get("Content-Type", "")
