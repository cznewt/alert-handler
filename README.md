# alert-handler

An Alertmanager webhook receiver that **does something** about an alert. Rules
match on alert labels, and each matching rule runs its actions: an outbound HTTP
call, a command, a runbook script, a log line, a write against the Kubernetes
API - restart a rollout, scale a deployment, delete a pod, cordon a node,
annotate an object - a Salt call for the half of an estate that is not in
Kubernetes, or a question to an LLM whose answer the next action can use.

It is the small end of the remediation spectrum: the things that do not deserve
their own operator, but that somebody currently does by hand at 3am.

Documentation: [Install](docs/install.md) · [Run](docs/run.md) ·
[Configuration](docs/configuration.md) · [Usage](docs/usage.md) ·
[Reference](docs/reference.md) - published at
<https://cznewt.github.io/alert-handler/>.

## How it works

```
Prometheus / Mimir ruler --> Alertmanager --webhook--> alert-handler --> actions
        ^                                                   |    . log line
        |                                                   |    . runbook script (a mounted ConfigMap)
        +------------------ scrapes /metrics ---------------+    . HTTP call
                                                                 . k8s: rollout restart, scale, delete pod, cordon, annotate
                                                                 . salt: state.apply, cmd, runner
                                                                 . llm: ask, keep {{ llm.answer }} for the next action
```

1. Alertmanager `POST`s a group of alerts to `/alert`; the handler answers `202`
   at once and does the work on a thread pool.
2. Each alert is matched against the rules in order: `match` (label equality),
   `match_re` (regex over labels) and `status` all have to hold.
3. A matching rule that is not in **cooldown** runs its actions in order. They
   share a namespace, so a later action can use `{{ last.stdout }}` from a
   runbook or `{{ llm.answer }}` from the model; a failure stops the chain
   unless the action says `continue_on_error: true`.
4. Every outcome is a sample of `alert_handler_actions_total{rule,action,result}`,
   so the handler is monitored by the same Prometheus it serves.

Guard rails: ships in `dry_run`; per-rule cooldown keyed on the alert
fingerprint; `allowed_namespaces` in front of every cluster write and
`allowed_targets` globs in front of every Salt call; credentials are files in a
mounted directory, reach actions only by name, and are redacted from the logs;
an optional bearer token on the webhook.

## Quickstart

```bash
just build && just run           # the image, with docker/config.yaml mounted, on :8080
just fire RedisMemoryHigh        # POST a firing alert and watch the log
curl -s localhost:8080/rules     # what is loaded; /runbooks, /metrics, /healthz, /-/ready
```

The full loop - Prometheus fires `DemoWorkloadUnhealthy`, Alertmanager posts it,
the handler runs a runbook and an HTTP call - is one command:

```bash
just demo                        # demo/docker-compose.yml, ctrl-c to stop
just demo-logs                   # what the handler did with each alert
just demo-clean
```

## Tests

```bash
just venv                        # .venv with the runtime deps and pytest
just test                        # the suite: templating, config, every action type, chaining, the HTTP server
just test-all                    # the suite, then a build of the image
```

The suite runs against a recording HTTP server that stands in for a chat
webhook, an OpenAI-compatible endpoint, salt-api and the Kubernetes API, so no
cluster, model or Salt master is needed. `make test` and `make test-all` are
aliases for the machines without `just`.

## Deploy

| Path | What |
| :--- | :--- |
| `docker/` | The service: stdlib HTTP server, `prometheus-client`, PyYAML. No Kubernetes SDK - the `k8s_*` actions use the pod's ServiceAccount token over plain HTTP. |
| `operations/alert-handler-kapitan/` | Kapitan component and class: Deployment, Service, config and runbook ConfigMaps, ServiceAccount, and (unless `rbac: false`) a ClusterRole and binding. |
| `operations/alert-handler-helm-chart/` | The same, for Helm consumers (`just chart-lint`, `just chart-template`). |
| `demo/` | The three-container demo stack (Prometheus, Alertmanager, the handler with a runbook and a credential). |

Wiring Alertmanager:

```yaml
receivers:
  - name: alert-handler
    webhook_configs:
      - url: http://alert-handler-server.monitoring.svc:8080/alert
        send_resolved: true
```

Route only what you mean to act on, and keep `continue: true` on that route so
people still get paged. Start in `dry_run`, read the log, then turn it off with
an `allowed_namespaces` list - see [Usage](docs/usage.md).

## Release

`VERSION` is the image tag. `just publish` builds and pushes
`ghcr.io/cznewt/alert-handler:<VERSION>` and `:latest`; a push to `main` that
touches `docker/` or `VERSION` does the same through GitHub Actions.
