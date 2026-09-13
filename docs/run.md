# Run

## Environment

Everything structural is in the config file; the environment only says where
things are.

| Variable | Default | Meaning |
| :--- | :--- | :--- |
| `CONFIG_FILE` | `/etc/alert-handler/config.yaml` | Settings and rules. |
| `RUNBOOK_DIR` | `/etc/alert-handler/runbooks` | Scripts a `runbook` action may run. Missing directory = no runbooks. |
| `SECRETS_DIR` | `/etc/alert-handler/secrets` | One file per credential. Missing directory = no credentials. |
| `WEBHOOK_TOKEN` | _(unset)_ | Bearer token required on `/alert`; overrides `settings.auth_token`. |
| `HTTP_PORT` | `8080` | Listen port. |
| `LOG_LEVEL` | `INFO` | Python log level. |

The startup line says what actually got wired up, which is the quickest sanity
check after a deploy:

```
listening on :8080 with 3 rules, dry_run=False, kubernetes=in-cluster, runbooks=2, credentials=3
```

`kubernetes=unavailable` means no ServiceAccount token was found — fine unless
you use the `k8s_*` actions, which will then fail with that message.

## The dry-run loop

The handler ships with `dry_run: true` and it is worth leaving there until the
matchers are proven. In dry-run every action is logged instead of run:

```
[dry-run] rule recycle would run runbook: {"args": ["prod", "api"], "name": "recycle-deployment.sh"}
```

The loop is: post a payload, read `/rules` and the log, adjust, reload.

```bash
curl -s localhost:8080/rules                      # the rules as parsed
curl -s localhost:8080/runbooks                   # scripts the handler can see
curl -sX POST -H 'Content-Type: application/json' \
  -d '{"alerts":[{"status":"firing","fingerprint":"t1",
       "labels":{"alertname":"KubePodCrashLooping","namespace":"prod","deployment":"api"},
       "annotations":{"summary":"test"}}]}' \
  localhost:8080/alert
```

A real Alertmanager payload has more in it, but matching only ever looks at
`labels` and `status`, so a hand-written one is a fair test.

## Reloading

`SIGHUP` re-reads the config file, the runbook directory and the credentials
directory, without dropping the listener:

```bash
kubectl -n monitor exec deploy/alert-handler-server -- kill -HUP 1
docker compose kill -s HUP alert-handler
```

A config that does not parse is **refused** — the running rules stay in effect
and `alert_handler_config_valid` drops to 0. Alert on that, because the pod
looks healthy while running yesterday's rules.

Rotated a credential? A reload picks it up; so does a pod restart. The
Kubernetes Secret volume updates on its own, the handler just needs to re-read
it.

## What to watch

| Signal | Meaning |
| :--- | :--- |
| `alert_handler_actions_total{result="failure"}` | An action is failing: bad URL, script exit, RBAC refusal, missing credential. |
| `alert_handler_actions_total{result="cooldown"}` | Normal on a flapping alert. Constant means the cooldown is doing the work a `for:` clause should. |
| `alert_handler_config_valid == 0` | The last reload was rejected; the running config is stale. |
| `alert_handler_webhook_requests_total{result="unauthorised"}` | Something is posting without the token — usually a receiver that was not updated. |
| `alert_handler_actions_inflight` near `workers` | The pool is saturated; slow actions are queueing behind each other. |

Both failure modes are worth an alert rule, and the demo stack in monitor-tools
ships them.

## Logs and secrets

Credential values are replaced with `***` everywhere the handler logs — action
output, error messages and the dry-run trace — so a script that echoes its
token, or an API that returns it in an error body, does not end up in Loki.
Redaction covers values of six characters or more; a two-character "secret" is
not treated as one.

Nothing else is filtered: alert labels and annotations appear in the log as they
arrive, so do not put secrets in an alert.

## Operational endpoints

| Path | Use |
| :--- | :--- |
| `GET /healthz` | Liveness. |
| `GET /-/ready` | Readiness — 503 until rules are loaded. |
| `GET /rules` | The rules as parsed, with the action types per rule. |
| `GET /runbooks` | Script names the handler can see (names only). |
| `GET /metrics` | Prometheus metrics. |

Full list with response shapes: [Reference](reference.md).
