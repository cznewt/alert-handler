# Reference

## HTTP endpoints

| Path | Method | Purpose |
| :--- | :--- | :--- |
| `/alert`, `/alerts`, `/webhook`, `/` | POST | Alertmanager webhook receiver. Answers `202 {"queued": n}` as soon as the actions are queued. |
| `/metrics` | GET | Prometheus metrics. |
| `/rules` | GET | The rules as parsed: name, matchers, status, cooldown, action types. |
| `/runbooks` | GET | Names of the scripts in the runbook directory. |
| `/healthz`, `/-/healthy` | GET | Liveness. |
| `/-/ready`, `/readyz` | GET | Readiness; `503` until rules are loaded. |
| `/` | GET | One-line hint. |

Responses are deliberately dull: the webhook never returns `5xx` for a rule that
failed, because Alertmanager would retry the whole group and the actions would
run twice. Failures are visible in the metrics and the log instead.

`SIGHUP` reloads the config, runbooks and credentials.

## Metrics

| Metric | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `alert_handler_webhook_requests_total` | counter | `result` | `accepted`, `unauthorised`, `bad_request`, `error`. |
| `alert_handler_alerts_total` | counter | `status` | Alerts unpacked from the payloads, by alert status. |
| `alert_handler_rule_matches_total` | counter | `rule` | Alerts each rule matched. |
| `alert_handler_actions_total` | counter | `rule`, `action`, `result` | `success`, `failure`, `cooldown`, `dry_run`, `skipped` (the rest of a chain after a failure). `action` is the type, so `salt_state_apply` or `llm` failures are visible on their own. |
| `alert_handler_action_duration_seconds` | histogram | `rule`, `action` | Action wall-clock time. |
| `alert_handler_actions_inflight` | gauge | — | Actions executing right now. |
| `alert_handler_config_rules` | gauge | — | Rules in the loaded config. |
| `alert_handler_config_loaded_timestamp_seconds` | gauge | — | Unix time of the last successful load. |
| `alert_handler_config_valid` | gauge | — | `0` after a rejected reload: the running config is stale. |
| `alert_handler_secrets_loaded` | gauge | — | Credentials read from the secrets directory. |
| `alert_handler_runbooks_available` | gauge | — | Scripts present in the runbook directory. |

### Rules worth having

```yaml
- alert: AlertHandlerActionsFailing
  expr: increase(alert_handler_actions_total{result="failure"}[5m]) > 0
  labels: { severity: warning }
  annotations:
    summary: "{{ $labels.rule }} keeps failing its {{ $labels.action }} action"

- alert: AlertHandlerConfigInvalid
  expr: alert_handler_config_valid == 0
  for: 5m
  labels: { severity: warning }
  annotations:
    summary: "alert-handler is running a stale config, the last reload failed"
```

## Scrape annotations

The Deployment pod template and the Service both carry
`prometheus.io/{scrape,port,path}` and `metrics.grafana.com/{scrape,port,path}`,
so the handler is discovered whether the agent scrapes with role `pod` or role
`endpoints` — no scrape config needed in either convention.

## Rendered manifests

`base.Components('alert-handler', 'server', resources)` produces:

| Manifest | Notes |
| :--- | :--- |
| `alert-handler-server-deployment` | Scrape annotations, `checksum/config` over the config **and** the runbooks, readiness on `/-/ready`, read-only root filesystem. |
| `alert-handler-server-service` | ClusterIP on 8080, same annotations. |
| `alert-handler-server-configmap-service` | `config.yaml`, mounted as a file via `subPath`. |
| `alert-handler-server-configmap-runbooks` | One key per runbook, mounted at `/etc/alert-handler/runbooks`. |
| `alert-handler-server-service-account` | Subject of the binding below. |
| `alert-handler-server-cluster-role` + `-binding` | Only when `rbac: true` (the default). |

The credentials Secret is **not** rendered — it is referenced by name
(`alert_handler_secret_name`) and created out of band, so no secret material
passes through the inventory or the compiled output.
