# Alert Handler

An Alertmanager webhook receiver that **does something** about an alert. Every
alert in a webhook group is matched against an ordered list of rules, and each
matching rule runs its actions: an outbound HTTP call, a command, a runbook
script, a log line, or a write against the Kubernetes API — restart a rollout,
scale a deployment, delete a pod, cordon a node, annotate an object.

It is the small end of the remediation spectrum: the things that do not deserve
their own operator, but that somebody currently does by hand at 3am.

## How it works

1. Alertmanager `POST`s a group of alerts to `/alert`.
2. Each alert is matched against the rules in order — `match` (exact label
   equality), `match_re` (regex over labels) and `status` all have to hold.
3. A matching rule that is not in **cooldown** queues its actions on a thread
   pool, and the webhook answers `202` immediately; Alertmanager retries
   aggressively against slow receivers, so no action ever blocks it.
4. Each action renders its `{{ ... }}` placeholders from that alert, runs, and
   records the outcome in `alert_handler_actions_total`.

## Capabilities

| | |
| :--- | :--- |
| **Actions** | `log`, `http`, `exec`, `runbook`, five Kubernetes writes (`k8s_rollout_restart`, `k8s_scale`, `k8s_delete_pod`, `k8s_cordon_node`, `k8s_annotate`) and three Salt calls (`salt_state_apply`, `salt_cmd`, `salt_run`). |
| **Runbooks** | A mounted directory of scripts, usually a ConfigMap. A new procedure is a config change, not a rebuilt image. |
| **Credentials** | A mounted directory of files, usually a Secret. Actions reach them by name — `{{ secrets.<key> }}`, or `secret_env` on a command — and the values are redacted from every log line. |
| **Salt** | salt-api with a credential, token cached across a burst of alerts, `allowed_targets` globs fencing which minions an action may touch. |
| **LLM** | Any OpenAI-compatible endpoint. A rule can collect diagnostics, hand them to a model, and post the answer where people read it - the model writes text, the rule decides what happens to it. |
| **Incidents** | With `incident: true`, one incident per firing alert: an Alertmanager silence so it stops paging, automatic mitigations, gated steps that wait for a person on `/approvals`, a Jira ticket (Cloud or Server) that a re-fire comments on instead of duplicating, and a person closing it - in Jira or on `/incidents` - which lifts the silences again. See [Incidents](incidents.md). |
| **Chaining** | A rule's actions run in order sharing a namespace, so a later one uses `{{ last.stdout }}` or `{{ llm.answer }}`; a failure stops the chain unless told otherwise. |
| **Guard rails** | Ships in `dry_run`; per-rule cooldown keyed on the alert fingerprint; `allowed_namespaces` in front of every cluster write and `allowed_targets` in front of every Salt call; an optional bearer token on the webhook. |
| **Observability** | A metric per action outcome, per rule; the handler is monitored by the same Prometheus it serves. |

## Where to go next

- [Install](install.md) — image, compose, Kapitan component, Helm chart.
- [Run](run.md) — environment, the dry-run loop, reloads, what to watch.
- [Configuration](configuration.md) — settings, rules, every action type, templating.
- [Usage](usage.md) — wiring Alertmanager and going from logging to acting.
- [Incidents](incidents.md) — silences, approvals, Jira tickets and human resolution.
- [Reference](reference.md) — endpoints and metrics.

A runnable Prometheus → Alertmanager → handler demo lives in the monitor-tools
repository under `extra/alert-handler` (`just alert-handler-demo`).
