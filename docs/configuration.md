# Configuration

One YAML file — `settings` and `rules`. The Kapitan component and the Helm chart
both render it into a ConfigMap from inventory parameters, so the inventory *is*
the configuration.

## settings

| Key | Default | Meaning |
| :--- | :--- | :--- |
| `dry_run` | `true` | Log what each action would do, change nothing. The shipped default. |
| `cooldown` | `300` | Seconds a (rule, alert) pair stays silent after firing. Per-rule override. |
| `action_timeout` | `30` | Per-action wall-clock budget, seconds. Per-action override. |
| `workers` | `4` | Concurrent actions. |
| `allowed_namespaces` | `[]` | Empty = any namespace. Otherwise Kubernetes actions outside the list are refused. |
| `auth_token` | `""` | When set, `/alert` requires `Authorization: Bearer <token>`. `WEBHOOK_TOKEN` overrides it. |
| `auth_token_secret` | `""` | Name of a credential file to read that token from instead — keeps it out of the ConfigMap. |
| `salt` | _(unconfigured)_ | salt-api connection for the `salt_*` actions, see [Salt](#salt). |
| `llm` | _(unconfigured)_ | OpenAI-compatible endpoint for the `llm` action, see [LLM](#llm). |
| `public_url`, `state_file`, `alertmanager`, `jira`, `approvals`, `incidents` | _(unconfigured)_ | Incidents, approvals, silences and tickets, see [Incidents](incidents.md#settings). |

## rules

Rules are evaluated in order, for every alert in the group.

```yaml
rules:
  - name: recycle-crashlooping-deployment
    match:                       # all must match exactly
      alertname: KubePodCrashLooping
    match_re:                    # all must match as a full-string regex
      namespace: 'prod-.*'
    status: firing               # firing (default) | resolved | any
    cooldown: 900                # overrides settings.cooldown
    continue: true               # false = stop after this rule matches
    incident: false              # true = track an incident per firing alert
    actions: [...]
```

| Field | Default | Meaning |
| :--- | :--- | :--- |
| `name` | `rule-<n>` | Used in logs and in every metric label. |
| `match` | `{}` | Label equality, ANDed. Empty matches everything. |
| `match_re` | `{}` | Full-string regex per label, ANDed with `match`. |
| `status` | `firing` | `firing`, `resolved` or `any`. |
| `cooldown` | `settings.cooldown` | Seconds, keyed on (rule, alert fingerprint). `0` disables. |
| `continue` | `true` | `false` stops rule evaluation for this alert after a match. |
| `incident` | `false` | `true` opens an incident per firing alert: silences, ticket, timeline, closed by a person. See [Incidents](incidents.md). |
| `actions` | _(required)_ | At least one; a rule without actions is a config error. |

Cooldown is the flap guard. Alertmanager re-notifies every `repeat_interval`;
without it, a rule would restart a deployment on every repeat.

## Actions

| `type` | Fields | Does |
| :--- | :--- | :--- |
| `log` | `message` | Writes one line. Good on its own while tuning matchers. |
| `http` | `url`, `method` (POST), `headers`, `body` (string or object → JSON), `timeout` | Calls a webhook: chat, a ticket API, another automation. |
| `exec` | `command` (argv list, or a string run via `/bin/sh -c`), `env`, `secret_env`, `timeout` | Runs a command from the image. |
| `runbook` | `name`, `args`, `env`, `secret_env`, `timeout` | Runs a script from the runbook directory. |
| `k8s_rollout_restart` | `kind` (deployment/statefulset/daemonset), `namespace`, `name` | Patches `kubectl.kubernetes.io/restartedAt`, like `kubectl rollout restart`. |
| `k8s_scale` | `kind`, `namespace`, `name`, `replicas` | Patches the `scale` subresource. |
| `k8s_delete_pod` | `namespace`, `name` | Deletes one pod, lets its controller replace it. |
| `k8s_cordon_node` | `name`, `unschedulable` (`true`) | Cordons, or with `false` uncordons, a node. |
| `k8s_annotate` | `annotations`, plus `node`, or `kind`+`namespace`+`name` | Annotates the object — e.g. stamp what an alert did. |
| `salt_state_apply` | `tgt`, `tgt_type` (`glob`), `state`, `pillar`, `test`, `salt_timeout` | `state.apply <state>` on the matching minions. |
| `salt_cmd` | `tgt`, `tgt_type`, `fun`, `arg`, `kwarg`, `salt_timeout` | Any execution module: `cmd.run`, `service.restart`, `pkg.install`, … |
| `salt_run` | `fun`, `arg`, `kwarg` | A runner on the master itself: `manage.up`, `state.orchestrate`, … |
| `llm` | `prompt`, `system`, `model`, `max_tokens`, `temperature`, `url`, `api_key_secret` | Asks an OpenAI-compatible endpoint about the alert and keeps the answer in `{{ llm.answer }}`. |
| `am_silence` | `duration`, `labels`, `comment`, `url`, `tenant` | Silences the alert in Alertmanager. See [Incidents](incidents.md#silences). |
| `am_expire` | `id`, `url`, `tenant` | Expires a silence, or every silence the incident set. |
| `jira_create` | `summary`, `description`, `project`, `issue_type`, `priority`, `labels`, `fields` | Opens a ticket, or comments on the alert's open one. See [Incidents](incidents.md#jira). |
| `jira_comment` | `body`, `issue` | Comments on the alert's ticket. |
| `jira_transition` | `transition`, `comment`, `issue` | Moves the alert's ticket. |

Every action also accepts `timeout`, `continue_on_error: true` to keep the
rest of the rule running when it fails, and `approval: required` to wait for a
person before it runs ([Approvals](incidents.md#approvals)). The `k8s_*` actions talk to the API server
with the pod's ServiceAccount token over plain HTTP calls — no vendored SDK to
keep in step with the cluster version — and refuse namespaces outside
`allowed_namespaces`.

## Chaining

A rule's actions run **in order**, sharing one namespace, so a later action can
use what an earlier one produced:

| Placeholder | Set by |
| :--- | :--- |
| `{{ last.stdout }}`, `{{ last.stderr }}`, `{{ last.exit_code }}` | The previous `exec` or `runbook` action. |
| `{{ llm.answer }}`, `{{ llm.model }}`, `{{ llm.tokens }}` | The previous `llm` action. |
| `{{ steps }}` | Every action so far in this chain, one line each: what the ticket shows. |
| `{{ silence.id }}`, `{{ silence.until }}` | The previous `am_silence`. |
| `{{ jira.key }}`, `{{ jira.url }}`, `{{ jira.created }}` | The previous `jira_*` action. |
| `{{ incident.id }}`, `{{ incident.url }}` | The rule's incident, with `incident: true`. |
| `{{ approval.by }}`, `{{ approval.at }}`, `{{ approval.url }}` | The approval that resumed this chain. |

A failed action **stops the rest of the chain** — if the diagnostic did not run
there is nothing to explain and nothing to announce — and the skipped actions
are counted as `result="skipped"`. An action that should not stop it sets
`continue_on_error: true`.

Different rules, and different alerts, still run concurrently; `workers` bounds
how many chains are in flight.

## Templating

Action fields are rendered per alert:

| Placeholder | Value |
| :--- | :--- |
| `{{ labels.<name> }}` | Alert label. |
| `{{ annotations.<name> }}` | Alert annotation. |
| `{{ status }}`, `{{ fingerprint }}`, `{{ startsAt }}`, `{{ endsAt }}`, `{{ generatorURL }}` | Alert fields. |
| `{{ receiver }}`, `{{ externalURL }}`, `{{ groupKey }}` | The webhook group envelope. |
| `{{ secrets.<key> }}` | A credential (see below). |

Substitution only — no loops, no conditionals, no expression evaluation. An
action that can delete a pod is the wrong place for a template language. A
placeholder the alert does not carry renders empty and logs a warning, which is
how you catch a typo.

## Runbooks

A runbook is a script in `RUNBOOK_DIR` (`/etc/alert-handler/runbooks`), usually a
mounted ConfigMap, so a new procedure is a config change rather than a rebuilt
image.

```yaml
- type: runbook
  name: recycle-deployment.sh          # file name, no paths
  args: ["{{ labels.namespace }}", "{{ labels.deployment }}"]
  secret_env:
    KUBECONFIG: kubeconfig             # credential name -> env var
```

- The name is resolved inside the directory; anything that escapes it is
  refused, and a missing script fails with the list of what is there.
- ConfigMap keys mount `0644`, so a script without the executable bit is run
  through `/bin/sh`. Either works; a shebang is respected when the bit is set.
- Scripts run as the unprivileged `handler` user with the image's tooling. To
  give a runbook `kubectl` or `curl`, layer your own image
  `FROM ghcr.io/cznewt/alert-handler`.
- `GET /runbooks` lists what the handler can see.

The alert reaches the script as environment variables, so it needs no JSON
parsing:

| Variable | Example |
| :--- | :--- |
| `ALERT_STATUS` | `firing` |
| `ALERT_FINGERPRINT` | `a1b2c3` |
| `ALERT_STARTS_AT` | `2026-09-11T09:00:00Z` |
| `ALERT_LABELS`, `ALERT_ANNOTATIONS` | JSON objects |
| `ALERT_LABEL_<NAME>` | One per label with a name that is a valid identifier, upper-cased |

## Credentials

Credentials are files in `SECRETS_DIR` (`/etc/alert-handler/secrets`), usually a
mounted Secret: the file name is the key, its stripped contents the value.

```bash
kubectl -n monitor create secret generic alert-handler-credentials \
  --from-literal=chat-token=xoxb-... --from-file=kubeconfig=./kubeconfig
```

Two ways to use one, and no third:

```yaml
- type: http
  url: https://chat.example/hooks/alerts
  headers:
    Authorization: "Bearer {{ secrets.chat-token }}"   # rendered into the field

- type: runbook
  name: recycle-deployment.sh
  secret_env:
    KUBECONFIG: kubeconfig                             # injected as an env var
```

They are never injected wholesale into the process environment — an action gets
exactly the credentials it names — and their values are **redacted from every
log line**, including action output and the dry-run trace. A credential an
action names but the directory does not hold is a clean failure, not an empty
string.

## Salt

The half of an estate that is not in Kubernetes still has alerts. Point the
handler at salt-api and a rule can re-apply a state, restart a service or run an
orchestration exactly as it restarts a Deployment.

```yaml
settings:
  salt:
    url: https://salt-master.infra-salt.svc:8180
    eauth: rest                    # pam | ldap | rest | ...
    username: alert-handler
    password_secret: salt-password # credential file holding the password
    # token_secret: salt-token     # ... or a pre-issued token, instead
    verify_tls: true
    timeout: 60
    allowed_targets:               # empty = any minion; globs
      - 'gedu-*'
      - 'geekedu-roam-*'
```

- **Authentication** is the credentials capability: the password (or a token)
  is a file in the secrets directory, never a value in the rules. The handler
  logs in once and caches the token until it expires, so a group of twenty
  alerts is one login, not twenty.
- **`allowed_targets`** is the blast-radius fence, the counterpart of
  `allowed_namespaces`: an action whose `tgt` matches no pattern is refused
  before anything reaches the master. Set it before turning `dry_run` off —
  `tgt` usually comes from an alert label, and a label you do not control is
  not a target you want unfenced.
- **Failure is real failure**: a `state.apply` where any state reports
  `result: false` counts as a failed action, so
  `alert_handler_actions_total{result="failure"}` catches a remediation that
  ran but did not work.

```yaml
  - name: reapply-state-on-drift
    match:
      alertname: SaltStateDrift
    cooldown: 1800
    actions:
      - type: salt_state_apply
        tgt: "{{ labels.minion }}"
        state: batocera
        pillar:
          reason: "{{ labels.alertname }}"
      - type: salt_cmd
        tgt: "{{ labels.minion }}"
        fun: service.restart
        arg: ["alloy"]
```

The summary line names the minions that answered and how many states failed,
truncated to five minions, so a fleet-wide apply stays one log line.

## LLM

Alerts arrive with labels; people want sentences. Point the handler at any
OpenAI-compatible endpoint — LiteLLM, vLLM, Ollama's `/v1` shim, a gateway —
and a rule can hand the alert (and the output of a diagnostic it just ran) to a
model, then do something with the answer.

```yaml
settings:
  llm:
    url: http://litellm.infra-llm.svc:4000/v1/chat/completions
    model: sre-small
    api_key_secret: llm-api-key     # credential file, as everywhere else
    system: "You are an SRE assistant. Be concrete and brief."
    max_tokens: 400
    temperature: 0.2
    timeout: 60
```

The shape that makes it worth having is the three-step chain:

```yaml
  - name: diagnose-and-explain
    match:
      alertname: DiskFillingUp
    actions:
      # 1. collect the evidence, on the machine, with a script you control
      - type: runbook
        name: collect-disk-usage.sh
        args: ["{{ labels.instance }}"]
      # 2. hand the alert and that output to the model
      - type: llm
        prompt: |
          Alert {{ labels.alertname }} on {{ labels.instance }}.
          Summary: {{ annotations.summary }}
          Diagnostics:
          {{ last.stdout }}
          In two sentences: what is happening, and what should the on-call do?
      # 3. put the answer where people read it
      - type: http
        method: POST
        url: https://chat.example/hooks/alerts
        headers: { Authorization: "Bearer {{ secrets.chat-token }}" }
        body:
          text: "[{{ labels.alertname }}] {{ llm.answer }}"
```

Worth being clear about what this is and is not:

- **The model writes text. The rule decides what happens to it.** There is no
  action that executes what a model suggests, and there will not be one - the
  interesting failure modes of an LLM belong in a chat message, not in a
  `kubectl delete`.
- **The prompt is data you control**: alert fields and the output of your own
  script. Alert annotations come from your rules, but treat anything that
  reaches the prompt from outside as untrusted text.
- **Cost and latency are per alert.** A chain holds a worker for the length of
  the completion; keep `max_tokens` small, `timeout` honest, and the rule's
  matcher narrow. The cooldown applies here too - an alert that flaps should not
  buy twenty completions.
- The answer is never logged in full - the summary line is model, length and
  token count.

## A complete example

```yaml
settings:
  dry_run: false
  cooldown: 900
  action_timeout: 30
  workers: 4
  allowed_namespaces: [prod]
  auth_token_secret: webhook-token

rules:
  - name: recycle-crashlooping-deployment
    match: { alertname: KubePodCrashLooping }
    match_re: { namespace: 'prod' }
    actions:
      - type: runbook
        name: recycle-deployment.sh
        args: ["{{ labels.namespace }}", "{{ labels.deployment }}"]
      - type: http
        method: POST
        url: https://chat.example/hooks/alerts
        headers: { Authorization: "Bearer {{ secrets.chat-token }}" }
        body:
          text: "recycled {{ labels.namespace }}/{{ labels.deployment }}"

  - name: scale-out-workers
    match: { alertname: CeleryQueueBacklog, severity: warning }
    cooldown: 1800
    actions:
      - type: k8s_scale
        kind: deployment
        namespace: "{{ labels.namespace }}"
        name: "{{ labels.deployment }}"
        replicas: 4

  - name: log-everything
    status: any
    cooldown: 0
    actions:
      - type: log
        message: "{{ status }} {{ labels.alertname }} on {{ labels.instance }}: {{ annotations.summary }}"
```
