# Usage

The path from "alerts fire into a chat channel" to "alerts fix things" is short,
but it should be walked in order. Every step below is reversible; the one after
it is not always.

## 1. Route alerts to the handler

Add a receiver in Alertmanager. A `continue: true` route that copies alerts to
the handler alongside your human receivers is usually the right shape — people
still get paged, the handler does the mechanical part:

```yaml
route:
  routes:
    - receiver: alert-handler
      matchers: [ 'severity=~"warning|critical"' ]
      continue: true          # keep walking the tree, humans still get theirs

receivers:
  - name: alert-handler
    webhook_configs:
      - url: http://alert-handler-server.monitor.svc:8080/alert
        send_resolved: true
        # when settings.auth_token / auth_token_secret is set:
        # http_config:
        #   authorization: { type: Bearer, credentials: <token> }
```

`send_resolved: true` matters if you want clean-up rules (`status: resolved`).

## 2. Log first

Keep `dry_run: true` and start with one rule that matches everything:

```yaml
rules:
  - name: log-everything
    status: any
    cooldown: 0
    actions:
      - type: log
        message: "{{ status }} {{ labels.alertname }} ns={{ labels.namespace }} {{ annotations.summary }}"
```

Now the log tells you exactly which labels your alerts carry — which is what the
matchers in the next step depend on. Guessing `deployment` when your alerts only
have `pod` is the most common way to write a rule that never fires, or worse,
one that fires with an empty name.

## 3. Write the matcher, still dry

```yaml
  - name: recycle-crashlooping-deployment
    match:
      alertname: KubePodCrashLooping
    match_re:
      namespace: 'prod-.*'
    actions:
      - type: runbook
        name: recycle-deployment.sh
        args: ["{{ labels.namespace }}", "{{ labels.deployment }}"]
```

Check three things in the dry-run trace before going further:

- the rule matches the alerts you meant, and only those —
  `alert_handler_rule_matches_total{rule="..."}`;
- the rendered arguments are right, with no empty placeholders;
- the rule does **not** match resolved alerts unless you meant it to.

## 4. Turn it on, narrowly

```yaml
settings:
  dry_run: false
  allowed_namespaces: [prod-payments]   # start with one
  cooldown: 900
```

`allowed_namespaces` is the blast-radius fence for every Kubernetes action:
RBAC decides which verbs, the allow-list decides where. Widen it once the rule
has a few days of quiet behaviour behind it.

## 5. Give the runbook what it needs

A runbook is a script in the mounted directory, and a credential is a file in
another one. The action names both; nothing else is handed over:

```yaml
    actions:
      - type: runbook
        name: recycle-deployment.sh
        args: ["{{ labels.namespace }}", "{{ labels.deployment }}"]
        secret_env:
          KUBECONFIG: kubeconfig
      - type: http
        method: POST
        url: https://chat.example/hooks/alerts
        headers:
          Authorization: "Bearer {{ secrets.chat-token }}"
        body:
          text: "recycled {{ labels.namespace }}/{{ labels.deployment }} after {{ labels.alertname }}"
```

```sh
#!/bin/sh
# recycle-deployment.sh - $1 namespace, $2 deployment
set -eu
echo "recycling $2 in $1 after $ALERT_LABEL_ALERTNAME"
kubectl -n "$1" rollout restart "deployment/$2"
```

The credential value never appears in the rule, in the ConfigMap, or in the
logs. Details in [Configuration](configuration.md#credentials).

## Choosing where the logic goes

| Put it in | When |
| :--- | :--- |
| An Alertmanager route | The decision is "who hears about this". |
| A Prometheus rule | The decision is "is this a problem" — `for:` beats a cooldown. |
| A handler rule | The decision is "what to do about it", and it is the same every time. |
| A runbook script | The what-to-do has steps, conditionals, or needs a tool. |
| A Salt state | The target is a machine rather than a pod, and the fix is "make it look like the state again". |
| An operator | The thing needs to watch state continuously, not react to an alert. |

If you find yourself writing a `for:` clause into the handler, it belongs in the
alerting rule; if you find yourself writing a reconcile loop into a runbook, it
belongs in an operator.

## Worked examples

**Restart what is crash-looping**, at most once every 15 minutes:

```yaml
  - name: recycle-crashlooping-deployment
    match: { alertname: KubePodCrashLooping }
    cooldown: 900
    actions:
      - type: k8s_rollout_restart
        kind: deployment
        namespace: "{{ labels.namespace }}"
        name: "{{ labels.deployment }}"
```

**Scale out on a queue backlog**, once:

```yaml
  - name: scale-out-workers
    match: { alertname: CeleryQueueBacklog, severity: warning }
    cooldown: 1800
    actions:
      - type: k8s_scale
        kind: deployment
        namespace: "{{ labels.namespace }}"
        name: "{{ labels.deployment }}"
        replicas: 4
```

**Cordon a node with failing disks** and tell the channel:

```yaml
  - name: cordon-bad-node
    match: { alertname: NodeDiskErrors }
    cooldown: 3600
    actions:
      - type: k8s_cordon_node
        name: "{{ labels.node }}"
      - type: http
        method: POST
        url: https://chat.example/hooks/ops
        headers: { Authorization: "Bearer {{ secrets.chat-token }}" }
        body: { text: "cordoned {{ labels.node }}: {{ annotations.summary }}" }
```

**Re-apply a Salt state on a node that drifted**, at most twice an hour:

```yaml
  - name: reapply-state-on-drift
    match: { alertname: SaltStateDrift }
    cooldown: 1800
    actions:
      - type: salt_state_apply
        tgt: "{{ labels.minion }}"
        state: batocera
        pillar: { reason: "{{ labels.alertname }}" }
```

The minion comes from an alert label, so `settings.salt.allowed_targets` is what
stands between a mislabelled alert and a state run on the wrong machine.

**Diagnose, explain, announce** — the chain that makes an alert readable:

```yaml
  - name: diagnose-and-explain
    match: { alertname: DiskFillingUp }
    cooldown: 1800
    actions:
      - type: runbook
        name: collect-disk-usage.sh
        args: ["{{ labels.instance }}"]
      - type: llm
        prompt: |
          Alert {{ labels.alertname }} on {{ labels.instance }}.
          Diagnostics:
          {{ last.stdout }}
          In two sentences: what is happening, and what should the on-call do?
      - type: http
        method: POST
        url: https://chat.example/hooks/alerts
        headers: { Authorization: "Bearer {{ secrets.chat-token }}" }
        body: { text: "[{{ labels.alertname }}] {{ llm.answer }}" }
```

The script runs where the handler runs, the model only ever writes text, and if
the script fails the rest of the chain is skipped rather than asking a model to
explain an empty string.

**Clean up when it resolves**:

```yaml
  - name: uncordon-when-clear
    match: { alertname: NodeDiskErrors }
    status: resolved
    actions:
      - type: k8s_cordon_node
        name: "{{ labels.node }}"
        unschedulable: false
```

## Watch the handler itself

An automation nobody watches is worse than no automation. Scrape the handler
(the manifests annotate themselves for it) and alert on failing actions and on
a rejected config reload — the two rules are in [Reference](reference.md#rules-worth-having).

Then, once a month, read `alert_handler_actions_total` and ask which rules
actually fired. A rule that never fires is dead weight; a rule that fires every
day is papering over something that deserves a fix.
