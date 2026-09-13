# Install

The handler is one stateless Python process listening on `:8080`. It needs a
config file; a runbook directory and a credentials directory are optional, and
Kubernetes access is only required for the `k8s_*` actions.

## Container image

```bash
docker run --rm -p 8080:8080 \
  -v "$PWD/config.yaml:/etc/alert-handler/config.yaml:ro" \
  ghcr.io/cznewt/alert-handler:latest
```

Images are published to ghcr as `ghcr.io/cznewt/alert-handler`, tagged from
`.env` (`IMAGE_TAG`, e.g. `2026.9-r2`) and `latest`. The image bakes a default
`config.yaml` with a single logging rule and `dry_run: true`, so it starts
safely without one.

Three mount points exist in the image:

| Path | Holds | Usually |
| :--- | :--- | :--- |
| `/etc/alert-handler/config.yaml` | Settings and rules | ConfigMap key, mounted as a file |
| `/etc/alert-handler/runbooks/` | Scripts a `runbook` action can run | ConfigMap |
| `/etc/alert-handler/secrets/` | One file per credential | Secret |

Mount the config as a **file**, not over `/etc/alert-handler`: the other two
directories live inside it, and a read-only ConfigMap volume over the parent
leaves the kubelet nowhere to create them.

## Compose

From the component directory:

```bash
docker compose up -d --build
curl -s localhost:8080/rules
```

`docker-compose.yml` mounts `docker/config.yaml`, which is the fastest way to
try a matcher out — edit, `docker compose restart`, re-post a payload.

## Kubernetes, with Kapitan

```bash
just kapitan-target-build test-alert-handler-base    # SOURCE_TARGET=<target>
just kube-target-apply   test-alert-handler-base
```

The component renders a Deployment, a Service, the config ConfigMap, a ConfigMap
of runbooks, a ServiceAccount and — unless `rbac: false` — a ClusterRole and
binding. The pod template hashes the config and the runbooks, so changing either
rolls the pod instead of leaving the old rules running.

```yaml
parameters:
  _param_:
    alert_handler_settings:
      dry_run: false
      allowed_namespaces: [monitor, prod]
    alert_handler_secret_name: alert-handler-credentials   # an existing Secret
    alert_handler_runbooks:
      recycle-deployment.sh: |
        #!/bin/sh
        set -eu
        kubectl -n "$1" rollout restart "deployment/$2"
    ~alert_handler_rules:
      - name: recycle
        match: { alertname: KubeDeploymentReplicasMismatch }
        actions:
          - type: runbook
            name: recycle-deployment.sh
            args: ["{{ labels.namespace }}", "{{ labels.deployment }}"]
```

Two inventory details worth knowing:

- `~alert_handler_rules` **replaces** the class's rule list. Reclass appends
  lists, so a plain assignment leaves the default logging rule in front of yours.
- A runbook embedded in the inventory must not contain `${...}` — reclass reads
  that as its own reference syntax and fails to resolve it. Plain `$1` is fine.

## Kubernetes, with Helm

```bash
helm install alert-handler operations/alert-handler-helm-chart \
  --set settings.dry_run=false \
  --set rbac.create=true \
  --set secretName=alert-handler-credentials \
  --set-file runbooks.recycle-deployment\\.sh=./runbooks/recycle-deployment.sh
```

`values.yaml` carries the same `settings` and `rules`, plus `runbooks` (a map of
file name to script) and `secretName` (an existing Secret). `rbac.create` is off
by default — turn it on only for the `k8s_*` actions.

## Credentials

Credentials are files, one per credential, and the handler never writes them
anywhere. Create the Secret out of band:

```bash
kubectl -n monitor create secret generic alert-handler-credentials \
  --from-literal=chat-token=xoxb-... \
  --from-file=kubeconfig=./kubeconfig
```

Each key becomes `{{ secrets.<key> }}` in any action field, or an environment
variable through an action's `secret_env`. See
[Configuration](configuration.md#credentials).

## Salt

The `salt_*` actions need three things: `settings.salt.url` pointing at a
salt-api (`rest_cherrypy`), an eauth user, and that user's password or token as
a credential in the secrets directory. Nothing is mounted for it and no RBAC is
involved — it is an HTTP call.

```bash
kubectl -n monitor create secret generic alert-handler-credentials \
  --from-literal=salt-password='...'
```

The eauth user needs exactly the functions the rules call. With Salt's
`external_auth`, that is worth writing out rather than granting `.*`:

```yaml
external_auth:
  rest:
    alert-handler:
      - 'gedu-*':
          - state.apply
          - service.restart
```

## RBAC

The default ClusterRole is the minimum the shipped Kubernetes actions need:

| Resource | Verbs | For |
| :--- | :--- | :--- |
| `apps/deployments,statefulsets,daemonsets` | get, list, patch | `k8s_rollout_restart`, `k8s_annotate` |
| `apps/*/scale` | get, patch, update | `k8s_scale` |
| `pods` | get, list, delete | `k8s_delete_pod` |
| `nodes` | get, list, patch | `k8s_cordon_node`, `k8s_annotate` |

Trim it with `alert_handler_rbac_rules` (Kapitan) or `rbac.rules` (Helm) to the
actions you actually use, and set `rbac: false` for a handler that only logs,
posts and runs runbooks — then it needs no cluster access at all.
`allowed_namespaces` is the other half of that fence: RBAC says which verbs, the
allow-list says where.

## Sizing

A webhook receiver and a small thread pool: 25m CPU and 64Mi is enough for the
handler itself. What costs anything is what the actions do — an `exec` or
`runbook` script runs in this container, as the unprivileged `handler` user,
with whatever tooling the image has. To give a runbook `kubectl` or `curl`,
layer your own image `FROM ghcr.io/cznewt/alert-handler` and point the component
at it.

Run **one replica** unless every action is idempotent: cooldowns live in memory,
so two replicas dedupe separately.
