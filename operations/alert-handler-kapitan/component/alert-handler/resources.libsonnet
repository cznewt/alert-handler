local files = import 'files.libsonnet';
local kube = import 'kapitannet/k8s/resources.libsonnet';

{
  local this = self,

  // An existing Secret mounted at the credentials directory: one key per
  // credential. Left empty, the handler simply has no credentials.
  local secret_name(service) = if std.objectHas(service, 'secret_name') then service.secret_name else '',

  // Auto-scrape annotations in both conventions: classic Prometheus
  // (`prometheus.io/*`) and Grafana Alloy (`metrics.grafana.com/*`, whose
  // default role is `endpoints`). Set on the pod template and the Service so
  // discovery works either way, without double-scraping.
  scrape_annotations:: {
    'prometheus.io/scrape': 'true',
    'prometheus.io/port': '8080',
    'prometheus.io/path': '/metrics',
    'metrics.grafana.com/scrape': 'true',
    'metrics.grafana.com/port': '8080',
    'metrics.grafana.com/path': '/metrics',
  },

  deployment: this.Deployment,
  service: this.Service,
  configmap_service: this.ServiceConfigMap,
  configmap_runbooks: this.RunbooksConfigMap,
  service_account: kube.ServiceAccount,
  secret_basic_auth: kube.BasicAuthSecret,
  // Both are gated by `rbac: false` in the inventory, for a handler that only
  // runs log/http/exec actions and has no business talking to the API server.
  cluster_role: this.ClusterRole,
  cluster_role_binding: kube.ClusterRoleBinding,

  ServiceConfigMap(service):: kube.ConfigMap(service) {
    data: {
      // quote_keys=false keeps the rendered file readable in `kubectl get cm -o yaml`.
      'config.yaml': std.manifestYamlDoc(
        files.ServiceConfigFile(service), indent_array_in_object=false, quote_keys=false
      ),
    },
  },
  RunbooksConfigMap(service):: kube.ConfigMap(service) {
    data: files.RunbookFiles(service),
  },
  ClusterRole(service):: kube.ClusterRole(service) {
    // Only what the k8s_* actions in the shipped config need. Trim it with
    // `alert_handler_rbac_rules` when a site uses fewer action types.
    rules: service.rbac_rules,
  },
  ServerContainer(service):: kube.Container(service) {
    ports_+: {
      http: {
        protocol: 'TCP',
        containerPort: 8080,
      },
    },
    env_+: service.env_vars,
    volumeMounts_+: if secret_name(service) != '' then {
      secrets: {
        mountPath: '/etc/alert-handler/secrets',
        readOnly: true,
      },
    } else {},
    readinessProbe: {
      httpGet: {
        path: '/-/ready',
        port: 8080,
      },
      initialDelaySeconds: 5,
      periodSeconds: 15,
    },
    livenessProbe: {
      httpGet: {
        path: '/healthz',
        port: 8080,
      },
      initialDelaySeconds: 15,
      periodSeconds: 30,
    },
    securityContext: {
      allowPrivilegeEscalation: false,
      readOnlyRootFilesystem: true,
      capabilities: {
        drop: [
          'ALL',
        ],
      },
    },
  },
  Deployment(service):: kube.Deployment(service) {
    spec+: {
      template+: {
        metadata+: {
          annotations+: $.scrape_annotations {
            // Roll the pod when the rules change: the file is only read at
            // start-up (or on SIGHUP), so a ConfigMap edit alone is invisible.
            'checksum/config': kube.ConfigHash(
              [$.configmap_service(service).data['config.yaml']]
              + [
                $.configmap_runbooks(service).data[runbook]
                for runbook in std.objectFields($.configmap_runbooks(service).data)
              ]
            ),
          },
        },
        spec+: {
          serviceAccountName: service.name,
          // a private registry: name an EXISTING docker-registry Secret in the namespace.
          // Not `pull_secrets`: the base library renders a Secret for that key, and
          // with no token in the inventory it would overwrite the real one.
          imagePullSecrets: if std.objectHas(service, 'pull_secret_name') && service.pull_secret_name != '' then [{ name: service.pull_secret_name }] else [],
          volumes_+: if secret_name(service) != '' then {
            secrets: {
              secret: {
                secretName: secret_name(service),
              },
            },
          } else {},
          containers+: [
            $.ServerContainer(service),
          ],
        },
      },
    },
  },
  Service(service, deploy=null, container_name=null):: kube.Service(service, deploy, container_name) {
    metadata+: {
      annotations+: $.scrape_annotations,
    },
  },
}
