{
  // Rendered into the ConfigMap as config.yaml; the shape is exactly what
  // alert_handler.py parses, so the inventory is the configuration reference.
  ServiceConfigFile(service):: {
    settings: service.settings,
    rules: service.rules,
  },
  // One ConfigMap key per runbook: `{ 'recycle.sh': '#!/bin/sh\n...' }`. They
  // mount 0644, which is why the handler falls back to `/bin/sh <script>` when
  // the executable bit is missing.
  RunbookFiles(service):: service.runbooks,
}
