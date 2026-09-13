local base = import 'kapitannet/k8s/base.libsonnet';
local resources = import 'resources.libsonnet';

base.Components('alert-handler', 'server', resources)
