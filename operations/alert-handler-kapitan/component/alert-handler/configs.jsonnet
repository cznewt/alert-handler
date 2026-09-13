local base = import 'kapitannet/k8s/base.libsonnet';
local resources = import 'resources.libsonnet';

base.Configs('alert-handler', 'server', resources)
