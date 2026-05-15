{{/*
Shared pod & container security contexts (HS-03).

Every workload in the chart imports these helpers so the security
posture stays consistent: non-root, read-only root filesystem, all
capabilities dropped, no privilege escalation, seccomp RuntimeDefault.
*/}}

{{- define "vaultscan.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "vaultscan.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: 65532
capabilities:
  drop: [ALL]
{{- end -}}

{{- define "vaultscan.scannerContainerSecurityContext" -}}
# Scanner pods need to bind to low ports for some tools — keep them
# non-root but allow NET_BIND_SERVICE only when explicitly requested.
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: 65532
capabilities:
  drop: [ALL]
  add: [NET_BIND_SERVICE]
{{- end -}}

{{- define "vaultscan.podTopologyConstraints" -}}
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels: {{ . | toYaml | nindent 8 }}
{{- end -}}
