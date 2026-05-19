{{/* vaultscan helpers */}}

{{- define "vaultscan.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vaultscan.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "vaultscan.componentLabels" -}}
{{ include "vaultscan.labels" . }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "vaultscan.componentSelector" -}}
app.kubernetes.io/name: {{ .root.Chart.Name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
Resolve the image reference for a component.

Production strongly prefers SHA-digest pins over tags — a tag is
mutable, a digest is content-addressed. To opt into pinning, set:

  global:
    imageDigests:
      api:           "sha256:abc…"
      cron-runner:   "sha256:def…"
      agent-gateway: "sha256:..."

When global.imageDigests[<repository>] is set, the rendered ref is
"<registry>/<prefix>/<repository>@<digest>" and the tag is ignored.
Otherwise we fall through to the prior tag-based ref so dev / staging
overlays keep working without a digest map.

The Kyverno cosign policy gates on the digest at admission too — but
this helper is the single source of truth for the image string, so
SHA-pinning here is what actually closes the "what runs in prod"
gap.
*/}}
{{- define "vaultscan.image" -}}
{{- $g := .root.Values.global -}}
{{- $digests := $g.imageDigests | default dict -}}
{{- $digest := index $digests .repository -}}
{{- if $digest -}}
{{- printf "%s/%s/%s@%s" $g.imageRegistry $g.imageRepositoryPrefix .repository $digest -}}
{{- else -}}
{{- $tag := .tag | default $g.imageTag | default .root.Chart.AppVersion -}}
{{- printf "%s/%s/%s:%s" $g.imageRegistry $g.imageRepositoryPrefix .repository $tag -}}
{{- end -}}
{{- end -}}

{{/* Standard envFrom: existing Secret + the chart's ConfigMap. */}}
{{- define "vaultscan.envFrom" -}}
- secretRef:
    name: {{ .root.Values.secrets.existingSecret | default (include "vaultscan.fullname" .root) }}
- configMapRef:
    name: {{ include "vaultscan.fullname" .root }}-config
{{- end -}}
