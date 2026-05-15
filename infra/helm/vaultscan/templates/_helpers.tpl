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

{{/* Resolve the image reference for a component. */}}
{{- define "vaultscan.image" -}}
{{- $g := .root.Values.global -}}
{{- $tag := .tag | default $g.imageTag | default .root.Chart.AppVersion -}}
{{- printf "%s/%s/%s:%s" $g.imageRegistry $g.imageRepositoryPrefix .repository $tag -}}
{{- end -}}

{{/* Standard envFrom: existing Secret + the chart's ConfigMap. */}}
{{- define "vaultscan.envFrom" -}}
- secretRef:
    name: {{ .root.Values.secrets.existingSecret | default (include "vaultscan.fullname" .root) }}
- configMapRef:
    name: {{ include "vaultscan.fullname" .root }}-config
{{- end -}}
