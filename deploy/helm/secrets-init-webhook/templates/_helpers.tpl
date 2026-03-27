{{/*
Expand the name of the chart.
*/}}
{{- define "secrets-init-webhook.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "secrets-init-webhook.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "secrets-init-webhook.labels" -}}
helm.sh/chart: {{ include "secrets-init-webhook.name" . }}-{{ .Chart.Version }}
{{ include "secrets-init-webhook.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "secrets-init-webhook.selectorLabels" -}}
app.kubernetes.io/name: {{ include "secrets-init-webhook.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
