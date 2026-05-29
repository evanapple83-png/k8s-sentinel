{{- define "k8s-sentinel.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "k8s-sentinel.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "k8s-sentinel.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "k8s-sentinel.labels" -}}
app.kubernetes.io/name: {{ include "k8s-sentinel.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{- define "k8s-sentinel.serviceAccountName" -}}
{{- printf "%s-sa" (include "k8s-sentinel.fullname" .) -}}
{{- end -}}

{{- /*
Agent image reference. Prefer an immutable digest (set by CI at chart-publish
time → fully reproducible, IfNotPresent-safe); fall back to the mutable tag for
local/dev. (F13)
*/ -}}
{{- define "k8s-sentinel.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- end -}}
{{- end -}}
