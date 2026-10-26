{{- define "appguard.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "appguard.fullname" -}}
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

{{- define "appguard.labels" -}}
helm.sh/chart: {{ include "appguard.name" . }}-{{ .Chart.Version | replace "+" "_" }}
{{ include "appguard.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "appguard.selectorLabels" -}}
app.kubernetes.io/name: {{ include "appguard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "appguard.backendName" -}}
{{ include "appguard.fullname" . }}-backend
{{- end }}

{{- define "appguard.frontendName" -}}
{{ include "appguard.fullname" . }}-frontend
{{- end }}

{{- define "appguard.postgresqlName" -}}
{{ include "appguard.fullname" . }}-postgresql
{{- end }}

{{- define "appguard.databaseUrl" -}}
{{- if .Values.postgresql.internal -}}
postgres://{{ .Values.postgresql.user }}:{{ .Values.secrets.postgresPassword | default .Values.postgresql.password | urlquery }}@{{ include "appguard.postgresqlName" . }}:5432/{{ .Values.postgresql.database }}?sslmode=disable
{{- else -}}
{{- .Values.postgresql.externalUrl }}
{{- end -}}
{{- end }}
