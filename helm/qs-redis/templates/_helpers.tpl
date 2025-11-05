{{/*
Expand the name of the chart.
*/}}
{{- define "qs-redis.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "qs-redis.fullname" -}}
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
Create chart name and version as used by the chart label.
*/}}
{{- define "qs-redis.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "qs-redis.labels" -}}
helm.sh/chart: {{ include "qs-redis.chart" . }}
{{ include "qs-redis.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "qs-redis.selectorLabels" -}}
app.kubernetes.io/name: {{ include "qs-redis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "qs-redis.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "qs-redis.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Get Redis service name
*/}}
{{- define "qs-redis.redisHost" -}}
{{- .Release.Name }}
{{- end }}

{{/*
Get Redis port
*/}}
{{- define "qs-redis.redisPort" -}}
6379
{{- end }}

{{/*
Generate secret creation job
Params:
  .root - root context
*/}}
{{- define "qs-redis.secretCreationJob" -}}
{{- $root := . }}
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ include "qs-redis.fullname" $root }}-create-secrets
  labels:
    {{- include "qs-redis.labels" $root | nindent 4 }}
    app.kubernetes.io/component: create-secrets
  annotations:
    "helm.sh/hook": pre-install,pre-upgrade
    "helm.sh/hook-weight": "-5"
    "helm.sh/hook-delete-policy": before-hook-creation,hook-succeeded
spec:
  template:
    metadata:
      labels:
        {{- include "qs-redis.selectorLabels" $root | nindent 8 }}
        app.kubernetes.io/component: create-secrets
    spec:
      restartPolicy: Never
      serviceAccountName: {{ include "qs-redis.serviceAccountName" $root }}
      containers:
        - name: create-secrets
          image: "{{ $root.Values.jobImage.repository }}:{{ $root.Values.jobImage.tag }}"
          imagePullPolicy: {{ $root.Values.jobImage.pullPolicy }}
          command: ["/bin/bash", "/scripts/create-secrets.sh"]
          env:
            - name: REDIS_INSTANCE_NAME
              value: {{ $root.Release.Name | quote }}
            - name: REDIS_HOST
              value: {{ include "qs-redis.redisHost" $root | quote }}
            - name: REDIS_PORT
              value: {{ include "qs-redis.redisPort" $root | quote }}
            - name: MASTER_SECRET_NAME
              value: {{ $root.Values.redis.redisSecret.secretName | quote }}
            - name: APP_NAME
              value: {{ include "qs-redis.name" $root | quote }}
            - name: REDIS_APPLICATIONS
              value: "{{- range $index, $app := $root.Values.redisApplications }}{{- if $index }},{{- end }}{{ $app.name }}:{{ $app.database }}{{- end }}"
            - name: LOG_LEVEL
              value: {{ $root.Values.jobConfig.logLevel | quote }}
            - name: COLORED_OUTPUT
              value: {{ $root.Values.jobConfig.coloredOutput | quote }}
            - name: DRY_RUN
              value: {{ $root.Values.jobConfig.dryRun | quote }}
            - name: FAIL_ON_ERROR
              value: {{ $root.Values.jobConfig.failOnError | quote }}
          volumeMounts:
            - name: script
              mountPath: /scripts
          resources:
            requests:
              memory: "64Mi"
              cpu: "100m"
            limits:
              memory: "128Mi"
              cpu: "500m"
      volumes:
        - name: script
          configMap:
            name: {{ include "qs-redis.fullname" $root }}-secret-script
            defaultMode: 0755
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        fsGroup: 1001
{{- end }}

