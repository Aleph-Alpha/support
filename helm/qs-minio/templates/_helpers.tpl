{{/*
Expand the name of the chart.
*/}}
{{- define "qs-minio.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "qs-minio.fullname" -}}
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
{{- define "qs-minio.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "qs-minio.labels" -}}
helm.sh/chart: {{ include "qs-minio.chart" . }}
{{ include "qs-minio.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "qs-minio.selectorLabels" -}}
app.kubernetes.io/name: {{ include "qs-minio.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "qs-minio.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "qs-minio.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Generate secret creation job for MinIO instances
Params:
  .root - root context
  .instanceName - name of the MinIO instance (pharia-data, pharia-finetuning)
  .instanceConfig - MinIO instance configuration from values
*/}}
{{- define "qs-minio.secretCreationJob" -}}
{{- $root := .root }}
{{- $instanceName := .instanceName }}
{{- $instanceConfig := .instanceConfig }}
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ include "qs-minio.fullname" $root }}-create-secrets-{{ $instanceName }}
  labels:
    {{- include "qs-minio.labels" $root | nindent 4 }}
    app.kubernetes.io/component: create-secrets-{{ $instanceName }}
  annotations:
    "helm.sh/hook": pre-install,pre-upgrade
    "helm.sh/hook-weight": "-5"
    "helm.sh/hook-delete-policy": before-hook-creation,hook-succeeded
spec:
  template:
    metadata:
      labels:
        {{- include "qs-minio.selectorLabels" $root | nindent 8 }}
        app.kubernetes.io/component: create-secrets-{{ $instanceName }}
    spec:
      restartPolicy: Never
      serviceAccountName: {{ include "qs-minio.serviceAccountName" $root }}
      containers:
        - name: create-secrets
          image: "{{ $root.Values.jobImage.repository }}:{{ $root.Values.jobImage.tag }}"
          imagePullPolicy: {{ $root.Values.jobImage.pullPolicy }}
          command: ["/bin/bash", "/scripts/create-secrets.sh"]
          env:
            - name: INSTANCE_NAME
              value: "{{ $instanceName }}"
            - name: MINIO_FULLNAME
              value: "{{ $instanceConfig.fullnameOverride }}"
            - name: MINIO_HOST
              value: "{{ $instanceConfig.fullnameOverride }}.{{ $root.Release.Namespace }}.svc.cluster.local"
            - name: MINIO_PROTOCOL
              value: "{{ $root.Values.minio.protocol | default "http" }}"
            - name: MINIO_PORT
              value: "{{ $root.Values.minio.port | default "9000" }}"
            - name: MINIO_USER
              value: "{{ $instanceConfig.auth.user }}"
            - name: EXISTING_SECRET_NAME
              value: "{{ $instanceConfig.auth.existingSecret }}"
            - name: USER_KEY
              value: "{{ $instanceConfig.auth.existingSecretUserKey }}"
            - name: PASSWORD_KEY
              value: "{{ $instanceConfig.auth.existingSecretPasswordKey }}"
            - name: DEFAULT_BUCKETS
              value: "{{ $instanceConfig.defaultBuckets | default "" }}"
            - name: APP_NAME
              value: {{ include "qs-minio.name" $root | quote }}
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
            name: {{ include "qs-minio.fullname" $root }}-secret-script
            defaultMode: 0755
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        fsGroup: 1001
{{- end }}

