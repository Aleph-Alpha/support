{{/*
Expand the name of the chart.
*/}}
{{- define "qs-postgresql-cluster.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "qs-postgresql-cluster.fullname" -}}
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
{{- define "qs-postgresql-cluster.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "qs-postgresql-cluster.labels" -}}
helm.sh/chart: {{ include "qs-postgresql-cluster.chart" . }}
{{ include "qs-postgresql-cluster.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "qs-postgresql-cluster.selectorLabels" -}}
app.kubernetes.io/name: {{ include "qs-postgresql-cluster.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "qs-postgresql-cluster.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "qs-postgresql-cluster.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Generate secret creation job
Params:
  .root - root context
  .clusterName - name of the cluster (pharia, temporal)
  .clusterConfig - cluster configuration from values
*/}}
{{- define "qs-postgresql-cluster.secretCreationJob" -}}
{{- $root := .root }}
{{- $clusterName := .clusterName }}
{{- $clusterConfig := .clusterConfig }}
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ include "qs-postgresql-cluster.fullname" $root }}-create-secrets-{{ $clusterName }}
  labels:
    {{- include "qs-postgresql-cluster.labels" $root | nindent 4 }}
    app.kubernetes.io/component: create-secrets-{{ $clusterName }}
  annotations:
    "helm.sh/hook": pre-install,pre-upgrade
    "helm.sh/hook-weight": "-5"
    "helm.sh/hook-delete-policy": before-hook-creation,hook-succeeded
spec:
  template:
    metadata:
      labels:
        {{- include "qs-postgresql-cluster.selectorLabels" $root | nindent 8 }}
        app.kubernetes.io/component: create-secrets-{{ $clusterName }}
    spec:
      restartPolicy: Never
      serviceAccountName: {{ include "qs-postgresql-cluster.serviceAccountName" $root }}
      containers:
        - name: create-secrets
          image: "{{ $root.Values.jobImage.repository }}:{{ $root.Values.jobImage.tag }}"
          imagePullPolicy: {{ $root.Values.jobImage.pullPolicy }}
          command: ["/bin/bash", "/scripts/create-secrets.sh"]
          env:
            - name: CLUSTER_NAME
              value: "{{ $clusterName }}"
            - name: CLUSTER_FULLNAME
              value: "{{ $clusterConfig.fullnameOverride }}"
            - name: CLUSTER_HOST
              value: "{{ $clusterConfig.fullnameOverride }}-rw"
            - name: PGBOUNCER_HOST
              value: "{{ $clusterConfig.pgbouncerHost }}"
            {{- if $clusterConfig.poolers }}
            {{- range $clusterConfig.poolers }}
            {{- if eq .poolMode "transaction" }}
            - name: POOLER_TRANSACTION_HOST
              value: "{{ $clusterConfig.fullnameOverride }}-pooler-{{ .name }}"
            {{- end }}
            {{- if eq .poolMode "session" }}
            - name: POOLER_SESSION_HOST
              value: "{{ $clusterConfig.fullnameOverride }}-pooler-{{ .name }}"
            {{- end }}
            {{- end }}
            {{- end }}
            - name: APP_NAME
              value: {{ include "qs-postgresql-cluster.name" $root | quote }}
            - name: PG_ROLES
              value: "{{- range $index, $role := $clusterConfig.cluster.roles }}{{- if $index }},{{- end }}{{ $role.name }}{{- end }}"
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
            name: {{ include "qs-postgresql-cluster.fullname" $root }}-secret-script
            defaultMode: 0755
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        fsGroup: 1001
{{- end }}
