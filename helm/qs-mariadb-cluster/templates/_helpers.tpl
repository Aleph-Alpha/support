{{/*
Expand the name of the chart.
*/}}
{{- define "qs-mariadb-cluster.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "qs-mariadb-cluster.fullname" -}}
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
{{- define "qs-mariadb-cluster.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "qs-mariadb-cluster.labels" -}}
helm.sh/chart: {{ include "qs-mariadb-cluster.chart" . }}
{{ include "qs-mariadb-cluster.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "qs-mariadb-cluster.selectorLabels" -}}
app.kubernetes.io/name: {{ include "qs-mariadb-cluster.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "qs-mariadb-cluster.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "qs-mariadb-cluster.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the role to use or create
*/}}
{{- define "qs-mariadb-cluster.roleName" -}}
{{- if .Values.rbac.roleName }}
{{- .Values.rbac.roleName }}
{{- else }}
{{- printf "%s-secret-creator" (include "qs-mariadb-cluster.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Generate secret creation job
Params:
  .root - root context
*/}}
{{- define "qs-mariadb-cluster.secretCreationJob" -}}
{{- $root := .root }}
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ include "qs-mariadb-cluster.fullname" $root }}-create-secrets
  labels:
    {{- include "qs-mariadb-cluster.labels" $root | nindent 4 }}
    app.kubernetes.io/component: create-secrets
  annotations:
    "helm.sh/hook": pre-install,pre-upgrade
    "helm.sh/hook-weight": "-10"
    "helm.sh/hook-delete-policy": before-hook-creation,hook-succeeded
spec:
  template:
    metadata:
      labels:
        {{- include "qs-mariadb-cluster.selectorLabels" $root | nindent 8 }}
        app.kubernetes.io/component: create-secrets
    spec:
      restartPolicy: Never
      serviceAccountName: {{ include "qs-mariadb-cluster.serviceAccountName" $root }}
      containers:
        - name: create-secrets
          image: "{{ $root.Values.jobImage.repository }}:{{ $root.Values.jobImage.tag }}"
          imagePullPolicy: {{ $root.Values.jobImage.pullPolicy }}
          command: ["/bin/bash", "/scripts/create-secrets.sh"]
          env:
            - name: CLUSTER_FULLNAME
              value: {{ include "qs-mariadb-cluster.fullname" $root | quote }}
            - name: CLUSTER_HOST
              value: {{ include "qs-mariadb-cluster.fullname" $root | quote }}
            - name: APP_NAME
              value: {{ include "qs-mariadb-cluster.name" $root | quote }}
            {{- $mariadbCluster := index $root.Values "mariadb-cluster" }}
            - name: MARIADB_USERS
              value: "{{- range $index, $user := $mariadbCluster.users }}{{- if $index }},{{- end }}{{ $user.name }}{{- end }}"
            - name: MARIADB_DATABASES
              value: "{{- range $index, $db := $mariadbCluster.databases }}{{- if $index }},{{- end }}{{ $db.name }}{{- end }}"
            - name: LOG_LEVEL
              value: {{ $root.Values.jobConfig.logLevel | quote }}
            - name: COLORED_OUTPUT
              value: {{ $root.Values.jobConfig.coloredOutput | quote }}
            - name: DRY_RUN
              value: {{ $root.Values.jobConfig.dryRun | quote }}
            - name: FAIL_ON_ERROR
              value: {{ $root.Values.jobConfig.failOnError | quote }}
            {{- if $root.Values.rootPasswordSecret }}
            - name: CREATE_ROOT_PASSWORD_SECRET
              value: {{ $root.Values.rootPasswordSecret.create | quote }}
            - name: ROOT_PASSWORD_SECRET_NAME
              value: {{ $root.Values.rootPasswordSecret.name | quote }}
            - name: ROOT_PASSWORD_SECRET_KEY
              value: {{ $root.Values.rootPasswordSecret.key | quote }}
            {{- end }}
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
            name: {{ include "qs-mariadb-cluster.fullname" $root }}-secret-script
            defaultMode: 0755
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        fsGroup: 1001
{{- end }}

