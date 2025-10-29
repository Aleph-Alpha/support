{{/* vim: set filetype=mustache: */}}

{{/*
Get the qs-pgbouncer config file name.
*/}}
{{- define "qs-pgbouncer.configFile" -}}
{{- printf "%s-config-file" (include "qs-pgbouncer.fullname" .) | trunc 63 | trimSuffix "-" | quote -}}
{{- end -}}


{{/*

qs-pgbouncer.ini is a configuration file used to specify qs-pgbouncer parameters and identify user-specific parameters.
It can contain include directives to split the file into separate parts.

For further information, refer to https://www.qs-pgbouncer.org/config.html

*/}}

{{ define "qs-pgbouncer.ini" }}

{{/* [databases] section */}}
{{- if $.Values.databases }}
  {{ printf "[databases]" }}
  {{- range $key, $value := .Values.databases }}
    {{ $key }} ={{ range $k, $v := $value }} {{ $k }}={{ $v }}{{ end }}
  {{- end }}
{{- end }}

{{/* [qs-pgbouncer] section */}}
{{- if $.Values.pgbouncer }}
  {{ printf "[pgbouncer]" }}
  {{- range $k, $v := $.Values.pgbouncer }}
    {{ $k }} = {{ $v }}
  {{- end }}
{{- end }}

{{/* [users] section */}}
{{- if $.Values.users }}
  {{ printf "[users]" }}
  {{- range $k, $v := $.Values.users }}
    {{ $k }} = {{ $v }}
  {{- end }}
{{- end }}

{{/* include is a special configuration within [pgbouncer] section */}}
{{- if $.Values.include }}
  {{ printf "%s %s" "%include" $.Values.include }}
{{- end }}

{{ end }}


{{/*
The userlist.txt file in qs-pgbouncer contains the database users and their passwords,
used to authenticate the client agains PostgreSQL.

For further information, check https://www.qs-pgbouncer.org/config.html#authentication-file-format
*/}}
{{- define "qs-pgbouncer.userlist.secret" -}}
{{- default (printf "%s-qs-pgbouncer-userlist-secret" .Release.Name) .Values.userlist.secret | quote -}}
{{- end -}}
