{{/* vim: set filetype=mustache: */}}

{{/*
Get the pgbouncer config file name.
*/}}
{{- define "pgbouncer.configFile" -}}
{{- printf "%s-config-file" (include "pgbouncer.fullname" .) | trunc 63 | trimSuffix "-" | quote -}}
{{- end -}}


{{/*

pgbouncer.ini is a configuration file used to specify pgbouncer parameters and identify user-specific parameters.
It can contain include directives to split the file into separate parts.

For further information, refer to https://www.pgbouncer.org/config.html

*/}}

{{ define "pgbouncer.ini" }}
{{/* [databases] section */}}
{{- if $.Values.databases }}
  {{ printf "[databases]" }}
  {{- range $key, $value := .Values.databases }}
    {{ $key }} ={{ range $k, $v := $value }} {{ $k }}={{ $v }}{{ end }}
  {{- end }}
{{- end }}

{{/* [pgbouncer] section */}}
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
The userlist.txt file in pgbouncer contains the database users and their passwords,
used to authenticate the client agains PostgreSQL.

For further information, check https://www.pgbouncer.org/config.html#authentication-file-format
*/}}
{{- define "pgbouncer.userlist.secret" -}}
{{- default (printf "%s-pgbouncer-userlist-secret" .Release.Name) .Values.userlist.secret | quote -}}
{{- end -}}
