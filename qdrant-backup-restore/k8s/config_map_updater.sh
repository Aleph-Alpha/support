#!/usr/bin/env bash

set -euo pipefail

populate_config_map_with_script() {
    local template_path="$1"
    local script_path="$2"
    # Declaration split from assignment (SC2155): combined, a failing cat
    # would be masked under set -euo pipefail.
    local script_content
    script_content=$(cat "$script_path")

    # Byte-exact round-trip: store the source's trailing-newline count MINUS
    # ONE (floored at 0) — `yq eval` prints stored+1, so the standard
    # `diff <(yq eval ...) source` sync check then comes back clean. Computed
    # here, before --git-ref substitution changes the string length.
    local full_len stripped_len trailing_nl newlines_to_add=0 nl_i
    full_len=$(wc -c < "$script_path")
    stripped_len=$(printf '%s' "$script_content" | wc -c)
    trailing_nl=$((full_len - stripped_len))
    if [ "$trailing_nl" -gt 1 ]; then
        newlines_to_add=$((trailing_nl - 1))
    fi

    local script_name=""
    script_name="${script_path##*/}"
    local custom_script_name="${3:-$script_name}"
    # --git-ref bakes the sha into the CONFIGMAP COPY's GIT_REF default only
    # (disk untouched; a runtime GIT_REF env still wins). Hard-fails below if
    # the expected declaration is missing.
    if [ -n "${GIT_REF_OVERRIDE:-}" ]; then
        local default_decl='GIT_REF="${GIT_REF:-unknown}"'
        local baked_decl='GIT_REF="${GIT_REF:-'"$GIT_REF_OVERRIDE"'}"'
        case "$script_content" in
            *"$default_decl"*)
                script_content="${script_content/"$default_decl"/"$baked_decl"}"
                ;;
            *)
                # explicit --git-ref must never silently ship provenance-less
                printf 'ERROR: --git-ref given but %s does not contain %s — refusing to ship a provenance-less ConfigMap\n' \
                    "$script_path" "$default_decl" >&2
                exit 1
                ;;
        esac
    fi

    for ((nl_i = 0; nl_i < newlines_to_add; nl_i++)); do
        script_content+=$'\n'
    done
    # Content goes to yq via FILE (load_str), never env: Linux caps one env
    # string at 128 KiB and the script outgrew it. load_str is byte-exact.
    local content_file
    content_file=$(mktemp) || exit 1
    printf '%s' "$script_content" > "$content_file"
    export content_file
    export custom_script_name
    yq -i '.data.[(strenv(custom_script_name))] = load_str(strenv(content_file))' "$template_path"
    rm -f "$content_file"
}

# Dependency checks
check_dependencies() {
    local missing_deps=()

    for cmd in yq; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
            missing_deps+=("${cmd}")
        fi
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        # Plain printf: this standalone script has no _printf helper.
        printf 'Missing required dependencies: %s. Please install them and try again.\n' "${missing_deps[*]}" >&2
        exit 1
    fi
}

usage() {
    cat <<EOF
Usage: $0 <yaml_file_path> <source_script_path> [custom_script_name] [--git-ref <sha>]

Positional arguments:
  yaml_file_path                  Path to the yaml template to update.
  source_script_path              Path to the script to update.

Optional positional argument:
  custom_script_name

Optional arguments:
  --git-ref <sha>                 Bake <sha> into the ConfigMap copy's
                                   GIT_REF default only; source_script_path
                                   on disk is left untouched. Omit for
                                   today's behavior (default stays
                                   "unknown"). Backward compatible: existing
                                   invocations without this flag are
                                   unaffected.

Examples:
  $0 k8s/configmap-script.yaml qdrant_backup_recovery.sh
  $0 k8s/configmap-script.yaml qdrant_backup_recovery.sh custom_name.sh
  $0 k8s/configmap-script.yaml qdrant_backup_recovery.sh --git-ref abc1234
EOF

}

run() {
    check_dependencies

    local GIT_REF_OVERRIDE=""
    local args=()
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --git-ref)
                if [ "$#" -lt 2 ] || [ -z "${2:-}" ]; then
                    printf -- '%s requires a non-empty value\n' "$1"
                    usage
                    exit 1
                fi
                # Reject a dash-leading value: `--git-ref --help` would otherwise
                # silently bake the literal string "--help" in as the ref.
                case "$2" in
                    -*)
                        printf -- '--git-ref requires a value, got %s\n' "$2"
                        usage
                        exit 1
                        ;;
                esac
                GIT_REF_OVERRIDE="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                # Reject unknown dash-options — a typo'd flag must never
                # become the ConfigMap key.
                printf -- 'unknown option: %s\n' "$1"
                usage
                exit 1
                ;;
            *)
                args+=("$1")
                shift
                ;;
        esac
    done

    if [ "${#args[@]}" -lt 2 ]; then
        usage
        exit 1
    fi

    populate_config_map_with_script "${args[@]}"
}

run "$@"
