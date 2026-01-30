#!/usr/bin/env bash

set -euo pipefail

populate_config_map_with_script() {
    local template_path="$1"
    local script_path="$2"
    local script_content=""
    local script_content=$(cat "$script_path")
    export script_content
    local script_name=""
    script_name="${script_path##*/}"
    local custom_script_name="${3:-$script_name}"
    export custom_script_name
    yq -i '.data.[(strenv(custom_script_name))] = (strenv(script_content) + "\n")' "$template_path"
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
        _printf "Missing required dependencies: %s. Please install them and try again.\n" "${missing_deps[*]}"
        exit 1
    fi
}

usage() {
    cat <<EOF
Usage: $0 <yaml_file_path> <source_script_path> [custom_script_name]

Positional arguments:
  yaml_file_path                  Path to the yaml template to update.
  source_script_path              Path to the script to update.

Optional postional argument:
  custom_script_name

Examples:
  $0 config_map_updater.sh k8s/configmap-script.yaml qdrant_backup_recovery.sh
  $0 config_map_updater.sh k8s/configmap-script.yaml qdrant_backup_recovery.sh custom_name.sh
EOF

}

run() {
    check_dependencies

    if [ "$#" -lt 2 ]; then
        usage
        exit 1
    fi

    populate_config_map_with_script "$@"
}

run "$@"
