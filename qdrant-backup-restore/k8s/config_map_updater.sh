#!/usr/bin/env bash

set -euo pipefail

populate_config_map_with_script() {
    local template_path="$1"
    local script_path="$2"
    # Declaration and assignment split deliberately (ShellCheck SC2155): a combined
    # `local script_content=$(cat "$script_path")` can mask cat's exit status under
    # `set -euo pipefail` — empirically confirmed (an unreadable source silently produced
    # an empty payload instead of aborting). Split, the failing command substitution
    # correctly triggers errexit.
    local script_content
    script_content=$(cat "$script_path")

    # Byte-exact round-trip (F4) — computed HERE, from the pristine post-read content, before
    # any --git-ref substitution below touches script_content: substitution changes the
    # string's length (e.g. "unknown" -> a 40-char sha), which would corrupt this byte-length
    # arithmetic if done afterward. Trailing newlines never appear mid-file, so it is safe to
    # compute the amount now and apply it at the very end, after substitution.
    #
    # `$(cat …)` above strips EVERY trailing newline from script_content — bash
    # command-substitution behavior, unrelated to cat — regardless of how many the source file
    # actually ends in. The natural sync check
    # (`diff <(yq eval '.data[key]' configmap.yaml) source_script`, k8s/README's "Updating the
    # ConfigMap") uses `yq eval` to extract the stored value for comparison, and `yq eval`
    # itself unconditionally appends exactly one more trailing newline whenever it PRINTS a
    # scalar — verified empirically across stored values with 0, 1, and 2 trailing newlines
    # (yq's WRITER stores whatever it is given faithfully, confirmed independently by decoding
    # with a second, independent YAML parser; it is only `yq eval`'s PRINT path that always
    # shows stored+1). So for that sync check to come back clean, the STORED value must carry
    # exactly one FEWER trailing newline than the source file actually has — never a flat "+1"
    # regardless of count (that produced the pre-existing one-line drift this replaces: correct
    # only for a 2-trailing-newline source, wrong for the common 1-trailing-newline case) and
    # never a flat "+0" (wrong whenever the source ends in more than one newline). Reconstruct
    # the source's real trailing-newline count via a byte-length difference (exact regardless
    # of count, unlike parsing) and store count-1, floored at 0. A source with ZERO trailing
    # newlines is the one case this cannot make byte-exact via this check — `yq eval` always
    # shows at least one — and is left as a documented, inherent limitation of that extraction
    # tool rather than something to work around here.
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
    # Optional --git-ref (see usage()/run()): bake the given sha into the
    # CONFIGMAP COPY's GIT_REF default only — script_path on disk is never
    # written to. GIT_REF still yields to an actual GIT_REF env var at
    # runtime if one is ever set (that part of the expression is untouched);
    # this only replaces what it falls back to when unset. Literal
    # (non-glob) match: neither string contains a shell glob metacharacter.
    # No-op (with a warning) if the expected declaration text isn't found
    # verbatim, so a future rename of the variable fails loudly instead of
    # silently baking nothing in.
    if [ -n "${GIT_REF_OVERRIDE:-}" ]; then
        local default_decl='GIT_REF="${GIT_REF:-unknown}"'
        local baked_decl='GIT_REF="${GIT_REF:-'"$GIT_REF_OVERRIDE"'}"'
        case "$script_content" in
            *"$default_decl"*)
                script_content="${script_content/"$default_decl"/"$baked_decl"}"
                ;;
            *)
                printf 'WARNING: --git-ref given but %s does not contain %s — ConfigMap copy left unmodified for GIT_REF\n' \
                    "$script_path" "$default_decl" >&2
                ;;
        esac
    fi

    for ((nl_i = 0; nl_i < newlines_to_add; nl_i++)); do
        script_content+=$'\n'
    done
    export script_content
    export custom_script_name
    yq -i '.data.[(strenv(custom_script_name))] = strenv(script_content)' "$template_path"
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
        # Plain printf, not _printf: this is a standalone script (unlike
        # qdrant_backup_recovery.sh) and never defines that helper — the call
        # used to fail with "command not found" (rc 127) instead of showing
        # this message at all.
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
                # Reject unknown dash-options instead of silently absorbing them
                # as a positional (a typo'd flag, e.g. --gitref, would otherwise
                # become custom_script_name and write the ConfigMap under a key
                # no manifest mounts — a broken deploy from a typo, no error).
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
