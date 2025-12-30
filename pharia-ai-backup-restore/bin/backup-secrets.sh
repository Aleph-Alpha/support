#!/bin/bash

###############################################################################
# Kubernetes Secrets Backup Script
# Backs up Kubernetes secrets with specific prefixes
###############################################################################

set -e
set -o pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKUP_DIR="${PROJECT_ROOT}/secrets-backups"
TIMESTAMP=$(date +%Y-%m-%d_%H%M%S)
SECRETS_BACKUP_DIR="${BACKUP_DIR}/secrets_${TIMESTAMP}"

# Load common library
source "$SCRIPT_DIR/../lib/common.sh"

###############################################################################
# Backup Functions
###############################################################################

backup_secret() {
    local secret_name=$1
    local namespace=$2

    local backup_file="${SECRETS_BACKUP_DIR}/${secret_name}.yaml"

    echo "Backing up secret: $secret_name"

    # Get secret and save to file
    if kubectl get secret "$secret_name" -n "$namespace" -o yaml > "$backup_file" 2>&1; then
        # Remove managed fields and other dynamic metadata
        if command -v yq &> /dev/null; then
            yq eval 'del(.metadata.managedFields, .metadata.uid, .metadata.resourceVersion, .metadata.creationTimestamp, .metadata.selfLink, .metadata.ownerReferences)' -i "$backup_file"
            yq eval 'del(.metadata.labels."app.kubernetes.io/managed-by", .metadata.labels."secrets.hashicorp.com/vso-ownerRefUID")' -i "$backup_file"
        else
            echo -e "${YELLOW}WARNING: yq not found - backup may contain extra metadata${NC}"
        fi

        local file_size=$(du -h "$backup_file" | cut -f1)
        echo -e "${GREEN}SUCCESS: Backup completed for $secret_name (Size: $file_size)${NC}"
        echo "$backup_file" >> "${SECRETS_BACKUP_DIR}/.backup_success"
        return 0
    else
        echo -e "${RED}ERROR: Failed to backup secret: $secret_name${NC}"
        rm -f "$backup_file"
        return 1
    fi
}

get_secrets_by_prefix() {
    local prefix=$1
    local namespace=$2

    kubectl get secrets -n "$namespace" --no-headers -o custom-columns=":metadata.name" 2>/dev/null | grep "^${prefix}" || true
}

get_secret_type() {
    local secret_name=$1
    local namespace=$2

    kubectl get secret "$secret_name" -n "$namespace" -o jsonpath='{.type}' 2>/dev/null || echo ""
}

###############################################################################
# Usage/Help Functions
###############################################################################

show_usage() {
    cat << EOF
Kubernetes Secrets Backup Script

Usage: $0 [NAMESPACE]

Arguments:
    NAMESPACE           Kubernetes namespace to backup secrets from (default: pharia-ai)

This script backs up:
    1. All secrets starting with 'pharia-iam-' (type: Opaque)
    2. The secret 'pharia-oauth-gateway-secret'

Examples:
    # Backup secrets from default namespace (pharia-ai)
    $0

    # Backup secrets from specific namespace
    $0 production

EOF
}

###############################################################################
# Main Script
###############################################################################

main() {
    local namespace="${1:-pharia-ai}"

    # Show usage if help is requested
    if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        show_usage
        exit 0
    fi

    print_header "Kubernetes Secrets Backup Script"

    # Check for kubectl
    check_command "kubectl" "Please install kubectl." || exit 1

    # Check if we can access the cluster
    if ! kubectl cluster-info &> /dev/null; then
        echo -e "${RED}ERROR: Cannot connect to Kubernetes cluster. Please check your kubeconfig.${NC}"
        exit 1
    fi

    # Create directories
    mkdir -p "$BACKUP_DIR"
    mkdir -p "$SECRETS_BACKUP_DIR"

    echo "=========================================="
    echo "Starting secrets backup process"
    echo "Namespace: $namespace"
    echo "Backup directory: $SECRETS_BACKUP_DIR"
    echo "Timestamp: $TIMESTAMP"
    echo "=========================================="

    local success_count=0
    local failed_count=0

    # Backup secrets starting with "pharia-iam-" (type Opaque only)
    echo "Searching for secrets starting with 'pharia-iam-'..."

    local iam_secrets_array=()
    while IFS= read -r line; do
        if [ -n "$line" ]; then
            iam_secrets_array+=("$line")
        fi
    done < <(get_secrets_by_prefix "pharia-iam-" "$namespace")

    local iam_count=${#iam_secrets_array[@]}

    if [ $iam_count -gt 0 ]; then
        echo "Found $iam_count secret(s) starting with 'pharia-iam-'"

        for secret_name in "${iam_secrets_array[@]}"; do
            local secret_type=$(get_secret_type "$secret_name" "$namespace")

            if [ "$secret_type" == "Opaque" ]; then
                set +e
                backup_secret "$secret_name" "$namespace"
                local result=$?
                set -e

                if [ $result -eq 0 ]; then
                    success_count=$((success_count + 1))
                else
                    failed_count=$((failed_count + 1))
                fi
            else
                echo -e "${YELLOW}WARNING: Skipping $secret_name (type: $secret_type, expected: Opaque)${NC}"
            fi
        done
    else
        echo -e "${YELLOW}WARNING: No secrets found starting with 'pharia-iam-'${NC}"
    fi

    # Backup specific secret: pharia-oauth-gateway-secret
    echo "Searching for secret 'pharia-oauth-gateway-secret'..."
    if kubectl get secret "pharia-oauth-gateway-secret" -n "$namespace" &> /dev/null; then
        set +e
        backup_secret "pharia-oauth-gateway-secret" "$namespace"
        local result=$?
        set -e

        if [ $result -eq 0 ]; then
            success_count=$((success_count + 1))
        else
            failed_count=$((failed_count + 1))
        fi
    else
        echo -e "${YELLOW}WARNING: Secret 'pharia-oauth-gateway-secret' not found in namespace '$namespace'${NC}"
    fi

    # Print summary
    if print_summary "$success_count" "$failed_count" "Backup process"; then
        exit 0
    else
        exit 1
    fi
}

# Run main function
main "$@"
