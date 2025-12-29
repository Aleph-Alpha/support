#!/bin/bash

###############################################################################
# Kubernetes Secrets Restore Script
# Restores Kubernetes secrets from backups
###############################################################################

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKUP_DIR="${PROJECT_ROOT}/secrets-backups"
TIMESTAMP=$(date +%Y-%m-%d_%H%M%S)

# Load common library
source "$SCRIPT_DIR/../lib/common.sh"

###############################################################################
# Restore Functions
###############################################################################

find_latest_backup() {
    # Find the most recent secrets backup directory
    local latest=$(ls -td "${BACKUP_DIR}"/secrets_* 2>/dev/null | grep -v '\.tar\.gz$' | head -1)
    
    if [ -z "$latest" ] || [ ! -d "$latest" ]; then
        return 1
    fi
    
    echo "$latest"
    return 0
}

list_backups() {
    echo ""
    echo "Available secret backups:"
    echo "----------------------------------------"
    
    local backups=$(ls -td "${BACKUP_DIR}"/secrets_* 2>/dev/null | grep -v '\.tar\.gz$')
    
    if [ -z "$backups" ]; then
        echo "No secret backups found"
        return 1
    fi
    
    local count=1
    while IFS= read -r backup; do
        if [ ! -d "$backup" ]; then
            continue
        fi
        
        local size=$(du -sh "$backup" | cut -f1)
        local date=$(echo "$backup" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{6}')
        local secret_count=$(find "$backup" -name "*.yaml" -type f | wc -l | tr -d ' ')
        
        echo "$count) $(basename "$backup") (Size: $size, Date: $date, Secrets: $secret_count)"
        
        # Show first few secrets
        echo "   Secrets:"
        find "$backup" -name "*.yaml" -type f -exec basename {} .yaml \; | head -5 | sed 's/^/     - /'
        if [ "$secret_count" -gt 5 ]; then
            echo "     ... and $((secret_count - 5)) more"
        fi
        echo ""
        count=$((count + 1))
    done <<< "$backups"
    
    return 0
}

restore_secret() {
    local secret_file=$1
    local namespace=$2
    local force=$3
    
    local secret_name=$(basename "$secret_file" .yaml)
    
    echo "Restoring secret: $secret_name"
    
    # Check if secret already exists
    if kubectl get secret "$secret_name" -n "$namespace" &> /dev/null; then
        if [ "$force" == "true" ]; then
            echo -e "${YELLOW}WARNING: Secret $secret_name already exists, deleting...${NC}"
            if ! kubectl delete secret "$secret_name" -n "$namespace" 2>&1; then
                echo -e "${RED}ERROR: Failed to delete existing secret: $secret_name${NC}"
                return 1
            fi
        else
            echo -e "${YELLOW}WARNING: Secret $secret_name already exists, skipping (use --force to overwrite)${NC}"
            return 2
        fi
    fi
    
    # Apply the secret
    if kubectl apply -f "$secret_file" -n "$namespace" > /dev/null 2>&1; then
        echo -e "${GREEN}SUCCESS: Secret restored: $secret_name${NC}"
        return 0
    else
        echo -e "${RED}ERROR: Failed to restore secret: $secret_name${NC}"
        return 1
    fi
}

restore_from_directory() {
    local backup_dir=$1
    local namespace=$2
    local force=$3
    
    echo "Restoring from directory: $(basename "$backup_dir")"
    
    # Check if directory exists
    if [ ! -d "$backup_dir" ]; then
        echo -e "${RED}ERROR: Backup directory not found: $backup_dir${NC}"
        return 1
    fi
    
    # Restore all secrets
    local success_count=0
    local failed_count=0
    local skipped_count=0
    
    for secret_file in "$backup_dir"/*.yaml; do
        if [ ! -f "$secret_file" ]; then
            continue
        fi
        
        # Skip hidden files
        local filename=$(basename "$secret_file")
        if [[ "$filename" == .* ]]; then
            continue
        fi
        
        restore_secret "$secret_file" "$namespace" "$force"
        local result=$?
        
        case $result in
            0) success_count=$((success_count + 1)) ;;
            1) failed_count=$((failed_count + 1)) ;;
            2) skipped_count=$((skipped_count + 1)) ;;
        esac
    done
    
    echo ""
    echo "Restore summary: $success_count restored, $skipped_count skipped, $failed_count failed"
    
    [ $failed_count -eq 0 ]
    return $?
}

###############################################################################
# Usage/Help Functions
###############################################################################

show_usage() {
    cat << EOF
Kubernetes Secrets Restore Script

Usage: $0 [OPTIONS] [BACKUP_DIR]

Options:
    -h, --help              Show this help message
    -n, --namespace NAME    Kubernetes namespace (default: pharia-ai)
    -f, --force             Force overwrite existing secrets
    -l, --list              List available backup directories
    --latest                Use the latest backup directory

Arguments:
    BACKUP_DIR             Path to backup directory to restore

Examples:
    # List available backups
    $0 -l

    # Restore from latest backup
    $0 --latest

    # Restore from specific backup directory
    $0 secrets-backups/secrets_2025-12-21_173419

    # Restore to specific namespace with force overwrite
    $0 -n production -f secrets-backups/secrets_2025-12-21_173419

    # Restore from latest backup to production namespace
    $0 --latest -n production

EOF
}

###############################################################################
# Main Script
###############################################################################

main() {
    local backup_dir=""
    local namespace="pharia-ai"
    local force="false"
    local list_mode=false
    local use_latest=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -n|--namespace)
                namespace="$2"
                shift 2
                ;;
            -f|--force)
                force="true"
                shift
                ;;
            -l|--list)
                list_mode=true
                shift
                ;;
            --latest)
                use_latest=true
                shift
                ;;
            -*)
                echo "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                backup_dir="$1"
                shift
                ;;
        esac
    done
    
    print_header "Kubernetes Secrets Restore Script"
    
    # Check for kubectl
    check_command "kubectl" "Please install kubectl." || exit 1
    
    # Check if we can access the cluster
    if ! kubectl cluster-info &> /dev/null; then
        echo -e "${RED}ERROR: Cannot connect to Kubernetes cluster. Please check your kubeconfig.${NC}"
        exit 1
    fi
    
    # Handle list mode
    if [ "$list_mode" == true ]; then
        list_backups
        exit $?
    fi
    
    # Determine backup directory
    if [ "$use_latest" == true ]; then
        backup_dir=$(find_latest_backup)
        if [ $? -ne 0 ]; then
            echo -e "${RED}ERROR: No backup directories found${NC}"
            exit 1
        fi
        echo "Using latest backup: $(basename "$backup_dir")"
    fi
    
    # Check if backup directory is specified
    if [ -z "$backup_dir" ]; then
        echo "ERROR: Please specify a backup directory or use --latest"
        echo ""
        show_usage
        exit 1
    fi
    
    # Check if backup directory exists
    if [ ! -d "$backup_dir" ]; then
        echo -e "${RED}ERROR: Backup directory not found: $backup_dir${NC}"
        exit 1
    fi
    
    echo "=========================================="
    echo "Starting secrets restore process"
    echo "Backup directory: $(basename "$backup_dir")"
    echo "Namespace: $namespace"
    echo "Force overwrite: $force"
    echo "Timestamp: $TIMESTAMP"
    echo "=========================================="
    
    # Restore from directory
    if restore_from_directory "$backup_dir" "$namespace" "$force"; then
        echo -e "${GREEN}SUCCESS: Restore completed successfully!${NC}"
        exit 0
    else
        echo -e "${RED}ERROR: Restore completed with errors${NC}"
        exit 1
    fi
}

# Run main function
main "$@"

