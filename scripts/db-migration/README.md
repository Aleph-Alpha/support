# PostgreSQL Multi-Database Migration Utility

Automate backup and restore of multiple PostgreSQL databases using a YAML configuration. This utility is designed for Kubernetes environments and supports advanced features for reliability and security.

## Features

- Backup and restore multiple databases in one run
- YAML configuration for flexible source/destination mapping
- Comprehensive logging and error handling
- Pre-flight permission checks
- Dry-run mode for safe testing
- Colored output for clarity
- Retry logic and version validation
- Security options (password hiding, config backup)
- Automatic cleanup and retention policies

## Quick Start

### 1. Update Configuration

Edit the database passwords in the ConfigMap:

```sh
vim k8s/configmap-config.yaml
```

Update all `password: ""` fields with actual credentials for each database.

### 2. Deploy the Job

Apply the Kubernetes manifests using Kustomize:

```sh
kubectl apply -k k8s/
```

Or apply them individually:

```sh
kubectl apply -f k8s/configmap-script.yaml
kubectl apply -f k8s/configmap-config.yaml
kubectl apply -f k8s/job.yaml
```

### 3. Monitor the Job

Watch the job progress:

```sh
# Check job status
kubectl get job db-migration -n pharia-ai

# View logs in real-time
kubectl logs -f job/db-migration -n pharia-ai

# Get detailed job info
kubectl describe job db-migration -n pharia-ai
```

### 4. Cleanup

After successful migration:

```sh
# Delete the job (auto-deletes after 24 hours by default)
kubectl delete job db-migration -n pharia-ai

# Delete the ConfigMaps if no longer needed
kubectl delete configmap db-migration-script db-migration-config -n pharia-ai
```

## Directory Structure

```
db-migration/
├── k8s/                       # Kubernetes manifests
│   ├── configmap-config.yaml  # Database configuration (embedded)
│   ├── configmap-script.yaml  # Migration script (embedded)
│   ├── job.yaml               # Job definition
│   ├── kustomization.yaml     # Kustomize config
│   └── README.md              # Detailed k8s documentation
└── README.md                  # This file
```

**Note**: The migration script (`database_migrator.sh`) and configuration (`db_config.yaml`) are embedded directly in the ConfigMaps for simplified deployment.

## Configuration

The migration is configured via `k8s/configmap-config.yaml` which supports:

**Database Configuration:**
- Multiple source/destination database pairs
- Connection parameters (host, port, username, password, database)
- Per-database settings

**Migration Settings:**
- Dump and restore timeouts
- Retry attempts and delays
- PostgreSQL version requirements
- Dump options (format, compression, etc.)

**Security Options:**
- Hide passwords in logs
- Backup original config
- Secure credential handling

**Performance:**
- Compress dumps
- Verify checksums
- Cleanup old dumps (retention policy)

## Prerequisites

The migration job uses a pre-built container image (`ghcr.io/aleph-alpha/shared-images/pharia-helper:latest`) that includes:

- PostgreSQL 17.x client tools (`psql`, `pg_dump`)
- `yq` YAML processor
- `bash` shell

### For Airgapped Environments

See [k8s/README.md](k8s/README.md#for-airgapped-environments-without-internet-access) for instructions on:
- Preparing the helper container image
- Using internal container registries
- Verification checklist

## Job Configuration

The Kubernetes Job is configured with:

- **Timeout**: 2 hours (configurable)
- **Retries**: 2 attempts
- **Retention**: 24 hours after completion
- **Resources**: Configurable CPU/memory limits
- **Storage**: Ephemeral volumes for dumps and logs

## Pre-flight Checks

Before migration, the script verifies:

- ✅ Required PostgreSQL client version (17.x)
- ✅ Required tools available (`yq`, `bash`)
- ✅ Source database permissions (CONNECT, SELECT)
- ✅ Destination database permissions (CONNECT, CREATE)
- ✅ Network connectivity to databases
- ✅ Configuration validity

If any check fails, the script provides clear error messages and suggested fixes.

## Troubleshooting

### Job Failed

```sh
# Get pod name
kubectl get pods -n pharia-ai -l app=db-migration

# View logs
kubectl logs <pod-name> -n pharia-ai

# View logs from previous run (if restarted)
kubectl logs <pod-name> -n pharia-ai --previous
```

### Permission Issues

If permission checks fail, grant the required privileges:

**Source database (read permissions):**
```sql
GRANT CONNECT ON DATABASE <database_name> TO <username>;
GRANT USAGE ON SCHEMA public TO <username>;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO <username>;
```

**Destination database (write permissions):**
```sql
GRANT CONNECT ON DATABASE <database_name> TO <username>;
GRANT CREATE ON DATABASE <database_name> TO <username>;
GRANT ALL PRIVILEGES ON SCHEMA public TO <username>;
```

### Resource/Timeout Issues

For large databases, adjust settings in `k8s/job.yaml`:

```yaml
spec:
  activeDeadlineSeconds: 14400  # 4 hours
  template:
    spec:
      containers:
      - resources:
          limits:
            memory: "2Gi"
            cpu: "2000m"
```

And in `k8s/configmap-config.yaml`:

```yaml
config:
  timeouts:
    restore: 7200  # 2 hours
    dump: 7200     # 2 hours
```

## Advanced Usage

### Dry Run Mode

Test the migration without executing commands:

Edit `k8s/job.yaml` command:

```yaml
command:
- /bin/bash
- -c
- |
  ./database_migrator.sh --config db_config.yaml --dry-run --verbose
```

### Selective Migration

To migrate only specific databases, edit `k8s/configmap-config.yaml` and remove unwanted entries from the `databases` list.

### Custom Configuration

Customize the migration behavior by modifying `k8s/configmap-config.yaml`:

- Adjust timeouts for large databases
- Change dump options (compression, format, etc.)
- Modify retry behavior
- Update storage locations
- Configure security settings

## Documentation

For detailed information, see:

- [k8s/README.md](k8s/README.md) - Comprehensive Kubernetes deployment guide
- `k8s/configmap-script.yaml` - Migration script with inline documentation
- `k8s/configmap-config.yaml` - Configuration examples and options

## Security Considerations

1. **Credentials**: Consider using Kubernetes Secrets instead of ConfigMaps for sensitive data
2. **RBAC**: Use dedicated service accounts with minimal permissions
3. **Network Policies**: Ensure pod has network access to required databases only
4. **Audit**: Review logs for sensitive information before sharing

## References

- [Kubernetes Jobs](https://kubernetes.io/docs/concepts/workloads/controllers/job/)
- [ConfigMaps](https://kubernetes.io/docs/concepts/configuration/configmap/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/17/)
