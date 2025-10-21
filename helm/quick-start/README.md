# Pharia AI External Dependencies

A Helm chart that provides external dependencies required for the Pharia AI platform, including PostgreSQL clusters, Redis, and MinIO.

## Overview

This chart deploys the following components:

- **Automatic Secret Creation**: A Kubernetes Job that runs before installation to create all required secrets
- **CloudNative-PG operator**: Operator for creating postgres clusters, databases and roles
- **PostgreSQL Clusters**: Two CloudNative-PG clusters for application and temporal data
- **Redis**: Multiple Redis instances for caching and session storage
- **MinIO**: Object storage for data and finetuning artifacts

## Secret Management

This chart includes an automatic secret creation job. The job:

- **Creates all required secrets**: PostgreSQL, Redis, and MinIO secrets with randomly generated passwords
- **Persists secrets**: Created secrets are kept when the Helm chart is uninstalled
- **Uses proper RBAC**: Runs with a dedicated ServiceAccount with minimal required permissions

The job creates the following secrets:
- PostgreSQL secrets for all database users
- Redis secrets for caching services
- MinIO secrets for object storage

## Database Selection

This chart supports selective database installation. You can enable/disable specific databases by setting the `enabled` field in the `postgresql.databases` configuration.

### Available Databases

**Main Application Databases:**
- `document-index` - Document indexing and search database
- `pharia-os` - Pharia OS core database  
- `inference-api` - Inference API database
- `pharia-studio` - Pharia Studio database
- `pharia-oauth-gateway` - OAuth Gateway database
- `pharia-assistant` - Pharia Assistant database
- `pharia-chat` - Pharia Chat database
- `pharia-catch` - Pharia Catch database
- `zitadel` - Zitadel identity management database
- `openfga` - OpenFGA authorization database
- `dex` - Dex identity provider database
- `pharia-conductor` - Pharia Conductor database
- `pharia-numinous` - Pharia Numinous database
- `pharia-transcribe-app` - Pharia Transcribe App database
- `pharia-data` - Pharia Data database

**Temporal Databases:**
- `temporal` - Temporal workflow database
- `temporal-visibility` - Temporal visibility database

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- `kubectl` configured to access your cluster

## Installation


### 1. Install the Chart

```bash
# Update dependencies
helm dependency update

# Install the chart
helm upgrade --install quick-start . --namespace your-namespace
```

#### Selective Installation Examples

**Install only Temporal databases:**
```bash
helm upgrade --install my-release ./quick-start -f values-examples/temporal-only.yaml
```

**Custom configuration:**
```bash
# Create your own values file
cat > my-values.yaml << EOF
postgresql:
  databases:
    - name: "temporal"
      enabled: true
    - name: "temporal-visibility"
      enabled: true
    # All other databases disabled by default
EOF

# Install with custom values
helm upgrade --install my-release ./quick-start -f my-values.yaml
```

### 3. Verify Installation

```bash
# Check PostgreSQL clusters
kubectl get clusters

# Check databases
kubectl get databases

# Check other services
kubectl get pods
```

## Configuration

Key configuration options in `values.yaml`:

```yaml
# Enable/disable components
cloudnative:
  enabled: true

postgresql:
  enabled: true
  clusters: [...]
  databases: [...]

pharia-assistant-api-redis:
  enabled: true

pharia-transcribe-app-redis:
  enabled: true

pharia-data-api-minio:
  enabled: true

```

## PostgreSQL Configuration

The chart by default creates two PostgreSQL clusters:

### Main Cluster (`pharia-ai-pg-cluster`)
- **Instances**: 3 replicas
- **Storage**: 200Gi premium storage
- **Databases**: 16 application databases
- **Users**: 16 application users

### Temporal Cluster (`temporal-cluster`)
- **Instances**: 3 replicas  
- **Storage**: 100Gi premium storage
- **Databases**: 2 temporal databases
- **Users**: 2 temporal users

## Secret Management

All secrets are created with the following fields:

### PostgreSQL Secrets
- `username`: Database username
- `user`: Same as username (for compatibility)
- `password`: Generated password
- `host`: Database host
- `port`: Database port (5432)
- `protocol`: Connection protocol (postgres)
- `uri`: Complete PostgreSQL connection URI
- `database`: Database name

### Other Secrets
- **Redis**: `username`, `password`
- **RabbitMQ**: `rabbitmq-username`, `rabbitmq-password`
- **MinIO**: `username`, `password`, `bucket-name`

## Scripts

### `scripts/create-secrets.sh`
Creates all required Kubernetes secrets with proper field names and connection details.

**Usage:**
```bash
./scripts/create-secrets.sh
```

**Features:**
- Generates secure random passwords
- Creates secrets with correct field names
- Supports different hosts for temporal vs application databases
- Includes connection URIs for easy application integration

## Troubleshooting

### Common Issues

1. **Cloudnativepg is not ready**: The first installation may fail if cloudnative-pg operator is being installed the first time. Try rerunning or enable only cloudnative-pg in Chart.yaml with `.Values.postgres.clusters` and `.Values.postgres.databases` empty in the first run.
2. **PostgreSQL cluster not ready**: Check CloudNative-PG operator is installed
3. **Storage issues**: Verify storage classes are available in your cluster

### Checking Logs

```bash
# Check PostgreSQL cluster status
kubectl describe cluster pharia-ai-pg-cluster

# Check pod logs
kubectl logs -l app.kubernetes.io/name=postgresql

# Check secret contents
kubectl get secret document-index-pg-secret-qs -o yaml
```

## Uninstallation

```bash
# Remove the chart
helm uninstall quick-start

# Remove secrets (optional - secrets are preserved by default)
# Option 1: Remove all secrets created by this chart
kubectl delete secret -l app.kubernetes.io/name=quick-start

# Option 2: Remove specific secret types
kubectl delete secret -l app.kubernetes.io/component=secret

# Option 3: Remove all secrets with the chart's instance label
kubectl delete secret -l app.kubernetes.io/instance=quick-start

# Option 4: Manual cleanup of specific secrets
kubectl delete secret document-index-pg-secret-qs pharia-os-pg-secret-qs
```
