# ☸️ Database Migration Kubernetes Job

This directory contains Kubernetes manifests to run the database migration as a Job, eliminating the need for manual pod setup and file copying.

## 📁 Contents

- 📜 `configmap-script.yaml` - ConfigMap containing the `database_migrator.sh` script
- ⚙️ `configmap-config.yaml` - ConfigMap containing the `db_config.yaml` configuration
- 🚀 `job.yaml` - Job definition (adaptable for both standard and airgapped environments)
- 🔧 `kustomization.yaml` - Kustomize configuration for deployment

## 📋 Prerequisites

### 🌐 For Standard Environments

- ☸️ Kubernetes cluster with internet access
- 🔧 kubectl configured and connected to your cluster
- 📦 Access to pull images from:
  - `ghcr.io/aleph-alpha/shared-images/pharia-helper:latest`

### 🔒 For Airgapped Environments

⚠️ **IMPORTANT**: For airgapped environments, you **must** prepare the following:

#### 🛠️ Required: Helper Container Image

The migration script requires a container image with these tools pre-installed:
- 🐘 **PostgreSQL 17.x client tools**: `psql`, `pg_dump` (version 17.x)
- 📄 **yq**: YAML processor for parsing configuration files
- 🐚 **bash**: Shell for running the migration script

The default image used is `ghcr.io/aleph-alpha/shared-images/pharia-helper:latest` which includes all required tools.

#### 📦 Required: Images in Internal Registry

Ensure the helper image is available in your internal container registry:

| 📷 Image Purpose | 🌐 Source Image | 🏢 Required In Registry |
|---------------|--------------|---------------------|
| 🚀 Migration container | `ghcr.io/aleph-alpha/shared-images/pharia-helper:latest` | `your-registry.com/pharia-helper:latest` |

**🔧 Steps to prepare:**

1. Pull the image from the source registry:
```bash
docker pull ghcr.io/aleph-alpha/shared-images/pharia-helper:latest
```

2. Tag and push to your internal registry:
```bash
docker tag ghcr.io/aleph-alpha/shared-images/pharia-helper:latest \
  your-registry.company.com/pharia-helper:latest
docker push your-registry.company.com/pharia-helper:latest
```

#### ✅ Verification Checklist

Before deploying to airgapped environment:

- [ ] 📦 Helper image available in internal registry
- [ ] 🏢 Internal registry accessible from Kubernetes cluster
- [ ] 🔑 Image pull secrets configured (if required)
- [ ] 🌐 Network policies allow pod to connect to source and destination databases
- [ ] 🔐 Database credentials configured in `configmap-config.yaml`
- [ ] 📝 `job.yaml` updated with internal registry URL

## 🚀 Quick Start

### 🌐 For Standard Environments (with Internet Access)

#### 1. 🔐 Update Credentials

Edit `configmap-config.yaml` and fill in the database passwords:

```sh
vim configmap-config.yaml
```

Find and replace all `password: ""` fields with actual credentials.

#### 2. 🚀 Deploy with Kustomize

```sh
kubectl apply -k .
```

Or apply individually:

```sh
kubectl apply -f configmap-script.yaml
kubectl apply -f configmap-config.yaml
kubectl apply -f job.yaml
```

### 🔒 For Airgapped Environments (without Internet Access)

#### 1. 📦 Ensure Helper Image is Available

Make sure the helper image is available in your internal registry (see Prerequisites section above).

#### 2. 🔧 Modify job.yaml for Airgapped Use

Edit `job.yaml` to use your internal registry:

```bash
# Make a backup
cp job.yaml job.yaml.bak

# Edit the file
vim job.yaml
```

**⚠️ Required changes in job.yaml:**

Update the container image reference (around line 36):

```yaml
# Change from:
image: ghcr.io/aleph-alpha/shared-images/pharia-helper:latest

# To your internal registry:
image: your-registry.company.com/pharia-helper:latest
```

#### 3. Update Database Credentials

```bash
vim configmap-config.yaml
# Fill in all password fields with actual credentials
```

#### 4. Deploy

```bash
kubectl apply -f configmap-script.yaml
kubectl apply -f configmap-config.yaml
kubectl apply -f job.yaml
```

Or using Kustomize:

```bash
kubectl apply -k .
```

### 3. 👀 Monitor Progress

```sh
# Watch job status
kubectl get job db-migration -n pharia-ai -w

# View logs
kubectl logs -f job/db-migration -n pharia-ai

# Get pod name and check status
kubectl get pods -n pharia-ai -l app=db-migration
```

### 4. 🧹 Cleanup

```sh
# Delete the job
kubectl delete job db-migration -n pharia-ai

# Delete ConfigMaps
kubectl delete configmap db-migration-script db-migration-config -n pharia-ai
```

## ⚙️ Job Configuration

The Job is configured with:

- ⏰ **Timeout**: 2 hours (`activeDeadlineSeconds: 7200`)
- 🔄 **Retries**: 0 attempts (`backoffLimit: 0`) - fails fast on errors
- 🔁 **Restart Policy**: Never (`restartPolicy: Never`)
- 🗓️ **Retention**: Kept for 24 hours after completion (`ttlSecondsAfterFinished: 86400`)
- 💻 **Resources**:
  - 📊 Requests: 256Mi memory, 250m CPU
  - 🚫 Limits: 1Gi memory, 1000m CPU
- 💾 **Storage**:
  - 🗃️ Dumps: 50Gi ephemeral storage
  - 📝 Logs: 1Gi ephemeral storage

## ✨ Features

### 🛡️ Pre-flight Permission Checks

Before starting the actual migration, the script performs comprehensive permission checks to ensure users have the necessary privileges:

**📖 For Source Databases (Dump Operations):**
- 🔗 CONNECT privilege to the database
- 📊 Ability to read from `information_schema` tables
- 🏗️ Access to schema information (required for `pg_dump`)
- 🔐 Proper database access permissions

**✏️ For Destination Databases (Restore Operations):**
- 🔗 CONNECT privilege to the database
- 🏗️ CREATE privilege on the database (required for creating tables)
- 📝 CREATE privilege on the `public` schema (or target schemas)
- 🔐 Proper database access permissions

If any permission issues are detected, the script will:
1. Display clear error messages indicating which permissions are missing
2. Provide SQL commands to grant the necessary permissions
3. Abort the migration before attempting any operations

**Example Permission Errors:**

```
❌ pharia_temporal: User 'myuser' lacks CREATE privilege on destination database (required for restore)
⚠️  pharia_temporal: Grant CREATE permission with: GRANT CREATE ON DATABASE temporal TO myuser;
```

This pre-flight check prevents partial migrations and helps diagnose permission issues early.

## 🏗️ Architecture

The Job uses a single container (`migrator`) that runs the migration script:

- 📦 **Image**: `ghcr.io/aleph-alpha/shared-images/pharia-helper:latest`
- 🛠️ **Pre-installed tools**:
  - 🐘 PostgreSQL 17.x client tools (`psql`, `pg_dump`)
  - 📄 `yq` YAML processor
  - 🐚 `bash` shell
- ⚙️ **Configuration**: Mounted from ConfigMaps
- 💾 **Storage**: Ephemeral volumes for dumps and logs
- 🚀 **Execution**: Runs `database_migrator.sh` with verbose logging

## 📂 Volumes

| 📁 Volume | 📋 Type | 🎯 Purpose | 📏 Size |
|--------|------|---------|------|
| `migration-script` | configMap | The migration shell script | N/A |
| `migration-config` | configMap | Database configuration YAML | N/A |
| `dumps` | emptyDir | Temporary storage for database dumps | 50Gi |
| `logs` | emptyDir | Migration logs | 1Gi |

## 🔧 Troubleshooting

### ❌ Job Failed

Check the pod logs:

```sh
# Get pod name
kubectl get pods -n pharia-ai -l app=db-migration

# View logs
kubectl logs <pod-name> -n pharia-ai

# View logs from previous run (if restarted)
kubectl logs <pod-name> -n pharia-ai --previous
```

### 🔄 Restarting a Failed Job

If a job fails and you need to restart it after making configuration changes, you must delete the existing job before reapplying:

```sh
# Delete the failed job
kubectl delete job db-migration -n pharia-ai

# Reapply the job (and ConfigMaps if deleted)
kubectl apply -f configmap-script.yaml
kubectl apply -f configmap-config.yaml
kubectl apply -f job.yaml

# Or use Kustomize to reapply everything
kubectl apply -k .
```

**⚠️ Important Notes:**
- Kubernetes Jobs are immutable once created, so you cannot modify a running or completed job
- Always delete the job first before making changes to the configuration
- If you only need to update credentials, you can delete just the config ConfigMap and reapply it, but you'll still need to delete and recreate the job

### 🌐 Connection Issues

Verify that the pod can reach the database services:

```sh
# Exec into the pod
kubectl exec -it <pod-name> -n pharia-ai -- bash

# Test connection
psql -h <database-host> -p 5432 -U <username> -d <database>
```

### 🔐 Permission Issues

If the pre-flight checks fail due to missing permissions, you'll need to grant them on the respective databases:

**📖 For Source Database (Dump) Permissions:**

```sql
-- Connect as a superuser or database owner
GRANT CONNECT ON DATABASE <database_name> TO <username>;
GRANT USAGE ON SCHEMA public TO <username>;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO <username>;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO <username>;

-- If you have custom schemas, grant on them too
GRANT USAGE ON SCHEMA <schema_name> TO <username>;
GRANT SELECT ON ALL TABLES IN SCHEMA <schema_name> TO <username>;
```

**✏️ For Destination Database (Restore) Permissions:**

```sql
-- Connect as a superuser or database owner
GRANT CONNECT ON DATABASE <database_name> TO <username>;
GRANT CREATE ON DATABASE <database_name> TO <username>;
GRANT ALL PRIVILEGES ON SCHEMA public TO <username>;

-- If you have custom schemas, grant on them too
GRANT ALL PRIVILEGES ON SCHEMA <schema_name> TO <username>;
```

**🔍 Quick Permission Check:**

You can manually verify permissions by connecting to the database:

```sh
# Check if user can dump (source)
kubectl exec -it <pod-name> -n pharia-ai -- \
  psql -h <source-host> -U <username> -d <database> \
  -c "SELECT has_database_privilege('<username>', '<database>', 'CONNECT');"

# Check if user can restore (destination)
kubectl exec -it <pod-name> -n pharia-ai -- \
  psql -h <dest-host> -U <username> -d <database> \
  -c "SELECT has_database_privilege('<username>', '<database>', 'CREATE');"
```

### 💻 Insufficient Resources

If the job fails due to resource constraints, adjust the limits in `job.yaml`:

```yaml
resources:
  requests:
    memory: "512Mi"
    cpu: "500m"
  limits:
    memory: "2Gi"
    cpu: "2000m"
```

### ⏰ Timeout Issues

For large databases, increase the timeout:

```yaml
spec:
  activeDeadlineSeconds: 14400  # 4 hours
```

Also update the timeout in `configmap-config.yaml`:

```yaml
config:
  timeouts:
    restore: 7200  # 2 hours
    dump: 7200     # 2 hours
```

## 🔒 Security Considerations

1. 👮 **RBAC**: The job uses the default service account. For production, create a dedicated service account with minimal permissions.

2. 🌐 **Network Policies**: Ensure the job pod has network access to both source and destination databases.

## 🔬 Advanced Usage

### 🧪 Dry Run Mode

To test without actually migrating data, edit the job command in `job.yaml`:

```yaml
command:
- /bin/bash
- -c
- |
  ./database_migrator.sh --config db_config.yaml --dry-run --verbose
```

### 🎯 Selective Migration

To migrate only specific databases, edit `configmap-config.yaml` and remove unwanted database entries from the `databases` list.

### 🛠️ Custom Configuration

You can override the configuration by updating the `configmap-config.yaml` file. Common customizations:

- Adjust timeouts for large databases
- Change dump options
- Modify retry behavior
- Update dump directory location

## 📚 References

- ☸️ [Kubernetes Jobs](https://kubernetes.io/docs/concepts/workloads/controllers/job/)
- 📝 [ConfigMaps](https://kubernetes.io/docs/concepts/configuration/configmap/)
- 🔧 [Kustomize](https://kubernetes.io/docs/tasks/manage-kubernetes-objects/kustomization/)
- 🐘 [PostgreSQL Documentation](https://www.postgresql.org/docs/17/)
