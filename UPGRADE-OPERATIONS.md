# Pharia AI Upgrade Operations Manual

This operations manual provides step-by-step instructions for performing backups before a Pharia AI version upgrade and restoring to the previous version if issues are encountered with the new version.

## 📋 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Maintenance Window Planning](#maintenance-window-planning)
- [Scaling Down Application Deployments](#scaling-down-application-deployments)
- [Pre-Upgrade Backup Procedures](#pre-upgrade-backup-procedures)
  - [PostgreSQL Database Backup](#postgresql-database-backup)
  - [Kubernetes Secrets Backup](#kubernetes-secrets-backup)
  - [Qdrant Vector Database Backup](#qdrant-vector-database-backup)
- [Performing the Upgrade](#performing-the-upgrade)
- [Post-Upgrade Verification and Scale-Up](#post-upgrade-verification-and-scale-up)
- [Restore Procedures](#restore-procedures)
  - [Helm Rollback](#helm-rollback)
  - [PostgreSQL Database Restore](#postgresql-database-restore)
  - [Kubernetes Secrets Restore](#kubernetes-secrets-restore)
  - [Qdrant Vector Database Restore](#qdrant-vector-database-restore)
- [Troubleshooting](#troubleshooting)
- [Appendix: Quick Reference](#appendix-quick-reference)

## Overview

This manual covers the backup and restore workflow for Pharia AI deployments during version upgrades. The process involves:

1. **Pre-Upgrade**: Backing up PostgreSQL databases, Kubernetes secrets, and Qdrant vector databases
2. **Upgrade**: Perform your Helm upgrade to the new version (using your organization's standard procedures)
3. **Verification**: Testing the upgraded deployment
4. **Restore** (if needed): Restoring all components to the previous version

> **⚠️ Important**: Always perform backups before any upgrade. The restore process requires all backups to be completed successfully.
>
> **Note**: This manual focuses on backup and restore procedures. Helm upgrade/rollback operations should be performed according to your organization's change management procedures.

## Prerequisites

Before starting the upgrade process, ensure you have:

### Required Tools

- **kubectl** - Configured with access to your Kubernetes cluster
- **helm** - Version 3.x or later
- **PostgreSQL client tools** - `psql`, `pg_dump`, `pg_restore`
- **bash** - Version 4.0 or later
- **jq** - JSON processor
- **curl** - HTTP client
- **mc** (MinIO client) - For S3 operations (Qdrant restore only)

### Access Requirements

- Kubernetes cluster access with appropriate permissions (also port-forward permission)
- Network access to PostgreSQL databases
- Network access to Qdrant instances
- S3 bucket access (for Qdrant backups)
- Helm chart repository access

### Backup Scripts

Ensure you have the backup/restore scripts from this repository:

- `pharia-ai-backup-restore/` - PostgreSQL and Kubernetes secrets backup/restore
- `qdrant-backup-restore/` - Qdrant vector database backup/restore

### Information to Gather

Before starting, collect the following information:

1. **Current Helm Release Name**: The name of your Pharia AI Helm release
2. **Kubernetes Namespace**: The namespace where Pharia AI is deployed (typically `pharia-ai`)
3. **Current Version**: The current Pharia AI version (check with `helm list -n <namespace>`)
4. **Target Version**: The version you're upgrading to
5. **PostgreSQL Connection Details**: Host, port, database names, credentials
6. **Qdrant Connection Details**: Service endpoints, API keys (if configured)
7. **S3 Configuration**: Endpoint, bucket name, access credentials (for Qdrant)

## Maintenance Window Planning

### Recommended Maintenance Window Duration

- **Small deployments** (< 10GB data): 2-4 hours
- **Medium deployments** (10-100GB data): 4-8 hours
- **Large deployments** (> 100GB data): 8-12 hours

### Maintenance Window Checklist

- [ ] Notify stakeholders of the maintenance window
- [ ] Schedule during low-traffic periods
- [ ] Ensure team members are available for support
- [ ] Prepare rollback plan and communicate it
- [ ] Verify backup storage has sufficient space
- [ ] Test backup scripts in a non-production environment (if possible)

### Pre-Maintenance Verification

```bash
# Verify cluster connectivity
kubectl cluster-info

# Verify Helm access
helm list -n <namespace>

# Check pod status
kubectl get pods -n <namespace>

# Verify PostgreSQL connectivity (if accessible)
psql -h <postgres-host> -p <port> -U <user> -d <database> -c "SELECT version();"
```

## Scaling Down Application Deployments

**⏱️ Estimated Time**: 5-10 minutes

> **⚠️ Important**: Scaling down application deployments before backup ensures data consistency across all systems and prevents in-flight transactions during the backup process.

### Why Scale Down?

Scaling down provides several critical benefits:
- **Data Consistency**: Guarantees point-in-time consistency across PostgreSQL, Qdrant, and application state
- **No In-Flight Transactions**: Prevents partial transactions or data changes during backup
- **Clean Restore State**: Ensures a known, consistent state for rollback scenarios
- **Safer Operations**: Eliminates risk of data corruption during backup/restore

### Step 1: Identify Application Deployments

```bash
# List all deployments in the namespace 
kubectl get deployments -n <namespace>

# You might also be able to get all pharia-ai deployments using our default label
kubectl get deployment -l pharia.ai/edition=1

# Get detailed deployment information
kubectl get deployments -n <namespace> -o wide
```

### Step 2: Document Current Replica Counts

**📝 Critical**: Document current replica counts before scaling down. You'll need this information to restore normal operations.

```bash
# Get current replica counts for all deployments
kubectl get deployments -n <namespace> -o custom-columns=NAME:.metadata.name,REPLICAS:.spec.replicas,READY:.status.readyReplicas

# Compare with pharia-ai application deployments
kubectl get deployments -n <namespace>  -l pharia.ai/edition=1 -o custom-columns=NAME:.metadata.name,REPLICAS:.spec.replicas,READY:.status.readyReplicas

# Save to a file for reference
kubectl get deployments -n <namespace> -o json | jq -r '.items[] | "\(.metadata.name): \(.spec.replicas)"' > deployment-replicas-backup.txt

# Add any missed application deployments into the deployment-replicas-backup.txt
# Display the saved replica counts
cat deployment-replicas-backup.txt
```

**Document the replica counts:**

```
Deployment Name                 | Current Replicas
--------------------------------|------------------
<deployment-1>                  | _____________
<deployment-2>                  | _____________
<deployment-3>                  | _____________
```

### Step 3: Scale Down Application Deployments

```bash
# Scale down specific application deployment
kubectl scale deployment <deployment-name> --replicas=0 -n <namespace>

# Or scale down all application deployments at once (exclude database/infrastructure pods)
# Example: Scale down all deployments with label 'app.kubernetes.io/component=application'
kubectl scale deployment -l pharia.ai/edition=1 --replicas=0 -n <namespace>

# Wait for pods to terminate
kubectl wait --for=delete pod -l app=<app-label> -n <namespace> --timeout=300s
```

> **Note**: Do NOT scale down database deployments (PostgreSQL, Qdrant). Only scale down application workloads that interact with the databases.

### Step 4: Verify Scale Down

```bash
# Verify application pods are terminated
kubectl get pods -n <namespace>

# Check deployment replica counts
kubectl get deployments -n <namespace>

# Verify only database and infrastructure pods remain
kubectl get pods -n <namespace> --field-selector=status.phase=Running
```

**Expected state:**
- Application deployments should show 0/0 ready replicas
- Database pods (PostgreSQL, Qdrant) should remain running
- No application pods should be in Running state

**✅ Scale Down Checklist:**

- [ ] Current replica counts documented
- [ ] Replica backup file saved (`deployment-replicas-backup.txt`)
- [ ] Application deployments scaled to 0 replicas
- [ ] All application pods terminated
- [ ] Database pods still running
- [ ] Cluster in stable state

## Pre-Upgrade Backup Procedures

**⏱️ Estimated Time**: 30-60 minutes (depending on data size)

Perform all backups **before** starting the upgrade. Document the backup timestamps for reference during restore.

### Step 1: Prepare Backup Directories

```bash
# Navigate to the support repository
cd /path/to/support

# Create backup directories (if they don't exist)
mkdir -p pharia-ai-backup-restore/database-backups
mkdir -p pharia-ai-backup-restore/secrets-backups
mkdir -p qdrant-backup-restore/backups
```

### Step 2: PostgreSQL Database Backup

#### 2.1 Configure PostgreSQL Backup

```bash
cd pharia-ai-backup-restore

# Copy the example configuration
cp config.yaml.example config.yaml

# Edit config.yaml with your database details
nano config.yaml  # or use your preferred editor
```

**Example `config.yaml`:**

```yaml
backup_dir: "./database-backups"

databases:
  - name: pharia_chat_db
    host: postgres-chat-db.pharia-ai.svc.cluster.local
    port: 5432
    user: pharia_chat_user
    password: your_password_here
  - name: pharia_assistant_db
    host: postgres-assistant-db.pharia-ai.svc.cluster.local
    port: 5432
    user: pharia_assistant_user
    password: your_password_here
  ...
```

> **Note**: Ensure you have your database connection details for all databases (host, port, database name, username, password) available before proceeding.

#### 2.2 Test Database Connection

```bash
# You may need to port forward your database services if running in kubernetes cluster
# Test connection to verify credentials
psql -h <host> -p <port> -U <user> -d <database> -c "SELECT version();"
```

#### 2.3 Perform Database Backup

```bash
# Backup all databases configured in config.yaml
./bin/pharia-backup.sh db backup
```

**Expected Output:**
```
[2025-01-XX XX:XX:XX] Starting database backup...
[2025-01-XX XX:XX:XX] Backing up database: pharia_ai_db
[2025-01-XX XX:XX:XX] Backup completed: database-backups/pharia_ai_db_2025-01-XX_XXXXXX.sql
[2025-01-XX XX:XX:XX] All backups completed successfully
```

**Verify Backup Files:**

```bash
# List backup files with timestamps
ls -lth database-backups/

# Note the backup filenames and timestamps for restore reference
```

#### 2.4 Document Backup Information

Record the following information:

- Backup timestamp: `_____________`
- Backup file locations: `_____________`
- Database names backed up: `_____________`

### Step 3: Kubernetes Secrets Backup

#### 3.1 Perform Secrets Backup

```bash
# Backup all secrets in the Pharia AI namespace
./bin/pharia-backup.sh secrets backup pharia-ai
```

**Expected Output:**
```
[2025-01-XX XX:XX:XX] Starting secrets backup...
[2025-01-XX XX:XX:XX] Backing up secrets from namespace: pharia-ai
[2025-01-XX XX:XX:XX] Backup completed: secrets-backups/pharia-ai_2025-01-XX_XXXXXX.tar.gz
[2025-01-XX XX:XX:XX] All backups completed successfully
```

#### 3.2 Verify Secrets Backup

```bash
# List backup files
ls -lth secrets-backups/

# Verify backup archive integrity
tar -tzf secrets-backups/pharia-ai_<timestamp>.tar.gz | head -5
```

#### 3.3 Document Backup Information

Record the following information:

- Backup timestamp: `_____________`
- Backup file location: `_____________`
- Number of secrets backed up: `_____________`

### Step 4: Qdrant Vector Database Backup

#### 4.1 Configure Qdrant Backup

```bash
cd ../qdrant-backup-restore

# Create environment file
cp .env.sample .env  # If .env.sample exists, otherwise create .env manually
nano .env  # or use your preferred editor
```

**Example `.env` file for backup:**

```bash
# Qdrant API key (leave as is if none exists)
export QDRANT_API_KEY="your-api-key-here"

# Source Qdrant hosts (comma-separated)
# You may need to port-forward your Qdrant service if running in kubernetes
export QDRANT_SOURCE_HOSTS="http://document-index-qdrant-headless.pharia-ai.svc.cluster.local:6333"

# Restore hosts (empty for backup)
export QDRANT_RESTORE_HOSTS=""

# Auto-discover peers from cluster info (true for Kubernetes)
export GET_PEERS_FROM_CLUSTER_INFO="true"

# Timeout settings
export CURL_TIMEOUT="1800"  # 30 minutes

# Wait for tasks to complete
export QDRANT_WAIT_ON_TASK="true"
```

> **Note**: Ensure you have your Qdrant connection details (service endpoint, API key if configured) available before proceeding.

#### 4.2 Source Environment Variables

```bash
# Source the environment file
source .env

# Verify environment variables are set
echo "Source hosts: $QDRANT_SOURCE_HOSTS"
echo "API key set: $([ -n "$QDRANT_API_KEY" ] && echo "Yes" || echo "No")"
```

#### 4.3 Perform Qdrant Backup

```bash
# Create snapshots of all collections
./qdrant_backup_recovery.sh create_snap
```

**Expected Output:**
```
[2025-01-XX XX:XX:XX] fetching collections!
[2025-01-XX XX:XX:XX] collections file updated, found X collection(s)!
[2025-01-XX XX:XX:XX] Creating snapshot for collection: collection_name
[2025-01-XX XX:XX:XX] Snapshot created successfully: snapshot_name
...
[2025-01-XX XX:XX:XX] All snapshots created successfully
```

#### 4.4 Backup Collection Aliases

> **Important**: Collection aliases are not included in snapshots and must be backed up separately.

```bash
# Fetch and backup collection aliases
./qdrant_backup_recovery.sh get_colla
```

**Expected Output:**
```
[2025-01-XX XX:XX:XX] Fetching collection aliases...
[2025-01-XX XX:XX:XX] Found X alias(es)
[2025-01-XX XX:XX:XX] Aliases saved to collection_aliases file
```

#### 4.5 Verify Qdrant Backup

```bash
# Check state files
ls -lh collections snapshots collection_aliases

# View snapshots created
cat snapshots

# View collections backed up
cat collections

# View aliases backed up
cat collection_aliases
```

#### 4.6 Document Backup Information

Record the following information:

- Backup timestamp: `_____________`
- Number of collections: `_____________`
- Number of snapshots: `_____________`
- Number of aliases: `_____________`
- S3 bucket location: `_____________`

### Step 5: Final Backup Verification

Before proceeding with the upgrade, verify all backups:

```bash
# PostgreSQL backups
echo "=== PostgreSQL Backups ==="
ls -lh pharia-ai-backup-restore/database-backups/

# Kubernetes secrets backups
echo "=== Kubernetes Secrets Backups ==="
ls -lh pharia-ai-backup-restore/secrets-backups/

# Qdrant backups
echo "=== Qdrant Backups ==="
ls -lh qdrant-backup-restore/*.csv qdrant-backup-restore/collections qdrant-backup-restore/snapshots qdrant-backup-restore/collection_aliases 2>/dev/null
```

**✅ Backup Checklist:**

- [ ] Application deployments scaled down
- [ ] Replica counts documented
- [ ] PostgreSQL database backup completed successfully
- [ ] Kubernetes secrets backup completed successfully
- [ ] Qdrant snapshots created successfully
- [ ] Qdrant collection aliases backed up
- [ ] All backup files verified and accessible
- [ ] Backup timestamps documented
- [ ] Backup file locations documented

## Performing the Upgrade

After completing all backups, perform your Helm upgrade according to your organization's standard change management procedures.

### Document Upgrade Information

Record the following for reference:

- Upgrade timestamp: `_____________`
- Previous version: `_____________`
- New version: `_____________`
- Helm release name: `_____________`
- Namespace: `_____________`

> **Note**: Application deployments remain scaled down during the upgrade but may be scaled up after upgrade, depending on your Org standards.

## Post-Upgrade Verification and Scale-Up

**⏱️ Estimated Time**: 30-60 minutes

### Step 1: Verify Infrastructure Pods

```bash
# Check all pods are running (databases and infrastructure)
kubectl get pods -n <namespace>

### Step 2: Verify Database Connectivity

```bash
# Test PostgreSQL connectivity
psql -h <host> -p <port> -U <user> -d <database> -c "SELECT version();"

# Verify Qdrant connectivity
# You will need to port forward the qdrant service if running on kubernetes
kubectl port-forward svc/document-index-qdrant-headless 6333:6333
curl -s http://localhost:6333/collections
```

### Step 3: Scale Up Application Deployments

Note: If your pods already scaled back up then you can skip this step

Once infrastructure verification is complete, restore application deployments to their original replica counts.

```bash
# Restore replica counts from backup file
cat deployment-replicas-backup.txt

# Scale up specific deployment to original replica count
kubectl scale deployment <deployment-name> --replicas=<original-count> -n <namespace>

# Or use a script to restore all deployments
while IFS=': ' read -r name replicas; do
  echo "Scaling $name to $replicas replicas..."
  kubectl scale deployment "$name" --replicas="$replicas" -n <namespace>
done < deployment-replicas-backup.txt
```

### Step 4: Wait for Application Pods to Start

```bash
# Watch pods coming online
kubectl get pods -n <namespace> -w

# Wait for all pods to be ready
kubectl wait --for=condition=ready pod --all -n <namespace> --timeout=600s

# Check for any pod errors
kubectl get pods -n <namespace> | grep -v Running | grep -v Completed
```

### Step 5: Verify Application Health

```bash
# Check application endpoints
kubectl get ingress -n <namespace>

# Test application connectivity (adjust endpoint as needed)
curl -k https://<your-app-url>/health

# Check application logs for startup errors
kubectl logs -n <namespace> -l app=<app-label> --tail=50 --since=5m
```

### Step 6: Functional Testing

Perform your standard functional tests:

- [ ] Application login/authentication works
- [ ] Core application features operational
- [ ] Database queries executing correctly
- [ ] Vector search functionality working (if applicable)
- [ ] API endpoints responding correctly
- [ ] Integration points functioning

### Step 7: Performance Verification

```bash
# Check resource usage
kubectl top pods -n <namespace>

# Check for any resource constraints
kubectl describe pods -n <namespace> | grep -A 5 "Limits\|Requests"

# Monitor for any crash loops or restarts
kubectl get pods -n <namespace> -o custom-columns=NAME:.metadata.name,RESTARTS:.status.containerStatuses[0].restartCount
```

**✅ Post-Upgrade Verification Checklist:**

- [ ] All infrastructure pods running
- [ ] Database connectivity verified
- [ ] Qdrant connectivity verified
- [ ] Application deployments scaled up to original replica counts
- [ ] All application pods running and ready
- [ ] Application is accessible
- [ ] Functional tests passed
- [ ] No critical errors in logs
- [ ] No excessive pod restarts
- [ ] Resource usage is normal

> **Success**: If all checks pass, the upgrade is complete. Document the successful upgrade and notify stakeholders.

## Restore Procedures

**⏱️ Estimated Time**: 1-2 hours (depending on data size)

If issues are encountered after the upgrade, follow this restore procedure to revert to the previous version.

> **⚠️ Critical**:
> 1. Perform rollback steps in the exact order specified
> 2. Do not skip any steps
> 3. Application deployments should remain scaled down during restore

### Step 1: Document Issues

Before starting the restore process, document:

- Issues encountered: `_____________`
- Error messages: `_____________`
- Affected components: `_____________`
- Restore timestamp: `_____________`

### Step 2: Scale Down Application Deployments (if not already scaled down)

**Follow same steps in "Scaling Down Application Deployments" at the beginning of this document**


### Step 3: Perform Helm Rollback

Use your organization's standard Helm rollback procedures to revert to the previous release version.


> **Note**: This manual focuses on backup and restore procedures. Perform Helm rollback according to your organization's change management procedures.

### Step 4: PostgreSQL Database Restore

#### 4.1 Verify Backup Files

```bash
cd pharia-ai-backup-restore

# List available backups
./bin/pharia-backup.sh db restore -l all

# Or manually list
ls -lth database-backups/
```

#### 4.2 Restore Databases

```bash
# Restore all databases from backup
./bin/pharia-backup.sh db restore all
```

**Expected Output:**
```
[2025-01-XX XX:XX:XX] Starting database restore...
[2025-01-XX XX:XX:XX] Restoring database: pharia_ai_db
[2025-01-XX XX:XX:XX] Restore completed successfully
[2025-01-XX XX:XX:XX] All databases restored
```

**Or restore specific database:**

```bash
# Restore specific database
./bin/pharia-backup.sh db restore <database-name>

# Or restore from specific backup file
./bin/pharia-backup.sh db restore -f database-backups/<backup-file> <database-name>
```

#### 4.3 Verify Database Restore

```bash
# Verify database connectivity
psql -h <host> -p <port> -U <user> -d <database> -c "SELECT COUNT(*) FROM information_schema.tables;"

# Check database content (adjust query based on your schema)
psql -h <host> -p <port> -U <user> -d <database> -c "SELECT * FROM <your-table> LIMIT 5;"
```

### Step 5: Kubernetes Secrets Restore

#### 5.1 List Available Backups

```bash
# List available secret backups
./bin/pharia-backup.sh secrets restore -l

# Or manually list
ls -lth secrets-backups/
```

#### 5.2 Restore Secrets

```bash
# Restore from latest backup (with force to overwrite existing secrets)
./bin/pharia-backup.sh secrets restore --latest -f -n pharia-ai
```

**Expected Output:**
```
[2025-01-XX XX:XX:XX] Starting secrets restore...
[2025-01-XX XX:XX:XX] Restoring secrets to namespace: pharia-ai
[2025-01-XX XX:XX:XX] Restored secret: secret-name-1
[2025-01-XX XX:XX:XX] Restored secret: secret-name-2
...
[2025-01-XX XX:XX:XX] All secrets restored successfully
```

#### 5.3 Verify Secrets Restore

```bash
# Verify secrets exist
kubectl get secrets -n pharia-ai

# Verify specific secret (example)
kubectl get secret <secret-name> -n pharia-ai -o yaml
```

### Step 6: Qdrant Vector Database Restore

#### 6.1 Configure Qdrant Restore Environment

```bash
cd ../qdrant-backup-restore

# Update .env file for restore
nano .env
```

**Example `.env` file for restore:**

```bash
# Qdrant API key
export QDRANT_API_KEY="your-api-key-here"

# Source hosts (where snapshots are stored)
export QDRANT_SOURCE_HOSTS="http://localhost:6333"

# Restore hosts (target Qdrant instances)
export QDRANT_RESTORE_HOSTS="http://localhost:6334"

# S3 configuration (for fetching snapshots)
export QDRANT_S3_ENDPOINT_URL="http://minio.default.svc.cluster.local:9000"
export QDRANT_S3_ACCESS_KEY_ID="your-access-key"
export QDRANT_S3_SECRET_ACCESS_KEY="your-secret-key"
export QDRANT_S3_BUCKET_NAME="qdrant-snapshots"

# Auto-discover peers
export GET_PEERS_FROM_CLUSTER_INFO="true"

# Timeout settings
export CURL_TIMEOUT="1800"

# Wait for tasks
export QDRANT_WAIT_ON_TASK="true"

# Optional: Filter snapshots by datetime (leave empty for all)
export QDRANT_SNAPSHOT_DATETIME_FILTER=""
```

#### 6.2 Source Environment Variables

```bash
# Source the environment file
source .env

# Verify environment variables
echo "Source hosts: $QDRANT_SOURCE_HOSTS"
echo "Restore hosts: $QDRANT_RESTORE_HOSTS"
echo "S3 bucket: $QDRANT_S3_BUCKET_NAME"
```

#### 6.3 Fetch Snapshots from S3

```bash
# Fetch snapshot metadata from S3
./qdrant_backup_recovery.sh get_snap_s3
```

**Expected Output:**
```
[2025-01-XX XX:XX:XX] Fetching snapshots from S3...
[2025-01-XX XX:XX:XX] Found X snapshot(s) in S3
[2025-01-XX XX:XX:XX] Snapshots file updated
```

#### 6.4 Restore Snapshots

```bash
# Restore all snapshots
./qdrant_backup_recovery.sh recover_snap
```

**Expected Output:**
```
[2025-01-XX XX:XX:XX] Starting snapshot recovery...
[2025-01-XX XX:XX:XX] Recovering collection: collection_name
[2025-01-XX XX:XX:XX] Snapshot recovery completed successfully
...
[2025-01-XX XX:XX:XX] All snapshots recovered
```

#### 6.5 Restore Collection Aliases

```bash
# Restore collection aliases
./qdrant_backup_recovery.sh recover_colla
```

**Expected Output:**
```
[2025-01-XX XX:XX:XX] Starting alias recovery...
[2025-01-XX XX:XX:XX] Recovered alias: alias_name -> collection_name
...
[2025-01-XX XX:XX:XX] All aliases recovered
```

#### 6.6 Verify Qdrant Restore

```bash
# Verify collections exist
curl -s http://localhost:6333/collections | jq

# Verify specific collection
curl -s http://localhost:6333/collections/<collection-name> | jq

# Check collection aliases
curl -s http://localhost:6333/aliases | jq
```

### Step 7: Verify Infrastructure Before Scale-Up

```bash
# Verify all database pods are running
kubectl get pods -n <namespace>

# Verify database connectivity
psql -h <host> -p <port> -U <user> -d <database> -c "SELECT version();"

# Verify Qdrant connectivity
curl -s http://localhost:6333/collections
```

### Step 8: Scale Up Application Deployments

After verifying all data is restored, scale up application deployments:

**Follow same steps in "Scale Up Application Deployments" at the earlier section of this document**


### Step 9: Final Verification

```bash
# Verify all pods are running
kubectl get pods -n <namespace>

# Verify application is accessible
curl -k https://<your-app-url>/health

# Verify database connectivity
kubectl exec -n <namespace> <postgres-pod> -- psql -U <user> -d <database> -c "SELECT version();"

# Verify Qdrant connectivity
kubectl exec -n <namespace> <qdrant-pod> -- curl -s http://localhost:6333/collections
```

**✅ Restore Checklist:**

- [ ] Issues documented
- [ ] Application deployments scaled down
- [ ] Helm rollback completed (using your organization's procedures)
- [ ] PostgreSQL databases restored
- [ ] Kubernetes secrets restored
- [ ] Qdrant snapshots restored
- [ ] Qdrant collection aliases restored
- [ ] Infrastructure verified before scale-up
- [ ] Application deployments scaled up to original replica counts
- [ ] All pods running and ready
- [ ] Application is accessible
- [ ] Functional tests passed

## Troubleshooting

### Common Issues During Backup

#### PostgreSQL Connection Failed

**Symptoms:**
```
Error: connection to server failed
```

**Solutions:**
1. Verify network connectivity to PostgreSQL host
2. Check firewall rules
3. Verify credentials in `config.yaml`
4. Test connection manually: `psql -h <host> -p <port> -U <user> -d <database>`

#### Qdrant Snapshot Creation Timeout

**Symptoms:**
```
Error: timeout waiting for snapshot creation
```

**Solutions:**
1. Increase `CURL_TIMEOUT` in `.env` file (e.g., `3600` for 1 hour)
2. Check Qdrant pod resources (CPU/memory)
3. Verify S3 connectivity from Qdrant pods
4. Check Qdrant logs: `kubectl logs -n <namespace> <qdrant-pod>`

#### Kubernetes Secrets Backup Permission Denied

**Symptoms:**
```
Error: permission denied
```

**Solutions:**
1. Verify `kubectl` has appropriate permissions
2. Check RBAC rules for the service account
3. Verify namespace access: `kubectl auth can-i get secrets -n <namespace>`

### Common Issues During Restore

#### Database Restore Fails

**Symptoms:**
```
Error: database restore failed
```

**Solutions:**
1. Verify backup file exists and is not corrupted
2. Check database connection details
3. Ensure database exists: `CREATE DATABASE <name>;`
4. Check disk space on database server
5. Review PostgreSQL logs

#### Secrets Restore Conflicts

**Symptoms:**
```
Error: secret already exists
```

**Solutions:**
1. Use force flag: `--latest -f`
2. Delete existing secret first: `kubectl delete secret <name> -n <namespace>`
3. Verify namespace is correct

#### Qdrant Snapshot Recovery Fails

**Symptoms:**
```
Error: snapshot recovery failed
```

**Solutions:**
1. Verify S3 credentials are correct
2. Check S3 bucket accessibility
3. Verify snapshot exists in S3
4. Check Qdrant logs: `kubectl logs -n <namespace> <qdrant-pod>`
5. Verify collection doesn't already exist (may need to delete first)

### Getting Help

If you encounter issues not covered in this manual:

1. **Check Logs:**
   ```bash
   # Application logs
   kubectl logs -n <namespace> <pod-name> --tail=100
   
   # Helm release events
   helm get events <release-name> -n <namespace>
   
   # Kubernetes events
   kubectl get events -n <namespace> --sort-by='.lastTimestamp'
   ```

2. **Review Documentation:**
   - [pharia-ai-backup-restore README](pharia-ai-backup-restore/README.md)
   - [qdrant-backup-restore README](qdrant-backup-restore/README.md)

3. **Contact Support:**
   - Provide error messages and logs
   - Include backup/restore timestamps
   - Share relevant configuration (sanitized)


### Important Files and Locations

- **Deployment replica backup**: `deployment-replicas-backup.txt` (created during scale-down)
- **PostgreSQL backups**: `pharia-ai-backup-restore/database-backups/`
- **Kubernetes secrets backups**: `pharia-ai-backup-restore/secrets-backups/`
- **Qdrant state files**: `qdrant-backup-restore/collections`, `snapshots`, `collection_aliases`
- **PostgreSQL config**: `pharia-ai-backup-restore/config.yaml`
- **Qdrant config**: `qdrant-backup-restore/.env`

---

**Document Version**: 2.0
**Last Updated**: 2026-02-05
**Maintained By**: Aleph Alpha Support Team
