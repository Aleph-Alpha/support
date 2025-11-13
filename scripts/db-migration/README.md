
# PostgreSQL Backup & Restore Migration Guide

This guide describes the process for migrating PostgreSQL databases from Bitnami pods (per-app DB pods in Kubernetes) to a single PG Cloud Native cluster using the `backup_restore.sh` script.

## Overview

**Migration Path:** Bitnami PostgreSQL (individual pods) → PG Cloud Native (shared cluster)
- **Source:** Per-application database pods in Kubernetes
- **Target:** Single PostgreSQL cluster with multiple databases
- **Method:** Dump and restore using custom backup script

## Prerequisites
- Downtime is required during backup and restore. Block access to the database service (scale down application pods, disable ingress, or update NetworkPolicy) to prevent new data insertion.
- The script requires a `.env` file with DB credentials. For PG Cloud Native, credentials are stored in Kubernetes secrets with prefix `qs-postgresql-cluster-access-`.
- The script must be run in an environment with `psql` (version 17) and `pg_dump` installed.

## Migration Steps

### 1. Backup from Bitnami PostgreSQL

**Option A: kubectl port-forward**
```sh
kubectl port-forward svc/<bitnami-db-service> 5432:5432
# Example:
kubectl port-forward svc/bitnami-postgresql-pharia 5432:5432
```
Create a `.env` file with DB credentials (host: `localhost`, port: `5432`).
Run the backup script:
```sh
./pg_backup_restore.sh backup <output_file.sql>
```

**Option B: Pod with psql 17**
1. Launch a pod with psql 17 installed.
2. Inside the pod, create the `.env` file and copy the `backup_restore.sh` script.
3. In `.env`, set `DB_HOST` to the Bitnami database service name and `DB_PORT` to `5432`.
4. Run:
```sh
./pg_backup_restore.sh backup <output_file.sql>
```

### 2. Restore to PG Cloud Native

PG Cloud Native exposes a single service endpoint for all databases. The endpoint will be either `qs-postgresql-cluster-pharia-rw` or `qs-postgresql-cluster-temporal-rw` based on the database.
Retrieve DB credentials from the Kubernetes secret (prefix: `qs-postgresql-cluster-access-`).
Create a `.env` file with the new credentials.

If needed, port-forward the PG Cloud Native service:
```sh
kubectl port-forward svc/qs-postgresql-cluster-pharia-rw 5432:5432
# Or for temporal:
kubectl port-forward svc/qs-postgresql-cluster-temporal-rw 5432:5432
```
Run the restore script:
```sh
./pg_backup_restore.sh restore <input_file.sql>
# Example:
./pg_backup_restore.sh restore backup-pharia.sql
```

### 3. Switch Application Configuration
- Update application config to use the new PG Cloud Native database endpoint and credentials.
- Redeploy applications if needed.

### 4. Validate Migration
- Test application connectivity and data integrity.
- Resume normal operations.

## Example .env File
```
DB_HOST=your_host
DB_PORT=5432
DB_USER=your_user
DB_PASSWORD=your_password
DB_NAME=your_dbname
```

## Notes
- The script reads credentials from `.env` in the same directory.
- For PG Cloud Native, all databases share one cluster and endpoint through the PG pooler.
- Always use psql 17 for compatibility.
- Ensure backups are stored securely and tested before deleting old databases.

## Troubleshooting
- If you see connection errors, verify port-forwarding, credentials, and network access.
- Ensure downtime is enforced to prevent data loss.
- For restore, make sure the target database exists and is empty or ready for import.
