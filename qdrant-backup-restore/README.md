# Qdrant Backup and Restore Scripts

This directory provides production-grade scripts to back up Qdrant snapshots and restore or recover them across multiple instances, supporting migrations from n source instances to x target instances.

## Prerequisites

- **Bash**
- **curl**
- **jq**
- **mc**

## Installation

1. **Clone or navigate to the repository directory:**

   ```bash
   cd qdrant-backup-restore
   ```

2. **Create and configure environment file:**

   ```bash
   cp .env.sample .env
   # Edit .env with your configuration
   ```

3. **Source the environment file:**

   ```bash
   source .env
   ```

   **Note:** You must source the `.env` file in your current shell session, or export the variables before running the script.

## Configuration

### Environment Variables

Create a `.env` file based on `.env.sample` with the following variables:

#### Required Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `QDRANT_API_KEY` | Qdrant API key for authentication | `your-api-key-here` |
| `QDRANT_SOURCE_HOSTS` | Comma-separated list of source Qdrant hosts | `http://qdrant-1:6333,http://qdrant-2:6333` |
| `QDRANT_RESTORE_HOSTS` | Comma-separated list of destination Qdrant hosts | `http://qdrant-new:6333` |
| `QDRANT_S3_ENDPOINT_URL` | S3-compatible storage endpoint URL | `http://minio:9000` |
| `QDRANT_S3_ACCESS_KEY_ID` | S3 access key ID | `your-access-key` |
| `QDRANT_S3_SECRET_ACCESS_KEY` | S3 secret access key | `your-secret-key` |
| `QDRANT_S3_BUCKET_NAME` | S3 bucket name where snapshots are stored | `bucket-name` |
| `GET_PEERS_FROM_CLUSTER_INFO` | Auto-discover peers from cluster info endpoint (useful for Kubernetes) | `false` |
| `CURL_TIMEOUT` | Timeout for curl operations in seconds, set to 30mins  | `1800` (30mins) |
| `QDRANT_S3_LINK_EXPIRY_DURATION` | Presigned URL expiry duration in seconds | `3600` (1 hour) |
| `QDRANT_WAIT_ON_TASK` | Waits for changes to happen, used when creating snapshots and restoring snapshots | `true` |

### Example .env File

```bash
export QDRANT_API_KEY="your-qdrant-api-key"
export QDRANT_SOURCE_HOSTS="http://qdrant-source-1:6333,http://qdrant-source-2:6333"
export QDRANT_RESTORE_HOSTS="http://qdrant-dest:6333"
export QDRANT_S3_ENDPOINT_URL="http://minio.default.svc.cluster.local:9000"
export QDRANT_S3_ACCESS_KEY_ID="minioadmin"
export QDRANT_S3_SECRET_ACCESS_KEY="minioadmin"
export QDRANT_S3_BUCKET_NAME="qdrant-snapshots"
export GET_PEERS_FROM_CLUSTER_INFO="false"
export CURL_TIMEOUT="300"
```

## Overview

The scripts support backup and restoration of Qdrant collection snapshots using Qdrant REST APIs and S3-compatible storage. The workflow consists of:

1. **Backup Phase:** Create snapshots of collections and optionally fetch collection aliases
2. **Storage:** Snapshots are stored in S3-compatible storage (configured in Qdrant)
3. **Restore Phase:** Fetch snapshot metadata and recover collections to target instances

## State Files

The following state files are created in the script directory to track progress and act as input for subsequent operations:

| File | Purpose | Created By |
|------|---------|------------|
| `collections` | List of collections with their source hosts | `get_coll`, `get_snap`, `get_snap_s3` |
| `snapshots` | List of snapshots (host, collection, snapshot_name) | `create_snap`, `get_snap`, `get_snap_s3` |
| `collection_aliases` | List of collection aliases (collection_name, alias_name) | `get_colla` |
| `snapshot_recovery_history` | History of snapshot recovery attempts | `recover_snap` |
| `alias_recovery_history` | History of alias recovery attempts | `recover_colla` |
| `failed_snapshot_recovery` | Failed recovery attempts for debugging | `recover_snap` |

**Note:** These files are CSV format and can be manually edited if needed.

## Backup Operations

### Create Snapshots

Creates snapshots for all collections on all source hosts. This is the primary backup operation.

```bash
./qdrant_backup_recovery.sh create_snap
```

**What it does:**

1. Fetches list of collections from source hosts (if `collections` file doesn't exist)
2. Creates a snapshot for each collection on each source host
3. Records snapshot metadata in `snapshots` file

**Output:**

- Creates/updates `collections` file
- Creates/updates `snapshots` file
- Snapshots are stored in S3 (configured in Qdrant)

### Fetch Collections Only

Fetches the list of collections without creating snapshots:

```bash
./qdrant_backup_recovery.sh get_coll
```

**Use case:** When you want to inspect collections before creating snapshots.

### Fetch Collection Aliases

Collection aliases are not included in snapshots and must be backed up separately:

```bash
./qdrant_backup_recovery.sh get_colla
```

**Important:** Run this after creating snapshots to ensure aliases are backed up.

## Restore Operations

### Fetch Snapshots from S3

Lists snapshots available in S3 storage:

```bash
./qdrant_backup_recovery.sh get_snap_s3
```

**What it does:**

1. Connects to S3 and lists all snapshot objects
2. Parses snapshot paths to extract collection and snapshot names
3. Populates `collections` and `snapshots` files

**Use case:** When restoring from a different environment or after snapshots have been created elsewhere.

### Fetch Snapshots from Instance

Lists snapshots directly from Qdrant instances:

```bash
./qdrant_backup_recovery.sh get_snap
```

**What it does:**

1. Reads collections from `collections` file (or fetches if missing)
2. Queries each collection on each host for available snapshots
3. Records the latest snapshot for each collection in `snapshots` file

### Recover Snapshots

Restores collections from snapshots to target hosts:

```bash
./qdrant_backup_recovery.sh recover_snap
```

**What it does:**

1. Reads snapshot list from `snapshots` file
2. Generates presigned S3 URLs for each snapshot
3. Recovers each snapshot to each restore host
4. Tracks progress in `snapshot_recovery_history`
5. Records failures in `failed_snapshot_recovery`

**Idempotent:** Already recovered snapshots are automatically skipped.

### Recover Collection Aliases

Restores collection aliases to target hosts:

```bash
./qdrant_backup_recovery.sh recover_colla
```

**Prerequisites:** Must have `collection_aliases` file (created by `get_colla`).

**Idempotent:** Already recovered aliases are automatically skipped.

## Common Workflows

### Complete Backup Workflow

```bash
# 1. Source environment variables
source .env

# 2. Create snapshots of all collections
./qdrant_backup_recovery.sh create_snap

# 3. Backup collection aliases
./qdrant_backup_recovery.sh get_colla
```

### Complete Restore Workflow

```bash
# 1. Source environment variables (pointing to destination)
source .env

# 2. Fetch snapshots from S3
./qdrant_backup_recovery.sh get_snap_s3 # or get_snap if accessing source directly

# 3. Recover all snapshots
./qdrant_backup_recovery.sh recover_snap

# 4. Recover collection aliases
./qdrant_backup_recovery.sh recover_colla
```

### Migration Between Environments

```bash
# On source environment
source .env.source
./qdrant_backup_recovery.sh create_snap
./qdrant_backup_recovery.sh get_colla

# On destination environment
source .env.dest
./qdrant_backup_recovery.sh get_snap_s3  # or get_snap if accessing source directly
./qdrant_backup_recovery.sh recover_snap
./qdrant_backup_recovery.sh recover_colla
```

### Reset and Start Fresh

```bash
# Delete all state files
./qdrant_backup_recovery.sh reset

# Or backup state files before deletion
./qdrant_backup_recovery.sh reset --bkp true
```
