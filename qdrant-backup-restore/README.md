# Qdrant Backup and Restore Scripts

This directory provides production-grade scripts to back up Qdrant snapshots and restore or recover them across multiple instances, supporting migrations from n source instances to x target instances.

## Prerequisites

- **Bash**
- **curl**
- **jq**
- **mc**
- **S3 Bucket and it's credentials**

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

### TL;DR

- Jump to [deployment guide](#deployment-guide).
- Jump to [common workflows](#common-workflows).

### Qdrant Configuration

- **Create** S3 bucket.
  - Here you can use object storage service providers like StackIt, AWS e.t.c or a self hosted solution like [garage](https://garagehq.deuxfleurs.fr/), [minio](https://www.min.io/) e.t.c.
  - Acquire the credentials to push and pull from the S3 bucket.
- Update Qdrant deployment with above credentials.
  - For Kubernetes configuration continue [here](k8s/README.md#qdrant-setup).
  - For running the scripts directly;
    - Update Qdrant environment variables or the configuration yaml as stated [here](https://qdrant.tech/documentation/concepts/snapshots/#s3).

### Script Environment Variables

Create a `.env` file based on `.env.sample` with the following variables:

#### Required Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `QDRANT_API_KEY` | Qdrant API key for authentication. Leave as is if none exists. | `your-api-key-here` |
| `QDRANT_SOURCE_HOSTS` | Comma-separated list of source Qdrant hosts | `http://localhost:6333` |
| `QDRANT_RESTORE_HOSTS` | Comma-separated list of destination Qdrant hosts | `http://localhost:6334` |
| `QDRANT_S3_ENDPOINT_URL` | S3-compatible storage endpoint URL | `http://minio:9000` |
| `QDRANT_S3_ACCESS_KEY_ID` | S3 access key ID | `your-access-key` |
| `QDRANT_S3_SECRET_ACCESS_KEY` | S3 secret access key | `your-secret-key` |
| `QDRANT_S3_BUCKET_NAME` | S3 bucket name where snapshots are stored | `bucket-name` |
| `GET_PEERS_FROM_CLUSTER_INFO` | Auto-discover peers from cluster info endpoint (useful for Kubernetes) | `false` |

#### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CURL_TIMEOUT` | Timeout for curl operations in seconds, set to 30mins  | `1800` (30mins) |
| `QDRANT_S3_LINK_EXPIRY_DURATION` | Presigned URL expiry duration in seconds | `3600` (1 hour) |
| `QDRANT_WAIT_ON_TASK` | Waits for changes to happen, used when creating snapshots and restoring snapshots | `true` |
| `QDRANT_SNAPSHOT_DATETIME_FILTER` | Specify the datetime filter for snapshots to be fetched and/or restored, format YYYY-mm-dd, e,g "2026-01-29-11-44", default value is empty so it will fetch every snapshot!! | `` |
| `MC_CONFIG_DIR` | This overrides the default storage location for mc s3 client configurations. | `$HOME` |
| `QDRANT_HTTP_PORT` | This changes the default Qdrant HTTP port | `6333` |

### Example .env File

```bash
export QDRANT_API_KEY="your-qdrant-api-key"
export QDRANT_SOURCE_HOSTS="http://qdrant-source-1:6333"
export QDRANT_RESTORE_HOSTS="http://qdrant-dest:6333"
export QDRANT_S3_ENDPOINT_URL="http://minio.default.svc.cluster.local:9000"
export QDRANT_S3_ACCESS_KEY_ID="minioadmin"
export QDRANT_S3_SECRET_ACCESS_KEY="minioadmin"
export QDRANT_S3_BUCKET_NAME="qdrant-snapshots"
export GET_PEERS_FROM_CLUSTER_INFO="false"
export CURL_TIMEOUT="3000"
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

> NOTE: Updating `QDRANT_SNAPSHOT_DATETIME_FILTER` filters the snapshots that will be restored based on their datetime but can also work with collection name since glob pattern matching is applied on the entire snapshot name.

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

> NOTE: Since collection aliases are not part of snapshots created during backup, they have to be backed-up and restored separately.

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

# 3. Recover all snapshots
./qdrant_backup_recovery.sh recover_snap

# 4. Fetch collection aliases from Qdrant Source Hosts and recovers collection aliases
./qdrant_backup_recovery.sh recover_colla
```

### Migration Between Environments

```bash
# On source environment
source .env.source
./qdrant_backup_recovery.sh create_snap

# On destination environment
source .env.dest
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

## Deployment Guide

- For Kubernetes deployments kindly refer to [Kubernetes deployment documentation](k8s/README.md).
- For running scripts directly use the following steps;
  - Go through the steps in the [configuration section](#configuration).
  - Review of important configurations;
    - Ensure these configuration exist in your `.env` file.

      ```bash
      export QDRANT_API_KEY="your-qdrant-api-key"
      export QDRANT_SOURCE_HOSTS="http://qdrant-source-1:6333"
      export QDRANT_RESTORE_HOSTS="http://qdrant-dest:6333"
      export QDRANT_S3_ENDPOINT_URL="http://minio.default.svc.cluster.local:9000"
      export QDRANT_S3_ACCESS_KEY_ID="minioadmin"
      export QDRANT_S3_SECRET_ACCESS_KEY="minioadmin"
      export QDRANT_S3_BUCKET_NAME="qdrant-snapshots"
      export GET_PEERS_FROM_CLUSTER_INFO="false"
      export CURL_TIMEOUT="300"
      ```

    - Update the following configurations;
      - `QDRANT_API_KEY` - set your Qdrant api key if it exists otherwise leave as is.
      - `QDRANT_SOURCE_HOSTS` - set your Qdrant source host. if you are connecting to your a qdrant cluster deployed on kubernetes use port forwarding. Ensure **all** the pods/containers can be reached locally. Add these comma seperated hosts in this config .e.g `"http://qdrant-source-1:6333,http://qdrant-source-1:6334"`. This is required only for the backup process. In Kubernetes, service/peer discovery is done automatically by enabling `GET_PEERS_FROM_CLUSTER_INFO`.
      - `QDRANT_RESTORE_HOSTS` - set your Qdrant target restore host.
      - `QDRANT_S3_ENDPOINT_URL` - set it to your s3 endpoint url.
      - `QDRANT_S3_ACCESS_KEY_ID` - set it to your s3 access key id credentials.
      - `QDRANT_S3_SECRET_ACCESS_KEY`- set it to your s3 secret access key credentials.
      - `QDRANT_S3_BUCKET_NAME`- set it to your s3 bucket name.
      - `GET_PEERS_FROM_CLUSTER_INFO`- leave as is for non-kubernetes usecases.
  - Run below to make the environment variables available.

    ```bash
    source .env
    ```

  - Run the desired command.

    ```bash
    ./qdrant_backup_recovery.sh create_snap
    ```
