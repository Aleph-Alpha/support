# Qdrant Backup and Restore Scripts

This directory provides production-grade scripts to back up Qdrant snapshots and restore or recover them across multiple instances, supporting migrations from n source instances to x target instances.

## Prerequisites

- **Bash** (>= 4 — the per-shard tasks use associative arrays; macOS ships Bash 3.2, install
  a newer one via Homebrew for local dev/testing. The `pharia-helper` container image ships
  Bash 5.x.)
- **curl**
- **jq** (>= 1.6 — the per-shard manifest/config-mapping jq filters use features not present in older jq;
  1.7+ is recommended for precise handling of large integers such as peer ids. The
  `pharia-helper` image ships jq 1.8.x.)
- **mc** (MinIO Client)
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

#### Required Variables For Backup

| Variable | Description | Default |
|----------|-------------|---------|
| `QDRANT_API_KEY` | Qdrant API key for authentication. Leave as is if none exists. | `your-api-key-here` |
| `QDRANT_SOURCE_HOSTS` | Comma-separated list of source Qdrant hosts | `http://localhost:6333` |
| `QDRANT_RESTORE_HOSTS` | Comma-separated list of destination Qdrant hosts set as `""` | `""` |
| `GET_PEERS_FROM_CLUSTER_INFO` | Auto-discover peers from Qdrant cluster info endpoint (only for Kubernetes) | `false` |

if `BACKUP_COLLECTION_ALIASES_ON_S3` is `true` include the S3 credentials. When `true` ensure S3 credentials are set i.e. `QDRANT_S3_SECRET_ACCESS_KEY`, `QDRANT_S3_SECRET_ACCESS_KEY`, `QDRANT_S3_ENDPOINT_URL`, `QDRANT_S3_BUCKET_NAME` (use same bucket name on qdrant configuration).

#### Required Variables For Optional Collection Aliases Backup
| Variable | Description | Default |
|----------|-------------|---------|
| `QDRANT_SOURCE_HOSTS` | Comma-separated list of source Qdrant hosts | `http://localhost:6333` |
| `QDRANT_RESTORE_HOSTS` | Comma-separated list of destination Qdrant hosts set as `""` | `""` |
| `QDRANT_S3_ENDPOINT_URL` | S3-compatible storage endpoint URL | `http://minio:9000` |
| `QDRANT_S3_ACCESS_KEY_ID` | S3 access key ID | `your-access-key` |
| `QDRANT_S3_SECRET_ACCESS_KEY` | S3 secret access key | `your-secret-key` |
| `QDRANT_S3_BUCKET_NAME` | S3 bucket name where snapshots are stored | `bucket-name` |
| `BACKUP_COLLECTION_ALIASES_ON_S3` | set `true` to toggle backing up collection aliases on S3 | `false` |

#### Required Variables For Restore

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
| `CURL_TIMEOUT` | Timeout for a SINGLE curl operation, in seconds. On the per-shard backup path, a hung peer can be retried up to ~3 times per shard before that shard's collection is abandoned — a stuck run can therefore take a multiple of this value; see `activeDeadlineSeconds` in `k8s/backup-cronjob.yaml` for the outer backstop when running as a CronJob. | `1800` (30mins) |
| `QDRANT_S3_LINK_EXPIRY_DURATION` | Presigned URL expiry duration, passed verbatim to `mc share download --expire`, hence the trailing unit suffix (`mc` requires it — a bare integer is not a valid duration for this flag) | `3600s` (1 hour) |
| `QDRANT_WAIT_ON_TASK` | Waits for changes to happen, used when creating snapshots and restoring snapshots. **Legacy tasks only** — the per-shard tasks always wait (`accepted` is never success) and print a WARNING if this is set to anything else. | `true` |
| `QDRANT_SNAPSHOT_DATETIME_FILTER` | **Legacy tasks** (`get_snap`, `get_snap_s3`, `recover_snap`): glob pattern matched against the **entire snapshot name** (so a collection name can also be used as the filter), format YYYY-mm-dd, e,g "2026-01-29-11-44", default value is empty so it will fetch every snapshot! **Per-shard `recover_snap_shards`:** different semantics — see [per-shard datetime-filter semantics](#per-shard-datetime-filter-semantics-recover_snap_shards) below; this is the same env var, read differently by the two task families. | `` |
| `QDRANT_HTTP_PORT` | This changes the default Qdrant HTTP port | `6333` |
| `MC_CONFIG_DIR` | This overrides the default storage location for mc s3 client configurations. | `$HOME` |

#### Per-Shard Variables (`create_snap_shards`, `prune_snap`, `recover_snap_shards`)

| Variable | Description | Default |
|----------|-------------|---------|
| `QDRANT_BACKUP_RETENTION_SETS` | Number of per-shard backup sets to retain per collection. `0` makes `create_snap_shards`'s automatic post-backup retention pass SKIP entirely (existing sets untouched); a **manual** `prune_snap` run with the same `0` instead clamps up to `1` and DELETES every other set — same variable, different effect by task, by design. The newest complete set is never deleted regardless of this value. | `2` |
| `QDRANT_LEGACY_KEEP_RUNS` | Legacy per-node snapshots to keep per `(collection, peer_id)` for `prune_snap --legacy` (day-0 unblock, see [RUNBOOK.md](RUNBOOK.md)). Must be an integer **>= 1** — `0` is rejected outright (it would delete every legacy snapshot in one pass, including the only proven-nothing-yet fallback); escalating to exactly `1` is a deliberate, explicit operator action taken only after a legacy restore canary passes, never a default the tool chooses for you. | `2` |
| `QDRANT_RESTORE_FORCE` | `true` to delete + recreate a non-empty or config-incompatible target collection on restore, purging its resume history (local AND the S3-mirrored durable copy) for a clean-slate restore. **Not consulted at all** when the target is resumable (matching set-scoped history) and config-compatible — resume wins in that case, loudly logged either way. See [RUNBOOK.md](RUNBOOK.md) for how to force a full redo of a resumable target. | `false` |
| `QDRANT_SKIP_VERSION_CHECK` | `true` to bypass the restore version gate (Qdrant only supports restoring a snapshot onto the same minor version or the next one). | `false` |
| `QDRANT_VERIFY_TOLERANCE_PCT` | Restored point-count tolerance for restore verification, as an **integer** percentage `0`-`100`. A non-integer or out-of-range value fails the gate closed rather than being coerced (e.g. `0.5` is rejected, not silently treated as permissive). | `1` |
| `QDRANT_VERIFY_GREEN_TIMEOUT_SECONDS` | Max seconds `recover_snap_shards` waits for collection status `green` and, separately, for the replica-set check to pass. A small 6-shard/RF-3 test collection reaches green in ~13s locally; real restores at production data volumes take minutes to tens of minutes — size this to the collection, not the small-scale number. | `1800` |
| `QDRANT_VERIFY_POLL_INTERVAL_SECONDS` | Seconds between polls while waiting on the above. Must be **>= 1**. | `5` |
| `QDRANT_VERIFY_SAMPLE_POINTS` | Number of RANDOM points whose payloads restore verification probe-reads (batches of <= 100 via the Query API's `{"query": {"sample": "random"}}`, `with_payload: true` — only a payload read touches the storage where R5b-class corruption lives). Complements the deterministic head scroll: a corrupt region covering fraction `f` of points is caught with probability `1-(1-f)^N` — ~99.99998% at `f`=5%, ~95% at `f`=1%, ~26% at `f`=0.1% for the default 300. Bounded sampling, never per-point validation; Qdrant >= 1.16 snapshot checksums remain the designated full closure. Random sampling needs Qdrant >= 1.11 and this tool's supported floor is >= 1.15, so the probe is unconditional (no version fallback). `0` disables the probes (loudly logged); non-integer values fail the restore closed. | `300` |
| `QDRANT_SWEEP_DELETE_CAP_PCT` | Max percent of a collection's `snapshots/{c}/shards/` objects `prune_snap`'s orphan sweep may delete in one pass. A would-be sweep over this cap aborts and demands manual review instead of deleting anything (sanity brake against listing bugs/permission regressions). | `50` |
| `QDRANT_SWEEP_GRACE_SECONDS` | Minimum object age, in seconds, before the orphan sweep may consider it for deletion. Must be **>= 1** (sweeping with zero grace risks deleting an in-flight backup's just-created objects, so `0` is rejected, not treated as "no grace period"); a value under `3600` (1 hour) is accepted but prints a warning that the sweep may race with an in-flight backup. | `172800` (48h) |

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

> **Legacy tasks only.** The per-shard tasks carry aliases inside each backup manifest and
> restore them as part of `recover_snap_shards` — the S3 alias store stops being refreshed
> at the last legacy `create_snap` run and goes silently stale. Do not use `recover_colla`
> for post-cutover state (see RUNBOOK.md, Transition rules).

Restores collection aliases to target hosts:

```bash
./qdrant_backup_recovery.sh recover_colla
```

**Prerequisites:** Must have `collection_aliases` file (created by `get_colla`).

**Idempotent:** Already recovered aliases are automatically skipped.

## Per-Shard Backup & Restore

Per-shard backup/restore reduces bucket growth from ≈3× logical data (one full collection
snapshot per replica, on every backup run) down to ≈1× (one snapshot per logical shard), adds a
manifest per backup set, automatic retention, and a manifest-driven restore with built-in
verification. All three tasks below are dispatched the same way as the legacy tasks above.
(The design/rationale document — "Qdrant per-shard backup design", 2026-08-10 — is maintained
outside this repo.)

**Cutover status:** the legacy tasks (`create_snap`, `recover_snap`, …) are still what the
shipped `k8s/backup-cronjob.yaml`/`k8s/restore-job.yaml` run by default — the command flip to
the tasks below is a deliberate, gated step (see [RUNBOOK.md](RUNBOOK.md)), not automatic just
because this script ships them. Every legacy task's behavior is unchanged — the ConfigMap
injector ships every merge straight to production, so legacy behavior is frozen by rule.

### create_snap_shards

Per-shard backup of every collection, then automatic retention on success:

```bash
./qdrant_backup_recovery.sh create_snap_shards
```

**What it does:**

1. Per collection, checks preconditions — every shard must have an `Active` replica, no shard
   transfers or resharding may be in flight, and sharding must be `auto` (custom sharding is out
   of scope). A violation skips **only that collection**, loudly, and the run continues with the
   rest.
2. Per shard, creates a snapshot on one Active-replica peer (round-robin across the peers that
   hold one, spreading snapshot I/O), waits for completion, and confirms the resulting S3 object
   with `mc stat`. A timeout or an `accepted` (not-yet-final) response is never treated as
   success — it is retried, and if still unconfirmed the collection's set is abandoned for this
   run (its already-created shard objects become orphans, reclaimed by `prune_snap`'s sweep
   after a grace period).
3. Only once every shard of a collection has succeeded does it upload a manifest to
   `backup_manifests/{collection}/{set_id}.json`. The manifest is what makes a backup set exist
   for restore or retention — no manifest means the set does not exist, even if some shard
   objects for it are sitting in S3.
4. After all collections are processed, if at least one set was written successfully and
   `QDRANT_BACKUP_RETENTION_SETS > 0`, runs retention (`prune_snap`, below) for the collections
   that succeeded.

Exit code is nonzero if any collection failed or was skipped — check the per-collection summary
line in the log either way.

### prune_snap

Retention for per-shard backup sets; `--legacy` switches to the day-0 emergency unblock for old
per-node snapshots instead:

```bash
./qdrant_backup_recovery.sh prune_snap            # steady-state per-shard retention
./qdrant_backup_recovery.sh prune_snap --legacy   # day-0: prune old per-node snapshots
```

**Steady-state:** for each collection, keeps the newest `QDRANT_BACKUP_RETENTION_SETS` manifests
and deletes the rest — manifest first, then that set's shard objects, so a set is never visible
to restore while half-deleted — then sweeps shard objects referenced by no manifest and older
than `QDRANT_SWEEP_GRACE_SECONDS`. The sweep refuses to delete anything (whole-collection abort)
if a listing fails, if zero manifests parse for a collection (never treated as "everything under
it is an orphan"), or if it would delete more than `QDRANT_SWEEP_DELETE_CAP_PCT` of a
collection's shard objects in one pass.

**`--legacy` (day-0 unblock):** groups old per-node snapshots by `(collection, peer_id)` and
deletes everything except the newest `QDRANT_LEGACY_KEEP_RUNS` per group. See
[RUNBOOK.md](RUNBOOK.md) for the full day-0 sequence and why the default keeps 2 generations,
not 1.

### recover_snap_shards

Manifest-driven per-shard restore with built-in verification:

```bash
./qdrant_backup_recovery.sh recover_snap_shards
```

**What it does:** selects a backup set (see the datetime-filter semantics below), runs
pre-flight checks (every shard object exists and is non-empty; restore-version gate; capacity
gate; target-collection state gate — absent / empty-or-resumable / non-empty-needs-FORCE),
creates the collection and its payload indexes if it was absent, recovers each shard from a
presigned S3 URL with durable, S3-mirrored resume support (survives pod replacement — the
shipped `restore-job.yaml` gives pods no persistent volume), recreates aliases from the
manifest, then **verifies**: collection status reaches `green`, restored point count is within
`QDRANT_VERIFY_TOLERANCE_PCT` of the manifest's, every shard has exactly the expected number of
`Active` replicas, a payload scroll and a vector search both succeed. **Exit code reflects
verification** — a restore that completes but fails verification is a failed restore.

See [RUNBOOK.md](RUNBOOK.md) for FORCE semantics, the resumable-beats-FORCE precedence rule, and
the remediation for each verification-failure mode (including the known
[qdrant#7851](https://github.com/qdrant/qdrant/issues/7851) surplus-replica issue).

### Per-shard datetime-filter semantics (`recover_snap_shards`)

`QDRANT_SNAPSHOT_DATETIME_FILTER` is read by `recover_snap_shards` too, but with **different
semantics** than the legacy tasks documented above:

- **No filter:** the latest complete backup set. If a pre-flight check finds one of its objects
  missing, falls back to the next-older complete set with a loud warning naming both sets.
- **With a filter:** a **prefix match** against the backup set id. Set ids are UTC timestamps
  with a pod-name-or-pid suffix appended (`BACKUP_SET_ID="$(date -u '+%Y-%m-%dT%H-%M-%SZ')-${HOSTNAME:-p$$}"`
  — format `YYYY-MM-DDTHH-MM-SSZ-<pod-or-pid>`, e.g.
  `2026-08-11T00-00-00Z-qdrant-backup-28114-x9k2v`, never a bare timestamp), so the documented
  `YYYY-MM-DD` form still matches every set created that day (the prefix match only needs the
  date portion); a **full** set id — suffix included — matches exactly one set. List real set
  ids with `mc ls "$QDRANT_S3_ALIAS/$QDRANT_S3_BUCKET_NAME/backup_manifests/<collection>/"`
  rather than guessing the suffix. Multiple matches select the latest among
  them (logged). **Zero matches abort the restore**, listing the available set ids on stderr — a
  filtered restore never silently substitutes an older set, because under
  `QDRANT_RESTORE_FORCE=true` that would destructively restore a point-in-time the operator did
  not choose.

This is not a glob and is not matched against a snapshot filename — it is matched against the
manifest's `backup_set_id` only.

### Per-shard restore peer discovery

**One target cluster per run:** only the FIRST `QDRANT_RESTORE_HOSTS` entry's cluster is
restored to; extra entries are ignored with a WARNING naming the count. Run once per
cluster (legacy `recover_snap`, by contrast, fanned out to every listed host).

`recover_snap_shards` always discovers the **target** cluster's peers via
`QDRANT_RESTORE_HOSTS`, unconditionally — it does not consult `GET_PEERS_FROM_CLUSTER_INFO` at
all (that variable only still affects the legacy dispatch path). If you deploy this on
Kubernetes, `k8s/restore-job.yaml` sets `GET_PEERS_FROM_CLUSTER_INFO=true` for exactly this
reason; see that file's comment if you also run the legacy `recover_snap` task from the same
manifest.

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
      - `QDRANT_SOURCE_HOSTS` - set your Qdrant source host. if you are connecting to your a qdrant cluster deployed on kubernetes use port forwarding. Ensure **all** the pods/containers can be reached locally. Add these comma seperated hosts in this config .e.g `"http://qdrant-source-1:6333,http://qdrant-source-1:6334"`. This is required only for the backup process. In Kubernetes, service/peer discovery is done automatically by enabling `GET_PEERS_FROM_CLUSTER_INFO`. **Port-forward-driven runs apply to the legacy tasks only** — the per-shard tasks discover every peer's own URI via `GET /cluster` and must reach each peer directly (see RUNBOOK.md, "Restore requirements").
      - `QDRANT_RESTORE_HOSTS` - set your Qdrant target restore host **(for restore only)** set as `""` when backing up.
      - `QDRANT_S3_ENDPOINT_URL` - set it to your s3 endpoint url.
      - `QDRANT_S3_ACCESS_KEY_ID` - set it to your s3 access key id credentials.
      - `QDRANT_S3_SECRET_ACCESS_KEY`- set it to your s3 secret access key credentials.
      - `QDRANT_S3_BUCKET_NAME`- set it to your s3 bucket name.
      - `GET_PEERS_FROM_CLUSTER_INFO`- leave as is (`false`) for non-cluster usecases. **Non-cluster (standalone) targets apply to the legacy tasks only** — the per-shard tasks require working `GET /cluster` peer discovery and exit loudly without it; there is no static-hosts mode (RUNBOOK.md, "Restore requirements").
  - Run below to make the environment variables available.

    ```bash
    source .env
    ```

  - Run the desired command.

    ```bash
    ./qdrant_backup_recovery.sh create_snap
    ```
