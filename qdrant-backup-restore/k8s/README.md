# Kubernetes ConfigMap Management for Qdrant Backup/Restore Scripts

This directory contains tools for managing the Qdrant backup/restore script as a Kubernetes ConfigMap, allowing the script to be mounted into pods and executed within a Kubernetes cluster.

## Prerequisites

- Kubernetes Cluster
- Qdrant (self-hosted)

## Configuration

### Qdrant Setup

Ensure that Qdrant is configured to use S3 object store for snapshot storage. More information can be found [here](https://qdrant.tech/documentation/concepts/snapshots/#s3).

Important steps to note:

- **Create** S3 bucket.
  - Here you can use object storage service providers like StackIt, AWS e.t.c or a self hosted solution like [minio](https://www.min.io/).
  - Acquire the credentials to push and pull from the S3 bucket.

- Add the S3 credentials as a kubernetes secret to the cluster.
  - Using the Kubernetes secret template provided [here](config-secret.yaml) update the values accordngly.
    - For Qdrant instances without API key leave the secret as is otherwise update it.
    - Deploy the secret to the cluster.

      ````bash
      kubectl -n <namespace> apply -f config-secret.yaml
      ````

- Configure Qdrant Deployment To Use S3 snapshot storage.
  - Using the [Qdrant Helm chart](https://github.com/qdrant/qdrant-helm/tree/main/charts/qdrant) update the following configurations;
    - Add the following environment variables in the `env:` config of your the values.yaml.
      - The `secretKeyRef.name` is the name of the kubernetes secret you deployed on the previous step you can get the name from the `metadata.name` section of the secret file.
      - Update `QDRANT__STORAGE__SNAPSHOTS_CONFIG__S3_CONFIG__ENDPOINT_URL` with the endpoint url of your s3 host e.g.`https://object.storage.eu01.onstackit.cloud`,`http://minio.default.svc.cluster.local:9000` .

      ````yaml
      env:
        - name: QDRANT__STORAGE__SNAPSHOTS_CONFIG__S3_CONFIG__ACCESS_KEY
          valueFrom:
            secretKeyRef:
                name: <your-qdrant-kubernetes-secret-name>
                key: QDRANT_S3_ACCESS_KEY_ID
        - name: QDRANT__STORAGE__SNAPSHOTS_CONFIG__S3_CONFIG__SECRET_KEY
          valueFrom:
            secretKeyRef:
                name: <your-qdrant-kubernetes-secret-name>
                key: QDRANT_S3_SECRET_ACCESS_KEY
        - name: QDRANT__STORAGE__SNAPSHOTS_CONFIG__S3_CONFIG__BUCKET
          valueFrom:
            secretKeyRef:
                name: <your-qdrant-kubernetes-secret-name>
                key: QDRANT_S3_BUCKET_NAME
        - name: QDRANT__STORAGE__SNAPSHOTS_CONFIG__S3_CONFIG__ENDPOINT_URL
          value: "<your-s3-endpoint-url>"
        - name: QDRANT__STORAGE__SNAPSHOTS_CONFIG__SNAPSHOTS_STORAGE
          value: "s3"
      ````

(Re)Deploy the Qdrant cluster!

Depending on how your kubernetes cluster has been setup there are several ways to update the applications on a cluster; the most common ones is using a tool such as helm or kustomize together with a deployment pipeline tool.

**With Helm**

[Using Offical Qdrant Helm Chart](https://github.com/qdrant/qdrant-helm/tree/main/charts/qdrant)

1. Fetch helm chart

    ```bash
    helm repo add qdrant https://qdrant.github.io/qdrant-helm
    ```

2. Deploy changes

    The below command should trigger a rolling update on the qdrant nodes.

    ```bash
    helm upgrade -i <release-name> qdrant/qdrant -f <your-helm-values-file-with-above-config>
    ```

### Scripts Setup

#### Prerequistes

- In the kubernetes cluster there should be kubernetes secret with the following [template](config-secret.yaml) deployed.
- A healthy Qdrant instance.
- A config-map manifest with the following [template](configmap-script.yaml).
  - Create the config-map if its missing and deploy.

    ```bash
    kubectl -n <namespace> apply -f config-secret.yaml
    ```

  - Unless required modify the `.metadata` fields as needed.

**Backup Configuration**

- Create `Backup` job or cronjob with the job template [here](backup-job.yaml) or cronjob template [here](backup-cronjob.yaml).

Update the following environment varibles in your copy of `backup-cronjob.yaml` accordingly;

1. Update the `secretKeyRef.name` on all `env:` entries under `env.[*].valueFrom` to the name of the kubernetes secrets deployed when configuring Qdrant.
2. Update the `QDRANT_SOURCE_HOSTS` to the kubernetes service domain of the Qdrant deployment.
   - Get services and narrow down to Qdrant deployment

     ```bash
     kubectl -n <namespace> get services | grep qdrant
     ```

     alternatively use labels;

     ```bash
     kubectl get services -lapp=qdrant
     ```

   - Pick the headless service. i.e `qdrant-headless`, the `QDRANT_SOURCE_HOSTS` now becomes `http://qdrant-headless:6333` or `qdrant-headless.<namespace>.svc.cluster.local` if its in another namespace.
3. Update the `QDRANT_RESTORE_HOSTS` to `""` empty since in backup the restoration target is not needed.
4. `GET_PEERS_FROM_CLUSTER_INFO` should be `true` to discover qdrant cluster peers when backing up collections.
5. `CURL_TIMEOUT` is set at `3000` seconds. This is the max time curl will wait for request to complete. Its increased in scenarios where backup takes a while.
6. `QDRANT_S3_LINK_EXPIRY_DURATION` (script default `3600s`, i.e. 1 hour, if not set here) is the duration that an s3 presigned url will be active. The url is used during the recovery process.
7. `QDRANT_WAIT_ON_TASK` is set as `true`. This configuation make backup process synchronous meaning 'wait for snapshot process to finish successfully before moving on'. Its used during backup and recovery.
8. `BACKUP_COLLECTION_ALIASES_ON_S3` is `true` in the shipped `backup-job.yaml` (it backs up collection aliases to S3). Set to `false` if you don't want alias backup to S3. The collection_aliases are versioned by the timestamp. When `true` ensure S3 credentials are set;
      ````yaml
      env:
        - name: QDRANT_S3_ACCESS_KEY_ID
          valueFrom:
            secretKeyRef:
                name: <your-qdrant-kubernetes-secret-name>
                key: QDRANT_S3_ACCESS_KEY_ID
        - name: QDRANT_S3_SECRET_ACCESS_KEY
          valueFrom:
            secretKeyRef:
                name: <your-qdrant-kubernetes-secret-name>
                key: QDRANT_S3_SECRET_ACCESS_KEY
        - name: QDRANT_S3_BUCKET_NAME
          valueFrom:
            secretKeyRef:
                name: <your-qdrant-kubernetes-secret-name>
                key: QDRANT_S3_BUCKET_NAME
        - name: QDRANT_S3_ENDPOINT_URL
          value: "<your-s3-endpoint-url>"
        - name: BACKUP_COLLECTION_ALIASES_ON_S3
          value: "true"
      ````

Deploy the job!

```bash
kubectl -n <namespace> apply -f backup-job.yaml
```

Check the logs

```bash
kubectl -n <namespace> logs -lapp=qdrant-backup -f
```

**Restore Configuration**

- Create `Restore` job  with the job template [here](restore-job.yaml).

Update the following environment varibles accordingly;

1. Update the `secretKeyRef.name` on all `env:` entries under `env.[*].valueFrom` to the name of the kubernetes secrets deployed when configuring Qdrant.
2. Update the `QDRANT_SOURCE_HOSTS` to empty `""`.
3. Update the `QDRANT_RESTORE_HOSTS` to the target qdrant cluster service domain.
4. `GET_PEERS_FROM_CLUSTER_INFO` should be `true` for the per-shard `recover_snap_shards` task — it discovers the **target** cluster's peers via `QDRANT_RESTORE_HOSTS` (`QDRANT_SOURCE_HOSTS` stays `""` per step 2). This variable only actually affects the *legacy* dispatch path — `recover_snap_shards` itself always discovers peers this way regardless of its value. If you run the *legacy* `recover_snap` task from this same manifest, set it back to `false`: with `QDRANT_SOURCE_HOSTS=""`, legacy peer discovery has no source host to query and the job exits immediately at startup. See [RUNBOOK.md](../RUNBOOK.md) (Transition rules) for the per-shard cutover sequence.
5. `CURL_TIMEOUT` is set at `3000` seconds. This is the max time curl will wait for request to complete. Its increased in scenarios where restoration takes a while.
6. `QDRANT_S3_LINK_EXPIRY_DURATION` (script default `3600s`, i.e. 1 hour, if not set here) is the duration that an s3 presigned url will be active. The url is used during the recovery process.
7. `QDRANT_WAIT_ON_TASK` is set as `true`. This configuation make restoration process synchronous meaning 'wait for snapshot process to finish successfully before moving on'. Its used during backup and recovery.
8. `QDRANT_SNAPSHOT_DATETIME_FILTER` is empty. **Legacy `recover_snap`:** glob pattern matched against the entire snapshot name, e.g `"2026-01-29"` = all snapshots in 29th January 2026, `2026-01` = all backups in January 2026. **Per-shard `recover_snap_shards`:** different semantics — a **prefix match** against the backup set id (`YYYY-MM-DD` matches every set created that day; a full set id matches exactly one set); multiple matches select the latest, and **zero matches abort the restore** (available set ids listed on stderr) instead of silently falling back to an older set. See the main [README.md](../README.md#per-shard-datetime-filter-semantics-recover_snap_shards) for detail.
9. `MC_CONFIG_DIR` is `mc`. This overrides the default storage location ($HOME) for mc s3 client configurations. Essential in set ups that use stricter securityContext configuration like `readOnlyRootFilesystem: true`.
10. `BACKUP_COLLECTION_ALIASES_ON_S3` is `true` in the shipped `restore-job.yaml` (it fetches the latest `collection_alias` file from S3 during restoration). Set to `false` if you don't want alias recovery from S3. When `true` ensure the following S3 credentials are included. **Legacy tasks only** — per-shard restores carry aliases inside each backup manifest, ignore this flag (with a WARNING), and the S3 alias store goes stale after cutover (RUNBOOK.md, Transition rules).
      ````yaml
      env:
        - name: QDRANT_S3_ACCESS_KEY_ID
          valueFrom:
            secretKeyRef:
                name: <your-qdrant-kubernetes-secret-name>
                key: QDRANT_S3_ACCESS_KEY_ID
        - name: QDRANT_S3_SECRET_ACCESS_KEY
          valueFrom:
            secretKeyRef:
                name: <your-qdrant-kubernetes-secret-name>
                key: QDRANT_S3_SECRET_ACCESS_KEY
        - name: QDRANT_S3_BUCKET_NAME
          valueFrom:
            secretKeyRef:
                name: <your-qdrant-kubernetes-secret-name>
                key: QDRANT_S3_BUCKET_NAME
        - name: QDRANT_S3_ENDPOINT_URL
          value: "<your-s3-endpoint-url>"
        - name: BACKUP_COLLECTION_ALIASES_ON_S3
          value: "true"
      ````
11. `QDRANT_COLLECTION_ALIASES_STABLE_FILE` is `collection_aliases`. This configuration is used to override the stable version of collection_aliases file to restore. e.g. `collection_aliases-2026-04-30_18-31-04`. The file has to exist on s3. **Legacy tasks only** — ignored (with a WARNING) by the per-shard tasks.

Deploy the job!

```bash
kubectl -n <namespace> apply -f restore-job.yaml
```

Check the logs

```bash
kubectl -n <namespace> logs -lapp=qdrant-restore -f
```

**Specific recovery (per-shard)**

Per-shard restores select ONE backup set per run (a global set-id prefix filter), so a
per-collection point-in-time mix is expressed as one run per collection: pre-seed a
one-line `collections` file (`,collection_name` — the task warns that it is reusing the
existing file, which is exactly the intent) and pin `QDRANT_SNAPSHOT_DATETIME_FILTER` to
that collection's full set id (enumerate real ids with
`mc ls .../backup_manifests/<collection>/`). Repeat per collection with its own set id.
Mount the `collections` file the same way the legacy `snapshots` file is mounted below.

**Specific Recovery (legacy)**

In a situation where you want to recover specific collections, they can be provided in a csv format as follows; `host,collection_name,snapshot_name`. Host is optional so leave it empty. The values can be retrieved from S3 storage bucket and used during the restoration process. Save this csv file as `snapshots` without an extension .e.g

```text
,_default_128,_default_128-567156434043892-2026-01-29-11-44-22.snapshot
,midlib,midlib-567156434043892-2026-01-29-11-44-27.snapshot
```

Add the file as a configmap to the deployment and update the volume and volume mounts to retrieve the file in the kubernetes [job template](restore-job.yaml).

see yaml snippet below;

```yaml
          volumeMounts:
          - name: qdrant-backup-restore-script
            mountPath: /scripts/qdrant_backup_recovery.sh
            subPath: qdrant_backup_recovery.sh
          - name: qdrant-snapshots-file
            mountPath: /scripts/snapshots
            subPath: snapshots
          - name: scripts
            mountPath: /scripts
      volumes:
      - name: qdrant-backup-restore-script
        configMap:
          name: qdrant-backup-restore-script
          defaultMode: 0755
      - name: qdrant-snapshots-file
        configMap:
          name: qdrant-snapshots-file
          defaultMode: 0666
      - name: scripts
        emptyDir:
          sizeLimit: 100Mi
```

## Per-Shard Backup & Restore

Three new tasks reduce backup bucket growth from ≈3× logical data to ≈1×, add a manifest per
backup set with automatic retention, and a manifest-driven restore with built-in verification:
`create_snap_shards`, `prune_snap` (steady-state retention, or `--legacy` for the day-0
one-time unblock of old per-node snapshots), and `recover_snap_shards`. Full behavior is
documented in the main [README.md](../README.md#per-shard-backup--restore); the operational
sequence (day-0 unblock, restore procedure, verification-failure remediation, transition rules)
is in [RUNBOOK.md](../RUNBOOK.md).

**Cutover status:** `backup-cronjob.yaml` and `restore-job.yaml` ship with the per-shard env vars and
Job-policy fields already in place (S3 credentials, `MC_CONFIG_DIR`, `backoffLimit: 0`,
`activeDeadlineSeconds`, `restartPolicy: Never`, and — on the restore side —
`GET_PEERS_FROM_CLUSTER_INFO=true`), but the `args:` command in both is still the legacy task.
Flipping `create_snap` → `create_snap_shards` (and, when ready, `recover_snap` →
`recover_snap_shards`) is a deliberate, gated step — see RUNBOOK.md — not something that
happens just because the env is staged for it.

### Per-shard environment variables

These are plain `value:` entries (no secrets involved) — add any you want to override to the
`env:` block of `backup-cronjob.yaml` (for `create_snap_shards`/`prune_snap`) or `restore-job.yaml`
(for `recover_snap_shards`), the same way `CURL_TIMEOUT` already appears there. All have sane
defaults and can be omitted entirely.

```yaml
env:
  - name: QDRANT_BACKUP_RETENTION_SETS
    value: "2"
  - name: QDRANT_VERIFY_TOLERANCE_PCT
    value: "1"
  # ... any of the table rows below
```

| Variable | Description | Default |
|----------|-------------|---------|
| `QDRANT_BACKUP_RETENTION_SETS` | Per-shard backup sets to retain per collection (`create_snap_shards`'s automatic post-backup retention). `0` disables the automatic pass; a manual `prune_snap` run still clamps `0` up to `1` and prunes aggressively — see the main README for the full distinction. | `2` |
| `QDRANT_LEGACY_KEEP_RUNS` | Legacy per-node snapshots to keep per `(collection, peer_id)` for `prune_snap --legacy`. Must be an integer >= 1; `0` is rejected. | `2` |
| `QDRANT_RESTORE_FORCE` | `true` to delete + recreate a non-empty/incompatible target collection on restore (purges resume history too). Not consulted when the target is resumable and compatible — resume wins (RUNBOOK.md). | `false` |
| `QDRANT_SKIP_VERSION_CHECK` | `true` to bypass the restore version gate (same-minor / next-minor rule). | `false` |
| `QDRANT_VERIFY_TOLERANCE_PCT` | Restored point-count tolerance for restore verification, integer percentage 0-100. | `1` |
| `QDRANT_VERIFY_GREEN_TIMEOUT_SECONDS` | Max seconds to wait for collection status `green` and for the replica-set check during restore verification. Lab: ~13s for a 6-shard/RF-3 collection; scale up for real data. | `1800` |
| `QDRANT_VERIFY_POLL_INTERVAL_SECONDS` | Seconds between polls while waiting on the above. Must be >= 1. | `5` |
| `QDRANT_VERIFY_SAMPLE_POINTS` | Random points whose payloads restore verification probe-reads (batches of <= 100, Query API `sample: random`). `0` disables, loudly; see the main README for the catch-probability curve and version floor. | `300` |
| `QDRANT_SWEEP_DELETE_CAP_PCT` | Max percent of a collection's shard objects `prune_snap`'s orphan sweep may delete in one pass before aborting for manual review. | `50` |
| `QDRANT_SWEEP_GRACE_SECONDS` | Minimum object age (seconds) before the orphan sweep may delete it. Must be >= 1; under `3600` (1h) prints a warning. | `172800` (48h) |

## Contributor Configurations

### `configmap-script.yaml`

A Kubernetes ConfigMap manifest that stores the `qdrant_backup_recovery.sh` script in its `data` section.

**Important:** Do not edit the `data` section directly. Always use `config_map_updater.sh` to update the script content.

### `config_map_updater.sh`

A utility script that automatically updates the ConfigMap with the latest version of the backup/restore script from the source file.

- **yq** (YAML processor, version 4.0 or higher)
- **Bash** (version 4.0 or higher)

### Updating the ConfigMap

When you make changes to `qdrant_backup_recovery.sh`, run the unit tests first (see the main
[README.md](../README.md#running-the-tests)), then use the updater script to sync those changes
into the ConfigMap and commit both together:

```bash
# From the qdrant-backup-restore directory
./k8s/config_map_updater.sh k8s/configmap-script.yaml qdrant_backup_recovery.sh
```

**What it does:**

1. Reads the source script file
2. Injects the script content into the ConfigMap's `data` section
3. Updates the ConfigMap YAML file in-place

**Sync check** (should show no diff right after a regen):

```bash
diff <(yq eval '.data["qdrant_backup_recovery.sh"]' k8s/configmap-script.yaml) qdrant_backup_recovery.sh
```

**Optional `--git-ref <sha>`:** bakes `<sha>` into the *ConfigMap copy's* `GIT_REF` default
(`GIT_REF="${GIT_REF:-<sha>}"` — manifests' `created_by` field records this) — the source script
file on disk is never modified, and `GIT_REF` still yields to an actual `GIT_REF` env var set at
runtime if one is ever set. Omit it for local development (the default stays `"unknown"`); it is
fully backward compatible.

```bash
./k8s/config_map_updater.sh k8s/configmap-script.yaml qdrant_backup_recovery.sh --git-ref "$(git rev-parse HEAD)"
```

**CI does not no-op — it always follows up with a provenance commit, and that is intended, not
drift.** `.github/workflows/config-map-script-injector.yaml` (triggered only by pushes touching
`qdrant_backup_recovery.sh`) always passes `--git-ref "${{ github.sha }}"` — the pushed commit's
*real* sha, which a local regen can never bake in ahead of time (a commit cannot know its own
sha before it exists). So every push that changes the script gets a second, bot-authored commit
on the same branch that pins `GIT_REF` to that real sha — **even if you already committed a
correctly-regenerated ConfigMap yourself.** Your regen and CI's differ by design (yours says
`unknown`, CI's says the real sha); that one-line difference is the entire point of the flag —
provenance without needing to guess a not-yet-existent sha locally. **Pull before continuing on
the branch** after pushing a script change, or your next local operation will see "branch is
behind."

This cannot loop: the workflow's `on.push.paths` filter is only
`qdrant-backup-restore/qdrant_backup_recovery.sh`; the bot's own commit touches only
`k8s/configmap-script.yaml`, which never matches that filter, so it can never re-trigger the
workflow (confirmed by reading the workflow file directly — this is a second, independent
guard on top of GitHub's own protection against `GITHUB_TOKEN`-authored pushes re-triggering
workflow runs).

### Custom Script Name (Optional)

You can specify a custom key name in the ConfigMap:

```bash
./k8s/config_map_updater.sh k8s/configmap-script.yaml qdrant_backup_recovery.sh custom_script_name.sh
```

This is useful if you want to store multiple scripts in the same ConfigMap or use a different filename.

### Applying the ConfigMap

After updating the ConfigMap file, apply it to your Kubernetes cluster:

```bash
kubectl apply -f configmap-script.yaml
```

Or if you want to apply to a specific namespace:

```bash
kubectl apply -f configmap-script.yaml -n <namespace>
```

**Note:** The ConfigMap in the file is configured for the `pharia-ai` namespace by default. Update the `metadata.namespace` field if needed.

### Using the ConfigMap

[job](backup-job.yaml) and [cronjob](backup-cronjob.yaml) are example of how to use the `configmap-script.yaml`.
