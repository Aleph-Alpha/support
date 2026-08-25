# Qdrant Per-Shard Backup & Restore — Runbook

Operational procedures for the per-shard backup/restore tasks (`create_snap_shards`,
`prune_snap`, `recover_snap_shards`) added to `qdrant_backup_recovery.sh`. This document is
the "what to run and what to check" companion to [README.md](README.md) /
[k8s/README.md](k8s/README.md) (the reference docs). Written to be followed under incident
pressure — every step names its exact command and its pass/fail gate; do not skip a gate to
save time.

## Before you start

- **Confirm your `kubectl` context and namespace before running anything**, especially before
  the CronJob cutover and the restore canary. Context mix-ups under pressure are how incidents
  become worse incidents — `kubectl config current-context` and `kubectl config view --minify`
  are cheap; a command run against the wrong cluster is not undoable after the fact.
- **Confirm which cluster your shell's env vars point at** before running any command below —
  `QDRANT_SOURCE_HOSTS`/`QDRANT_RESTORE_HOSTS` and `QDRANT_S3_*` determine which cluster and
  which bucket you touch. `echo "$QDRANT_SOURCE_HOSTS $QDRANT_RESTORE_HOSTS $QDRANT_S3_BUCKET_NAME"`
  before anything destructive.
- All commands below assume you are in `qdrant-backup-restore/` with `.env` sourced (see
  [README.md](README.md#installation)), or running inside the deployed container at `/scripts`.
- `check_dependencies` (bash, curl, jq, mc) runs automatically at the top of every task and
  exits loudly if something is missing — you do not need to check this by hand.
- **Never use full-storage snapshots (`POST /snapshots`) on a distributed cluster** — they are
  not restorable there by design; this tool's per-shard flow is the supported path.

## Day-0 unblock sequence

The customer-prod incident this tool addresses: the S3 bucket is full of legacy per-node
snapshots (≈3× logical data per backup run, no retention), so the very first per-shard backup
run cannot succeed until space is freed. Follow these steps **in order**; each has its own gate
before you move to the next.

### Step 1 — free legacy space

```bash
./qdrant_backup_recovery.sh prune_snap --legacy
```

Groups legacy per-node snapshots by `(collection, peer_id)` (their filenames embed both; there
is no shared timestamp across a legacy run, so grouping by peer is the only decidable rule) and
deletes everything except the newest `QDRANT_LEGACY_KEEP_RUNS` per group (default **2** — never
1 by default; see "why 2, not 1" below). Never touches `shards/` or `backup_manifests/` keys —
legacy-format objects only.

**Run with the normal backup env, this only sees collections that still exist in Qdrant.**
`prune_snap` discovers which collections to prune by asking the live cluster whenever
`QDRANT_SOURCE_HOSTS` is non-empty — exactly the case for the normal backup env this step
assumes. A collection that has since been deleted or renamed (the customer's cluster has a
suspected recreate history, 6→12 shards) is invisible to that discovery, so its legacy
snapshots are silently skipped — precisely the dead weight a full-bucket incident most wants
gone. **To also reclaim legacy snapshots of deleted/renamed collections, re-run with
`QDRANT_SOURCE_HOSTS=""`** so discovery lists the bucket directly instead of the live cluster:

```bash
export QDRANT_SOURCE_HOSTS=""
./qdrant_backup_recovery.sh prune_snap --legacy
```

**Gate:** exit code `0`, and enough space freed for Step 2 (a full per-shard set is ≈1×
logical data per collection). Check bucket usage before and after:

```bash
mc du "qdrant_s3_snapshot/$QDRANT_S3_BUCKET_NAME"   # run before AND after Step 1, compare
```

If insufficient:

- **Do not** set `QDRANT_LEGACY_KEEP_RUNS=1` yet. Run a **legacy** restore canary first — restore
  the *current newest* legacy snapshot for your smallest collection into an isolated cluster and
  verify it — **then**, only after that passes:

  ```bash
  export QDRANT_LEGACY_KEEP_RUNS=1
  ./qdrant_backup_recovery.sh prune_snap --legacy
  ```

  Why 2 is the default and 1 is an explicit escalation, never a default: no legacy run has ever
  passed a restore verification (qdrant#6348 shows snapshot corruption that only surfaces at
  restore time) — keeping 2 generations means the newest one is never the *only* fallback before
  anything is proven restorable. `QDRANT_LEGACY_KEEP_RUNS=0` is rejected outright (not clamped)
  — it would delete every legacy snapshot in one pass, including the only backups that currently
  exist.

### Step 2 — shadow run of the per-shard backup

Run `create_snap_shards` as a one-off Job **alongside** the still-untouched legacy CronJob (do
not stop or modify the legacy cron for this step):

```bash
./qdrant_backup_recovery.sh create_snap_shards
```

(As a Job manifest: copy `k8s/backup-job.yaml`, change its `args` to
`create_snap_shards`, keep the S3 env vars, and `kubectl apply` it once. Do not touch
`backup-cronjob.yaml` yet — that is Step 4.)

This writes **only** new-format objects (`snapshots/{c}/shards/{sid}/…` +
`backup_manifests/{c}/{set_id}.json`) — it never reads or deletes anything legacy. Validates
real timing and size at true scale.

**Gate:** exit code `0`; the per-collection summary line names 0 failed/skipped collections;
per collection, **at least** `shard_number` shard objects under `snapshots/{c}/shards/` (Qdrant
may write a `.checksum` companion per shard — `delete_backup_set`'s own best-effort cleanup
exists for exactly that, so up to 2× `shard_number` is normal, not a sign of trouble) **plus
exactly one** new manifest, which lives at a *different* prefix —
`backup_manifests/{c}/`, never under `snapshots/{c}/`:

```bash
mc ls -r "qdrant_s3_snapshot/$QDRANT_S3_BUCKET_NAME/snapshots/<c>/shards/" | wc -l
mc ls    "qdrant_s3_snapshot/$QDRANT_S3_BUCKET_NAME/backup_manifests/<c>/"
```

**Troubleshooting — backup fails with shard objects missing from S3:** the tool's per-shard
layout check (`mc stat` of every observed key) failing right after a snapshot call that
Qdrant itself reported `ok` usually means Qdrant never actually loaded the S3 snapshot config
— a mis-mounted or mis-keyed config file makes it **silently fall back to local disk**
(qdrant#5026 class), so the snapshots land on the node's filesystem and never appear in the
bucket. The layout check is the detector; verify the mounted `snapshots_storage: s3` config
on every node before retrying.

**IDST checklist:** validate multipart snapshot upload against the **customer's actual S3
provider**, not just MinIO — some S3-compatibles reject Qdrant's multipart uploads outright
(qdrant#4701 class); this shadow run is the first time Qdrant's own S3 client meets that
provider at real object sizes. Also confirm the provider keeps **ETags stable for unmodified
objects at rest** — the restore pre-flight's integrity comparison depends on it, and any
bucket migration that rewrites objects (an `rclone sync`, a storage-class transition)
invalidates every schema-2 set's pre-flight; take a fresh backup after one. Confirmed
empirically on STACKIT: an `mc cp` of a shard object back into place (even byte-identical)
yields a plain-MD5 ETag where Qdrant's original was a multipart ETag (`…-N`), so that set's
pre-flight fails and the restore falls back to the next older complete set — never hand-copy
shard objects; if you must, re-run the backup afterwards so the manifest is re-recorded.

### Step 3 — restore canary

**First proof a restorable backup exists.** Restore the smallest prod collection from the real
bucket (read-only against the source) into an **isolated** cluster pinned to the same Qdrant
version as prod — never the prod cluster itself:

```bash
export QDRANT_SOURCE_HOSTS=""
export QDRANT_RESTORE_HOSTS="http://qdrant-canary-headless:6333"   # isolated cluster — NOT prod
# single var, used for BOTH clusters — must be the CANARY's key here, not prod's (S3 creds
# correctly stay prod's below: the restore reads the prod bucket, only the target Qdrant
# cluster is the canary)
export QDRANT_API_KEY="<canary cluster api key>"
export GET_PEERS_FROM_CLUSTER_INFO="true"
export QDRANT_SNAPSHOT_DATETIME_FILTER=""     # or a specific set id to pin a known set
./qdrant_backup_recovery.sh recover_snap_shards
```

**Gate:** exit code `0`, and the log shows `VERIFIED` for the collection (status green, point
count within tolerance, replica sets correct, scroll + vector smoke both passed — see
"Verification failures and remediation" below for what to do if any single check fails instead).

**Run the canary cluster at RF ≥ 2** so the replica-set verification layer stays active — at
RF 1 that layer is trivially satisfied and only the integrity layers (the manifest etag/size
pre-flight and the deep payload smoke scroll) stand between a corrupted shard archive and a
VERIFIED verdict (live-reproduced: Qdrant v1.15.1 accepts corrupted shard snapshots —
qdrant#3372 — and at RF 1 a pre-hardening restore certified one VERIFIED).

This becomes the **quarterly canary** thereafter — do not treat it as a one-time checkbox.

### Step 4 — CronJob cutover

Only after Steps 1–3 have passed. This repo's `k8s/backup-cronjob.yaml` carries the per-shard
ENV staged (S3 credentials, `MC_CONFIG_DIR`) but deliberately keeps the LEGACY Job policy —
the cutover is the command flip PLUS the three Job-policy values, applied together:

```diff
              args:
                - -c
-                - "cd scripts && ./qdrant_backup_recovery.sh create_snap"
+                - "cd scripts && ./qdrant_backup_recovery.sh create_snap_shards"
```

and in the same edit set `backoffLimit: 0`, `restartPolicy: Never`, and
`activeDeadlineSeconds: 7200`. Why together: per-shard exits nonzero on any partial failure
while still pruning the collections that succeeded, so a retrying Job (`backoffLimit > 0` or
`OnFailure`) can create+prune several sets back-to-back within ONE firing and collapse
retention history to near-duplicates minutes apart; conversely those values must never apply
while the legacy command still runs (legacy relies on retries and has no runtime ceiling).

**Pre-flight gate — before touching anything, confirm the deployed secret is ready:**

```bash
kubectl -n <namespace> get secret qdrant-credentials -o jsonpath='{.data}' | jq 'keys'
# expect all four: QDRANT_API_KEY, QDRANT_S3_ACCESS_KEY_ID, QDRANT_S3_SECRET_ACCESS_KEY, QDRANT_S3_BUCKET_NAME
```

**Do not `kubectl apply -f k8s/backup-cronjob.yaml` straight from this repo onto a customized
deployment.** This file carries repo placeholders — `QDRANT_SOURCE_HOSTS:
"http://qdrant-headless:6333"`, `QDRANT_S3_ENDPOINT_URL: "<your-s3-endpoint-url>"` (not a real
URL), and the secret name `qdrant-credentials` — and `apply` replaces the entire `env:` list, so
a site that customized its headless-service name or S3 endpoint would have those values
**reverted to placeholders**, and the first per-shard firing would fail at `mc alias set`. **Port the
command flip + Job-policy trio above, together with the env additions staged in this file,
into your site's own deployed manifest or values overlay, then apply *that*.**

This single swap also activates automatic retention (`create_snap_shards` runs `prune_snap`'s
retention pass on every successful run) — there is no separate retention deploy step.

**Gate:** the first scheduled firing completes with exit `0`; check
`kubectl -n <namespace> logs -lapp=qdrant-backup` for the per-collection summary and the
retention pass output.

**Job success semantics flip at this cutover.** The legacy backup job exited `0` even when
every collection failed — a green Job history from before the cutover may conceal partial
failures, so do not treat it as a baseline. The per-shard task fails the Job loudly on any
collection failure; expect alerting baselines to change the day you flip.

**Ongoing gate, not one-time:** `backoffLimit: 0` means a single transient pod failure (node
drain, OOMKill, …) loses that entire firing with zero retries, and the next attempt is a full
schedule interval away. Before you consider the cutover done, add monitoring on either signal:

```bash
# CronJob's last successful completion aging past one schedule interval
kubectl -n <namespace> get cronjob qdrant-backup -o jsonpath='{.status.lastSuccessfulTime}'
# any Job carrying the backup label with a failed pod
kubectl -n <namespace> get jobs -lapp=qdrant-backup -o jsonpath='{.items[*].status.failed}'
```

If you also intend to cut restores over to `recover_snap_shards`, see "Launching a restore in
Kubernetes" under Restore procedure below — it is a manually-invoked Job, not scheduled, so
there is no fixed "cutover moment" for it.

### Step 5 — per-collection legacy prune

**Per collection, not blanket.** Once — and only once — a given collection has itself passed a
verified per-shard restore (the canary in Step 3 covers the collection it restored; every other
collection needs its own verified restore before its legacy objects are pruned below the
retained generations — never prune the last legacy fallback of anything unproven):

```bash
./qdrant_backup_recovery.sh prune_snap --legacy
```

Re-running this normally (default `QDRANT_LEGACY_KEEP_RUNS=2`) is safe to do broadly, since it
never deletes the *last* two generations. The gate that matters is conceptual, not a flag: don't
treat "the mechanism works for collection A" as license to stop caring about legacy fallback
depth for collections B, C, … until each has its own verified restore.

## Restore procedure

**Target collection state determines what happens — check which row applies before you set
any flag:**

| Target collection state | What `recover_snap_shards` does | Flags needed |
|---|---|---|
| Absent | Creates it from the manifest, then recovers every shard. | None. |
| Exists, empty, **or** non-empty with resume history matching THIS exact set id | Resumes — creation skipped, only shards not yet recovered are recovered. | None. |
| Exists, non-empty, no matching history for this set (or config-incompatible) | Aborts. | `QDRANT_RESTORE_FORCE=true` — destructive: deletes and recreates the collection. |

**Launching a restore in Kubernetes.** The per-shard restore ships as its own
internally-consistent manifest — no field flipping required:

```bash
kubectl -n <namespace> create -f k8s/restore-per-shard-job.yaml
```

(`k8s/restore-job.yaml` remains the fully-legacy `recover_snap` manifest for legacy-era
snapshots; the two are independent and each runs its own default command as shipped.)

**Restore requirements — per-shard restore has no static-hosts mode.** `recover_snap_shards`
hard-requires (a) a **cluster-mode** target whose `GET /cluster` peer discovery works on the
first `QDRANT_RESTORE_HOSTS` entry, and (b) **direct reachability of every discovered peer
URI** from wherever the script runs — each shard is recovered against its placed peer's own
URL. There is no fallback that treats the listed hosts as the peer set, so per-shard sets
cannot be restored into a standalone/cluster-disabled Qdrant, from outside the cluster
network (e.g. an operator laptop over a single port-forward), or when `/cluster` itself is
broken; the legacy static-hosts flow still exists but **cannot see per-shard sets** by
design. Run restores from inside the cluster network (the shipped Job does). A
discovery-fallback (use the listed hosts as peers when discovery is unavailable) needs an
upstream spike into shard-snapshot recovery on cluster-disabled nodes first — tracked as a
follow-up, not shipped here.

**One target cluster per run.** `recover_snap_shards` restores to the FIRST
`QDRANT_RESTORE_HOSTS` entry's cluster only; extra entries are ignored (a WARNING names the
ignored count). To restore the same sets into several clusters, run once per cluster —
unlike legacy `recover_snap`, which fanned every snapshot out to every listed host.

**Restore capacity planning — local disk on the target nodes, even with S3 storage:** shard
recovery downloads the **full shard archive to the target node's local disk**
(`snapshots_path`/tmp) before unpacking it — `snapshots_storage: s3` does not change this
(measured live: an in-container staging probe plus Qdrant's own unpack-error paths both show
the archive landing under `snapshots_path/tmp/…download…`; creation, by contrast, streams to
S3 with no observed local staging). Plan free disk **≥ the largest shard archive on every
restore-target node** before starting a restore.

### Environment variables

| Variable | Restore-relevant notes |
|----------|-------------------------|
| `QDRANT_RESTORE_HOSTS` | Target cluster. `QDRANT_SOURCE_HOSTS` stays `""`. |
| `GET_PEERS_FROM_CLUSTER_INFO` | `true` — but note `recover_snap_shards` always discovers peers via `QDRANT_RESTORE_HOSTS` regardless of this var's value (it is only consulted by the legacy dispatch path). |
| `QDRANT_SNAPSHOT_DATETIME_FILTER` | Set selection — see below. |
| `QDRANT_RESTORE_FORCE` | `true`/`false`. See "FORCE semantics" below — **not always consulted**. |
| `QDRANT_SKIP_VERSION_CHECK` | `true` to bypass the same-minor/next-minor version gate. |
| `QDRANT_VERIFY_TOLERANCE_PCT` | Integer 0–100. Non-integer or out-of-range values fail the restore closed, not permissively. |
| `QDRANT_VERIFY_GREEN_TIMEOUT_SECONDS` / `QDRANT_VERIFY_POLL_INTERVAL_SECONDS` | Poll budget for the green-status and replica-set waits. See "Time-to-green expectations" below for sizing. |
| `QDRANT_S3_LINK_EXPIRY_DURATION` | Presigned-URL lifetime, **per shard** (each shard is presigned separately at recover time, so the budget is per shard, not per run) — passed verbatim to `mc share download --expire`, so the unit suffix is required (default `3600s`). Raise it for multi-GB shards on slow S3 — see "Presigned-URL expiry" below. |

Full per-shard env var reference (all defaults, including the backup/prune-side vars): see
[README.md](README.md#script-environment-variables).

### Collection names longer than 91 characters are skipped (unrestorable)

Qdrant's URL-based shard recovery writes the download to a temp file named
`<snapshot-name>-XXXXXX.downloadXXXXXX`, and the snapshot name Qdrant generates already contains
the collection name — so the collection name appears twice and, above 91 characters, the path
exceeds the 255-byte filesystem limit (`File IO error: File name too long (os error 36)`). Found on
ba-pre-prod with a 96-character Assistant-generated collection
(`<App>_<Collection>_<Index>-<id>` names routinely reach 80-100 chars). The backup task therefore
refuses such collections up front (`SKIP <c>: collection name too long to be restorable`) instead of
writing a backup that can never be restored. Remedies: rename/shorten the collection at the
application layer, or restore via Qdrant's upload endpoint (different temp naming) — an upload-based
fallback for long names is a tracked follow-up; the limit itself is upstream (Qdrant).

### Set selection semantics

- **No filter:** the latest complete backup set. If the pre-flight finds one of its objects
  missing, empty, or failing the etag/size identity check (schema-2 manifests), falls back one
  set at a time — with a loud warning naming both sets — and every fallback candidate gets the
  **same** pre-flight before being committed to; a failing candidate is skipped loudly.
- **With a filter (`QDRANT_SNAPSHOT_DATETIME_FILTER`):** a **prefix match** against the backup
  set id — format `YYYY-MM-DDTHH-MM-SSZ-<pod-or-pid>` (the script appends a pod-name-or-pid
  suffix: `BACKUP_SET_ID="$(date -u '+%Y-%m-%dT%H-%M-%SZ')-${HOSTNAME:-p$$}"`; a real id looks
  like `2026-08-11T00-00-00Z-qdrant-backup-28114-x9k2v`, never a bare timestamp). `"2026-08-10"`
  still matches every set created that day (the prefix match only needs the date portion, not
  the suffix); the **full** set id — suffix included — matches exactly one set. Multiple
  matches select the latest among them (logged). **Zero matches abort the restore** — available
  set ids are listed on stderr. A filtered restore never silently substitutes an older set:
  under `QDRANT_RESTORE_FORCE=true` that would destructively restore a point-in-time you did
  not choose.

  **List the real set ids before filling in any `<set_id>` placeholder below — never guess the
  suffix:**

  ```bash
  mc ls "qdrant_s3_snapshot/$QDRANT_S3_BUCKET_NAME/backup_manifests/<collection>/"
  ```

- **Resuming a failed restore:** pin `QDRANT_SNAPSHOT_DATETIME_FILTER` to the exact set id of
  the run you are resuming (read it from that run's log). Resume history is scoped to one set
  id — with no filter, a set created since your failed run (e.g. the backup CronJob fired in
  between) is selected instead, your progress no longer matches, and the run aborts asking for
  `QDRANT_RESTORE_FORCE=true` — which would then **delete the partially-restored collection**.
- **If every set fails pre-flight:** each fallback candidate is object-pre-flighted before
  being committed to (existence, size, and the schema-2 etag/size identity check), so damage
  to the older sets surfaces at pre-flight — each failing candidate is named and skipped
  loudly until either a candidate passes or the restore aborts with
  `set <id> incomplete and no older set available`. An unfiltered re-run re-walks the same
  chain; nothing self-heals. If you know a specific good set (for example one taken after the
  damage window), pin `QDRANT_SNAPSHOT_DATETIME_FILTER` to that **known-good** set id — the
  escape hatch is unchanged (enumerate real set ids with the `mc ls` command above).

### FORCE semantics, and the resumable-beats-FORCE rule

`QDRANT_RESTORE_FORCE=true` means: **DELETE the target collection, recreate it from the
manifest, and purge all resume-history entries for `(target, collection)` — both the local file
and the S3-mirrored durable copy.** A clean-slate restore. FORCE never overwrites in place and
never "skips the check" quietly.

**But FORCE is not always consulted.** If the target collection already exists, is
config-compatible (same `shard_number`, same vector params), and is *either* empty *or* carries
matching resume history for the **exact selected set id**, the restore takes the resume path —
it skips collection creation and continues recovering only the not-yet-recovered shards. This
happens **even if `QDRANT_RESTORE_FORCE=true` is set** — resume wins over FORCE whenever both
could apply, because resume preserves progress toward the *same* data FORCE would otherwise
destroy and redo from scratch. This is logged either way, so it is never a silent surprise; it
is not a bug to work around, it is the documented precedence.

### Forcing a full redo of a resumable target

If you genuinely want to discard existing progress and redo a restore that keeps resuming
instead of restarting, you have two options — pick based on whether you want the collection
gone entirely or just want FORCE to actually apply:

**Option A — delete the collection out-of-band (simplest; no FORCE needed afterward).** A
just-deleted collection is "absent" on the next run, which is its own case in the state gate and
**also** purges resume history unconditionally (a collection that does not exist cannot have any
actually-recovered shards) — the next `recover_snap_shards` run starts genuinely fresh with no
special flags. This command takes a **single** host — if `QDRANT_RESTORE_HOSTS` holds a
comma-separated list, pick one entry:

```bash
TARGET=${QDRANT_RESTORE_HOSTS%%,*}
curl -X DELETE "$TARGET/collections/<collection>?wait=true" \
  --header "api-key: $QDRANT_API_KEY"
./qdrant_backup_recovery.sh recover_snap_shards
```

**Option B — delete just the mirrored resume state out-of-band, then use FORCE.** Keeps the
collection as-is but removes the S3-mirrored history for that specific `(collection, set_id)`,
so the next run can no longer classify it as "resumable" — it lands in the non-empty/needs-FORCE
case, and `QDRANT_RESTORE_FORCE=true` is now genuinely consulted:

```bash
# ephemeral mc config — do not leave prod S3 creds sitting in ~/.mc on this host
export MC_CONFIG_DIR="$(mktemp -d)"
mc alias set qdrant_s3_snapshot "$QDRANT_S3_ENDPOINT_URL" "$QDRANT_S3_ACCESS_KEY_ID" "$QDRANT_S3_SECRET_ACCESS_KEY"
mc rm "qdrant_s3_snapshot/$QDRANT_S3_BUCKET_NAME/restore_state/<collection>/<set_id>.csv"
export QDRANT_RESTORE_FORCE=true
./qdrant_backup_recovery.sh recover_snap_shards
```

(Alternatively, `mc alias remove qdrant_s3_snapshot` when done, if you'd rather clean up
afterward than isolate the config directory up front.)

If you are running this from a **persistent shell** rather than a fresh Job pod (a fresh pod's
local workdir is already empty), also run `./qdrant_backup_recovery.sh reset` first — the local
resume-history file from an earlier invocation in the same session would otherwise still carry
the old "already recovered" lines even after the S3 copy is gone.

**A third option — switch the set filter** — restores a *different* available set instead of
re-attempting the same one (still requires FORCE if the target is non-empty and has no history
for that different set, which is the normal case). Use this when you specifically want an older
set's data, not as a generic "start over" trick for the same set.

## Verification failures and remediation

`recover_snap_shards`'s exit code reflects verification, not just whether the recover calls
succeeded — a restore that completes every shard but fails a check below is a **failed restore**
(nonzero exit). Each failure mode below is independent; fix the one that actually failed rather
than reflexively re-running the whole restore.

**Trust the tool's verdict line, never the cluster color.** Qdrant reported `status: green` in
**every** broken state the edge-case reproduction session produced — a partial restore
(2027/3000 points), Dead replicas, and a shard whose payload storage panicked on every read.
A dashboard keying on green will miss all of them; the final `VERIFIED` /
`verification failed` line is the health signal.

### Replica surplus (qdrant#7851)

Symptom in the log: `replica set verification failed:` followed by a line like
`shard 3: 4 replicas (3 Active, 1 Partial, 0 other), expected 3 Active`. This is a known Qdrant
issue (cluster restore can create a surplus `Partial` replica beyond the expected replication
factor; **fixed upstream in v1.17.1**, though the issue remains open — this remediation
section applies to versions **< v1.17.1**) — it is detected, not automatically remediated
(out of scope for the initial per-shard release).
Find the surplus replica, then drop it. These commands take a **single** host — if `QDRANT_RESTORE_HOSTS` holds
a comma-separated list, pick one entry:

```bash
TARGET=${QDRANT_RESTORE_HOSTS%%,*}

# 1. find which peer holds the Partial replica for the affected shard. local_shards entries
#    carry no peer_id of their own — the RESPONDING peer's own id is the sibling top-level
#    field .result.peer_id; remote_shards entries already have theirs. local_shards is always
#    relative to whichever peer answered, so query each peer if the first response shows
#    nothing.
curl -s "$TARGET/collections/<collection>/cluster" \
  --header "api-key: $QDRANT_API_KEY" \
  | jq '.result | .peer_id as $self
        | [ (.local_shards[] | . + {peer_id: $self}), (.remote_shards[]) ]
        | map(select(.state == "Partial"))'

# 2. drop it (shard_id and peer_id from the query above)
curl -X POST "$TARGET/collections/<collection>/cluster" \
  --header "api-key: $QDRANT_API_KEY" --header "Content-Type: application/json" \
  --data '{"drop_replica": {"shard_id": <sid>, "peer_id": <peer_id>}}'
```

Re-run `recover_snap_shards` (it will resume — the shards that already verified stay verified)
or just re-run verification by re-invoking the same command; the replica-set check is retried
automatically within the poll budget before it is reported as failed, so if you see this message
at all, the surplus replica did not resolve itself within `QDRANT_VERIFY_GREEN_TIMEOUT_SECONDS`.

### Count-check failures

Symptom: `verification failed for <collection>: point count outside tolerance`. The restored
point count must be within `QDRANT_VERIFY_TOLERANCE_PCT` (default 1%) of the manifest's
recorded `points_count`. Two distinct situations produce this message:

- **Transient, already handled:** collection status can reach `green` a beat before the point
  count fully converges. The count check is automatically re-polled within the remaining
  verification budget (same budget as the green-status wait) — you do not need to do anything
  for this case; it resolves on its own within a few polling intervals.
- **Persistent, needs investigation:** if the message appears after the **full** budget is
  exhausted, it is a real discrepancy — most likely one of: a shard genuinely failed to recover
  data despite the recover call reporting success (check the per-shard log lines for that
  collection), the manifest's `points_count` is stale relative to heavy concurrent writes at
  backup time (cross-shard skew is accepted up to the tolerance by design, but a very active
  collection can exceed it), or `QDRANT_VERIFY_TOLERANCE_PCT` is set tighter than the write
  traffic justifies. Do not raise the tolerance reflexively to make the symptom go away —
  confirm which of these it actually is first.

  **Sets taken under sustained writes systematically under-restore:** the manifest's
  `points_count` is a fresh read taken **after** the per-shard snapshot loop, so under a
  steady write load the restored count lands **below** it by roughly write-rate ×
  loop-duration. Because that drift is time-based, not size-based, **small collections
  routinely exceed the 1% default tolerance** — measured live: a ~12.6k-point collection
  backed up under ~890 points/s came back 1.14% short and was correctly refused at the
  default tolerance (measured in the live compose lab). Either back up in a low-write
  window, or accept the skew **deliberately** with the documented
  `QDRANT_VERIFY_TOLERANCE_PCT` override on the restore — after confirming the delta is
  write-drift and not a failed shard.

### Alias recreation failures

Symptom: `restore of <collection> from set <set_id> FAILED: alias recreation did not fully
succeed (points=…, manifest=…, tolerance=…%)`. **By the time you see this message, data
verification has already PASSED** — status went green, the point count and replica sets
checked out, and both smoke tests succeeded. Aliases are checked first internally but reported
last and enforced at the very end, specifically so a genuine data problem is never masked by an
unrelated alias one and vice versa (the "exit code reflects verification" rule covers aliases
too — a collection whose data is fine but whose aliases didn't come back is not a fully
successful restore). The restore still exits nonzero; do not treat "the data part passed" as
good enough to ignore it.

Look one step earlier in the log for which of the two alias failure modes you hit:

- **`WARNING: N/M collection alias(es) failed to recover for <collection>`** — a summary count;
  look further up for the specific alias(es) named.
- **`REFUSING to repoint live alias <alias> from <owner> to <collection> (set
  QDRANT_RESTORE_FORCE=true to override)`** — the alias-theft guard fired: the manifest wants to
  point `<alias>` at this collection, but it currently points at a *different*, live collection
  (`<owner>`). This is a safety refusal, not a bug — Qdrant itself will happily repoint an alias
  on request, so the guard exists specifically to stop a restore from silently stealing an alias
  out from under whatever else is currently using it. The log line already tells you the fix:
  set `QDRANT_RESTORE_FORCE=true` if you actually want this restore to take over the alias, and
  re-run. Since every shard already recovered successfully on the run that hit this message,
  the re-run's own target is resumable for this set — resume wins over FORCE at the state gate
  (see "FORCE semantics" above), so this does **not** delete or recreate the
  already-verified collection; FORCE only changes the alias-theft guard's own decision.
  Verification (green/count/replica/smoke) still re-runs on the re-run — harmlessly, as a
  re-confirmation, not a mutation. One deliberate side effect: under FORCE the object
  pre-flight exempts **nothing** — every shard object is etag/size-checked even though the
  resume will skip re-recovering them — so if the set's bucket objects were damaged since the
  restore, this re-run aborts at pre-flight instead of resuming. That abort is the tool
  telling you the backup set itself is damaged at rest: take a fresh backup, and repoint the
  alias by hand if you need it before then.

### Time-to-green expectations

`QDRANT_VERIFY_GREEN_TIMEOUT_SECONDS` (default 1800s / 30 min) is the budget for both the
green-status wait and the replica-set retry. Measured numbers (ba-pre-prod, Qdrant 1.15.1,
STACKIT S3, 3-node cluster): a 6-shard RF-3 collection with 5 000 points restores and verifies
in ~30 s; a **1 000 000-point, 3-shard RF-2 collection with ~2 GiB shards** (1.85 / 2.13 /
1.96 GiB) took **12 m 33 s** end to end — 2.6–4.0 min per shard for presigned download, unpack
and load, then green wait, count, replica sets, payload probes and search. Extrapolate per
shard, not per collection: a 40 GB / 12-shard production collection (~3.3 GiB shards) is
~8 min per shard sequentially, i.e. plan on the order of 1.5–2 h for the full restore and set
`QDRANT_VERIFY_GREEN_TIMEOUT_SECONDS` accordingly. qdrant#5857 documents dead shards and
cleanup errors at 37 GB; watch the first production-scale restore closely rather than trusting
any default blindly.

### Presigned-URL expiry

A per-shard object can be several GB at production scale, and `get_s3_url_for_key` presigns
each shard's URL *individually* at the point it is recovered (not once for the whole run) —
this significantly mitigates the risk, but a slow or throttled S3 backend can still push a
single shard's transfer past the expiry window. Measured on ba-pre-prod against STACKIT S3:
a 2.13 GiB shard recovered in 4 min, i.e. the default `3600s` window carried a >7× margin at
~2 GiB and covers a ~3.3 GiB production shard with room to spare — raise it only if your S3
path is materially slower than ~10 MB/s effective download. **Symptom:** a shard recover failing with an
error after a long transfer, with the presigned URL itself redacted from the log (by design —
it is a bearer credential). If you see this pattern, raise `QDRANT_S3_LINK_EXPIRY_DURATION`
(default `3600s`) before retrying, not just the verification timeout — the recover call itself
is what's timing out against S3, not the verification poll.

### Checksum / integrity layers note

On Qdrant v1.15.x, `POST .../shards/{sid}/snapshots` never returns a `checksum` field — every
manifest's `checksum` is empty, and the Qdrant-checksum gate that would validate it at recover
time is **inert** on this version (there is nothing to check). This is not silent: every shard
recovery prints a line like:

```
[<peer>] <collection> shard <sid>: manifest carries no checksum — recovering WITHOUT integrity verification (v1.15.x never returns one)
```

This is expected and does not indicate a problem by itself — it is a statement about what this
Qdrant version supports, not about this specific backup. Because that gate carries no weight
on v1.15.x, the tool supplies its **own** integrity layers (they close a live-reproduced
gap: a bit-flipped shard snapshot restored to VERIFIED at RF 1 before they existed):

- **Manifest etag/size pre-flight (at-rest):** schema-2 manifests record each shard object's
  S3 ETag and size at backup; the restore pre-flight re-checks every still-pending shard
  before the state gate and any destructive step. This proves the object is **unchanged since
  backup** (tamper/rot/truncation) — it does **not** prove validity: if Qdrant wrote a corrupt
  object at backup time, its recorded ETag is the corrupt object's. ETags are compared as
  opaque strings (multipart ETags are not MD5). A schema-1 manifest (lab-era) is flagged with
  `manifest predates integrity fields (schema 1)` and gets only the existence/size check.
- **Served-data payload checks:** verification reads what the restored collection actually
  serves, in two forms — a deterministic head scroll (up to 3 pages × 100 points,
  `with_payload: true` on every page; R5b's panic lived in payload storage and a
  payload-less read never touches it) plus **random-sample payload probes**
  (`QDRANT_VERIFY_SAMPLE_POINTS`, default 300, batches of ≤100 via the Query API's
  `sample: random`, `with_payload: true` per batch). This is **bounded sampling, never
  per-point validation**: a corrupt region covering fraction `f` of points is caught with
  probability `1−(1−f)^300` — ≈ 99.99998% at `f`=5%, ≈ 95% at `f`=1%, ≈ 26% at `f`=0.1%.
  Near-certain for percent-scale corruption; small regions can escape (live-demonstrated:
  head-only sampling missed served corruption starting past the sampled head, which is why
  the random probes exist). Qdrant ≥ 1.16
  snapshot checksums remain the designated full closure — they activate the tool's
  existing, currently-inert checksum gate. The two layers are a **pair, not alternatives**.

The count check, the replica-set check, and the scroll/vector smoke tests remain load-bearing
alongside them — do not treat the absence of a checksum warning as license to skip reviewing
any of these.

## Transition rules

### The S3 alias store freezes at cutover — alias truth moves into the manifests

The legacy alias flow (`backup_colla`/`recover_colla`, the
`collection_aliases_store/` S3 prefix, `BACKUP_COLLECTION_ALIASES_ON_S3`,
`QDRANT_COLLECTION_ALIASES_STABLE_FILE`) stops being refreshed the moment the last legacy
`create_snap` run happens. Nothing deletes the store, so a later `recover_colla` still
**succeeds** — while restoring aliases frozen at that last legacy run, with no warning
that they are stale. After cutover: alias truth lives inside each per-shard backup
manifest and is restored (with a theft guard) as part of `recover_snap_shards` — do NOT
use `recover_colla` for post-cutover state. Recommended: delete (or explicitly ignore)
`collection_aliases_store/` at cutover so the stale copy cannot be mistaken for truth.
The per-shard tasks warn if the legacy alias env knobs are set.

These apply for as long as the bucket contains **both** legacy (per-node) and per-shard
objects — from the first `create_snap_shards` shadow run (Day-0 Step 2) until every collection's
legacy objects have been pruned below the retained generations (Day-0 Step 5, done per
collection).

### Never use legacy `get_snap` during/after the transition — use `get_snap_s3`

**Forbidden on Qdrant v1.15.x once any v2 shard snapshot exists:** the legacy `get_snap` task
(`fetch_collection_snapshot`, the Qdrant **API**-listing path — `GET /collections/{c}/snapshots`)
was empirically proven, at the Phase-0 spike, to list per-shard (shard-level) snapshots unfiltered
alongside genuine legacy ones. The code now guards this with a name-based filter
(`filter_legacy_snapshot_names`), but that filter is a **heuristic over snapshot names**, while
the S3 key structure (which segregates `shards/{sid}/` under its own path) is **authoritative**.

**Always use `get_snap_s3` instead** (`fetch_collection_snapshot_from_s3`) for legacy discovery
during and after the transition — it lists S3 directly and filters on the real path structure
(`filter_legacy_snapshot_keys`), not on inferring intent from a filename:

```bash
./qdrant_backup_recovery.sh get_snap_s3
```

### Reset after a mid-incident ConfigMap update

If you update `k8s/configmap-script.yaml` (a new script version) **in the middle of** an
in-progress incident response, run `reset` before re-running any discovery task in the same
workdir:

```bash
./qdrant_backup_recovery.sh reset
```

A changed script version can change filter behavior, field names, or state-file formats
mid-session; stale local state files (`collections`, `snapshots`, `shard_recovery_history`, …)
from before the update are not guaranteed compatible with the new code path. `reset --bkp true`
backs them up instead of deleting them, if you want to keep a copy for comparison.

### Never run two restores against the same target concurrently

There is no distributed lock across `recover_snap_shards` invocations (out of scope initially). Two
concurrent restores against the same target collection can race on the state gate — both could
observe "absent" simultaneously and both attempt to create it, or one could `FORCE`-delete the
collection while the other is mid-recovery of its shards — with a real risk of corrupted
collection state or silently lost shard data. `concurrencyPolicy: Forbid` on the backup CronJob
only prevents that specific CronJob from overlapping with itself; it does **not** stop an
operator from manually starting a second ad-hoc restore Job against a target that already has
one running. Treat "one restore per target, at a time" as a hard operational rule, not a
suggestion — check `kubectl -n <namespace> get jobs -lapp=qdrant-restore` before starting
another one.
