# qdrant backup and restore scripts

Here lies essentials scripts to backup and restore/recover qdrant snapshots from n instance(s) to x instance(s).

## Prerequisites

- Bash -  curl, jq
- Python

  ```bash
  pip3 install -r requirements.txt
  ```

- Qdrant instance [with s3 storage for snapshots](https://qdrant.tech/documentation/concepts/snapshots/#storage)
- Create and configure .env file from [.env.sample](.env.sample)
- Initialize the .env file as below;
  
   ````bash
    source .env
    ````

## Overview

The scripts support backup and restoration of qdrant collection snapshots using qdrant and s3 apis.

The following state files are created to track progress and/or act as input in other tasks.

````text
collections
failed_snapshot_recovery
fw_ports
snapshot_recovery_history
snapshots
alias_recovery_history
collection_aliases
````

## Backup

Qdrant Apis is used to create snapshots of each collection from each node or nodes in distributed mode. Steps are as below:

- create snapshots: this creates `collections` (contains all collections) and `snapshots`(contains all snapshots created) file.

````bash
./qdrant_backup_recovery.sh create_snap
````

alternatively, one can fetch the collections alone; this creates `collections`  file.

````bash
./qdrant_backup_recovery.sh get_coll
````

and fetch collection aliases; this creates `collections_aliases` file

Collections aliases are not part of collection snapshot content so they have to be backed up separately,

````bash
./qdrant_backup_recovery.sh get_colla
````

## Restore

Qdrant & S3 Apis are used to fetch snapshots either from s3 or Qdrant instance(s). Once the snapshots are fetched they can be recovered. Below are the steps that happen:

- Fetch snapshots from s3; gets snapshots from s3; it will populate `collections` and `snapshots` file.

````bash
./qdrant_backup_recovery.sh get_snap_s3
````

- Alternatively, fetch snapshots from instance directly; it will populate `collections` and `snapshots` file.

````bash
./qdrant_backup_recovery.sh get_snap
````

- Once snapshots have been fetched; recover/restore the snapshots on to an instance;

- It recovers the snapshots listed on the `snapshot` file.

````bash
./qdrant_backup_recovery.sh recover_snap
````

- Recover collection aliases;

````bash
./qdrant_backup_recovery.sh recover_colla
````

## Reset

Deletes all the state files used in backup/recovery tasks.

````bash
./qdrant_backup_recovery.sh reset
````

keep the state files from previous tasks

````bash
./qdrant_backup_recovery.sh reset --bkp true
````

## Configuration

Below are system environment variables

| Name                        | Description                                                                                                                                                  | Default               |
|-----------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------|
| QDRANT_S3_ACCESS_KEY_ID     | S3 snapshots storage access key id                                                                                                                           | -                     |
| QDRANT_S3_SECRET_ACCESS_KEY | S3 snapshots storage secret access key                                                                                                                       | -                     |
| QDRANT_API_KEY              | Qdrant api key                                                                                                                                               | -                     |
| QDRANT_S3_BUCKET_NAME       | S3 bucket name                                                                                                                                               | -                     |
| QDRANT_SOURCE_HOSTS         | Comma separted list of qdrant peers (hosts), source of backup resources                                                                                      | http://localhost:6333 |
| QDRANT_S3_ENDPOINT_URL      | Path style s3 url                                                                                                                                            | -                     |
| QDRANT_RESTORE_HOSTS        | Comma separted list of qdrant peers (hosts) destination of backed up resources                                                                               | http://localhost:6333 |
| GET_PEERS_FROM_CLUSTER_INFO | Extracts peer urls from cluster info endpoint, useful for k8s setups it will support dynamic number of hosts when scaling. Updates `source_hosts` in script. | false                 |
