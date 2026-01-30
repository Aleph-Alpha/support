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
6. `QDRANT_S3_LINK_EXPIRY_DURATION` is set at `3600`. This is the duration that an s3 presigned url will be active. The url is used during the recovery process.
7. `QDRANT_WAIT_ON_TASK` is set as `true`. This configuation make backup process synchronous meaning 'wait for snapshot process to finish successfully before moving on'. Its used during backup and recovery.

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
2. Update the `QDRANT_SOURCE_HOSTS` to the kubernetes service domain of the source Qdrant deployment.
3. Update the `QDRANT_RESTORE_HOSTS` to the target qdrant cluster service domain.
4. `GET_PEERS_FROM_CLUSTER_INFO` should be `true` to discover qdrant cluster peers when backing up collections.
5. `CURL_TIMEOUT` is set at `3000` seconds. This is the max time curl will wait for request to complete. Its increased in scenarios where restoration takes a while.
6. `QDRANT_S3_LINK_EXPIRY_DURATION` is set at `3600`. This is the duration that an s3 presigned url will be active. The url is used during the recovery process.
7. `QDRANT_WAIT_ON_TASK` is set as `true`. This configuation make restoration process synchronous meaning 'wait for snapshot process to finish successfully before moving on'. Its used during backup and recovery.
8. `QDRANT_SNAPSHOT_DATETIME_FILTER` is empty. Setting this filters out snapshot/backups belonging to a certain date and time using glob pattern matching. e.g `"2026-01-29"` = all snapshots in 29th January 2026, `2026-01` = all backups in January 2026.
9. `MC_CONFIG_DIR` is `mc`. This overrides the default storage location ($HOME) for mc s3 client configurations. Essential in set ups that use stricter securityContext configuration like `readOnlyRootFilesystem: true`.

Deploy the job!

```bash
kubectl -n <namespace> apply -f restore-job.yaml
```

Check the logs

```bash
kubectl -n <namespace> logs -lapp=qdrant-restore -f
```

**Specific Recovery**

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

## Contributor Configurations

### `configmap-script.yaml`

A Kubernetes ConfigMap manifest that stores the `qdrant_backup_recovery.sh` script in its `data` section.

**Important:** Do not edit the `data` section directly. Always use `config_map_updater.sh` to update the script content.

### `config_map_updater.sh`

A utility script that automatically updates the ConfigMap with the latest version of the backup/restore script from the source file.

- **yq** (YAML processor, version 4.0 or higher)
- **Bash** (version 4.0 or higher)

### Updating the ConfigMap

When you make changes to `qdrant_backup_recovery.sh`, use the updater script to sync those changes into the ConfigMap:

```bash
# From the k8s directory
./k8s/config_map_updater.sh k8s/configmap-script.yaml qdrant_backup_recovery.sh
```

**What it does:**

1. Reads the source script file
2. Injects the script content into the ConfigMap's `data` section
3. Updates the ConfigMap YAML file in-place

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

[job](job.yaml) and [cronjob](cronjob.yaml) are example of how to use the `configmap-script.yaml`.
