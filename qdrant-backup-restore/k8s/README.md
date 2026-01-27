# Kubernetes ConfigMap Management for Qdrant Backup/Restore Scripts

This directory contains tools for managing the Qdrant backup/restore script as a Kubernetes ConfigMap, allowing the script to be mounted into pods and executed within a Kubernetes cluster.

## Files

### `configmap-script.yaml`

A Kubernetes ConfigMap manifest that stores the `qdrant_backup_recovery.sh` script in its `data` section.

**Important:** Do not edit the `data` section directly. Always use `config_map_updater.sh` to update the script content.

### `config_map_updater.sh`

A utility script that automatically updates the ConfigMap with the latest version of the backup/restore script from the source file.

## Prerequisites

- **yq** (YAML processor, version 4.0 or higher)
- **Bash** (version 4.0 or higher)

## Usage

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
