
# PostgreSQL Multi-Database Migration Utility

Automate backup and restore of multiple PostgreSQL databases using a YAML configuration. This utility is designed for Kubernetes environments and supports advanced features for reliability and security.

---

## Features
- Backup and restore multiple databases in one run
- YAML config for flexible source/destination mapping
- Comprehensive logging and error handling
- Dry-run mode for safe testing
- Colored output for clarity
- Retry logic and version validation
- Security options (password hiding, config backup)

---

## Quick Start

### 1. Prepare Configuration
Copy the example config and fill in your credentials:
```sh
cp example.db_config.yaml db_config.yaml
# Edit db_config.yaml with your database credentials
```

The config file supports multiple databases and advanced options. See `example.db_config.yaml` for structure:
```yaml
databases:
  - name: "mydb"
    source:
      host: "src-host"
      port: 5432
      username: "src-user"
      password: "src-pass"
      database: "src-db"
    destination:
      host: "dest-host"
      port: 5432
      username: "dest-user"
      password: "dest-pass"
      database: "dest-db"
config:
  dump_directory: "./dumps"
  log_file: "./migration.log"
  postgresql:
    dump_options:
      - "no-owner"
      - "format=plain"
      - "verbose"
    required_version: "17"
  timeouts:
    restore: 3600
    dump: 3600
  retry:
    max_attempts: 5
    delay_seconds: 10
  security:
    hide_passwords: true
    backup_config: true
  performance:
    compress_dumps: true
    verify_checksums: true
    cleanup_old_dumps: 5
```

### 2. Launch PostgreSQL Pod
We recommend launching a PostgreSQL pod in the `pharia-ai` namespace:
```sh
kubectl run psql17 --rm -it --image=postgres:17 --command -- bash
```

### 3. Install Tools in Pod
Inside the pod, install wget and yq:
```sh
apt update && apt install wget -y
wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/bin/yq
chmod +x /usr/bin/yq
```

### 4. Copy Script & Config to Pod
Copy the migration script and config file to the pod **from a different terminal** (not inside the pod):
```sh
kubectl cp scripts/db-migration/database_migrator.sh psql17:/tmp/database_migrator.sh
kubectl cp scripts/db-migration/db_config.yaml psql17:/tmp/db_config.yaml
```

### 5. Run Migration
In the pod, run:
```sh
cd /tmp
chmod +x database_migrator.sh
./database_migrator.sh
```

### 6. Cleanup
After migration is complete, delete the `psql17` pod:
```sh
kubectl delete pod psql17
```

---

## Script Usage & Options

```sh
./database_migrator.sh [OPTIONS]

OPTIONS:
  -c, --config FILE       Path to YAML configuration file (default: db_config.yaml)
  -d, --dry-run           Show what would be done without executing commands
  -v, --verbose           Enable verbose output
  -h, --help              Show help message
  --version               Show version information
```

---

## Prerequisites
- PostgreSQL client tools (`psql`, `pg_dump`)
- `yq` for YAML parsing
- Bash shell

The script checks for required tools and PostgreSQL version before running.

---

## Troubleshooting
- Check logs in `./logs/` for details on failures
- Ensure all credentials and hostnames are correct in `db_config.yaml`
- Use `--dry-run` to validate config and environment before actual migration
- For large databases, adjust `timeouts` in config

---

## Advanced Usage
- Supports retry logic for transient failures
- Dumps are stored in the directory specified in config
- Old dumps can be cleaned up automatically
- Passwords are hidden in logs if enabled

---

For more details, see comments in the script and config file.
