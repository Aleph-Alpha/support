# 🛡️ Pharia AI Backup & Restore

Safely backup and restore PostgreSQL databases and Kubernetes secrets for Pharia AI upgrades and rollbacks.

## 📋 Scope

### ✅ What's Included
- 🐘 **PostgreSQL Database Backup & Restore** - Full backup and restore of PostgreSQL databases
- 🔐 **Kubernetes Secrets Backup & Restore** - Export and restore K8s secrets

### ❌ What's NOT Included
- ⚠️ **Qdrant Database Backup** - Vector database backups are not supported
- ⚠️ **Application State** - Only database and secrets are backed up

> **Note:** If your application uses Qdrant or other vector databases, you'll need to backup those separately using Qdrant's native backup tools.

## 🚀 Quick Start

### 1. ⚙️ Setup Configuration

```bash
# Copy example config
cp config.yaml.example config.yaml

# Get credentials from Kubernetes
kubectl get secret pharia-ai-dex-credentials -n pharia-ai -o jsonpath='{.data.databaseName}' | base64 -d
kubectl get secret pharia-ai-dex-credentials -n pharia-ai -o jsonpath='{.data.username}' | base64 -d
kubectl get secret pharia-ai-dex-credentials -n pharia-ai -o jsonpath='{.data.password}' | base64 -d

# Edit config.yaml with your database details
nano config.yaml
```

**Example config.yaml:**
```yaml
backup_dir: "./database-backups"

databases:
  - name: dev
    host: localhost
    port: 5432
    user: pharia_user
    password: your_password
```

### 2. 🧪 Test Connection

```bash
psql -h localhost -p 5432 -U pharia_user -d dev -c "SELECT version();"
```

## 🔄 Pharia AI Upgrade Workflow

### 📦 Before Upgrade: Take Backups

```bash
# Backup databases
./bin/pharia-backup.sh db backup

# Backup Kubernetes secrets
./bin/pharia-backup.sh secrets backup pharia-ai
```

### ⬆️ Perform Upgrade

```bash
helm upgrade pharia-ai ./pharia-ai-chart --namespace pharia-ai
```

### ✅ If Upgrade Succeeds

Test your application and you're done!

### ⚠️ If Upgrade Fails: Rollback

```bash
# 1. Restore databases
./bin/pharia-backup.sh db restore all

# 2. Restore secrets
./bin/pharia-backup.sh secrets restore --latest -f -n pharia-ai

# 3. Rollback Helm deployment
helm rollback pharia-ai -n pharia-ai

# 4. Verify pods are running
kubectl get pods -n pharia-ai
```

## 📝 Common Commands

### 🗄️ Database Operations

```bash
# Backup all databases
./bin/pharia-backup.sh db backup

# Restore specific database
./bin/pharia-backup.sh db restore dev

# Restore all databases
./bin/pharia-backup.sh db restore all

# List backups
./bin/pharia-backup.sh db restore -l dev

# Restore from specific file
./bin/pharia-backup.sh db restore -f database-backups/dev_2025-12-22_143052.sql dev
```

### 🔐 Secrets Operations

```bash
# Backup secrets
./bin/pharia-backup.sh secrets backup pharia-ai

# Restore from latest
./bin/pharia-backup.sh secrets restore --latest -n pharia-ai

# Force overwrite existing secrets
./bin/pharia-backup.sh secrets restore --latest -f -n pharia-ai

# List available backups
./bin/pharia-backup.sh secrets restore -l
```

## 💡 Complete Example

```bash
# === INITIAL SETUP (once) ===
cp config.yaml.example config.yaml
nano config.yaml  # Add your DB credentials

# === BEFORE UPGRADE ===
./bin/pharia-backup.sh db backup
./bin/pharia-backup.sh secrets backup pharia-ai

# Note backup timestamps
ls -lt database-backups/ | head -3
ls -lt secrets-backups/ | head -3

# === UPGRADE ===
helm upgrade pharia-ai ./pharia-ai-v2.0 -n pharia-ai

# === IF ROLLBACK NEEDED ===
./bin/pharia-backup.sh db restore all
./bin/pharia-backup.sh secrets restore --latest -f -n pharia-ai
helm rollback pharia-ai -n pharia-ai
kubectl get pods -n pharia-ai
```

## 🔧 Troubleshooting

**❌ Connection failed:**
```bash
# Verify credentials in config.yaml
# Check PostgreSQL is accessible
pg_isready -h localhost -p 5432
```

**⚠️ Secrets already exist:**
```bash
# Use force flag to overwrite
./bin/pharia-backup.sh secrets restore --latest -f -n pharia-ai
```

**❌ Database restore fails:**
```bash
# List available backups
./bin/pharia-backup.sh db restore -l dev

# Restore from specific backup
./bin/pharia-backup.sh db restore -f database-backups/dev_2025-12-22_143052.sql dev
```

## 📚 Help

```bash
./bin/pharia-backup.sh --help
./bin/pharia-backup.sh db --help
./bin/pharia-backup.sh secrets --help
```

## ✅ Prerequisites

- 🐘 PostgreSQL client tools (`pg_dump`, `psql`)
- ☸️ `kubectl` configured for your cluster
- 📄 `yq` (optional, fallback parser included)

## 📁 Directory Structure

```
scripts/pharia-ai-backup-restore/
├── bin/
│   ├── pharia-backup.sh        # Main CLI
│   ├── backup-db.sh            # Database backup
│   ├── restore-db.sh           # Database restore
│   ├── backup-secrets.sh       # Secrets backup
│   └── restore-secrets.sh      # Secrets restore
├── config.yaml                 # Your config (gitignored)
├── config.yaml.example         # Example config
├── database-backups/           # DB backups (gitignored)
└── secrets-backups/            # Secret backups (gitignored)
```

## 🔒 Security Notes

- 🔐 `config.yaml` is gitignored and contains sensitive credentials
- 🚫 Backup directories are gitignored (contain sensitive data)
- 🛡️ Set restrictive permissions: `chmod 600 config.yaml`
- ⚠️ Never commit config.yaml or backup files to version control
