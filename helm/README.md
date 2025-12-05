# Pharia AI Quick Start Helm Charts

This directory contains Helm charts for deploying the infrastructure components required by Pharia AI applications: PostgreSQL, Redis, and MinIO.

## Table of Contents

- [📖 Overview](#-overview)
- [🐘 PostgreSQL Setup](#-postgresql-setup)
- [⚡ Redis Setup](#-redis-setup)
- [🪣 MinIO Setup](#-minio-setup)
- [📝 Additional Notes](#-additional-notes)

---

## 📖 Overview

> **⚠️ Important Notice:** The support charts provided in this directory are designed for **quickstart and development purposes** to help you get started with the Pharia AI stack quickly. For production deployments, we strongly recommend replacing these in-cluster services with **externally managed services** for PostgreSQL, Redis, and object storage (e.g., AWS RDS, Amazon ElastiCache, Amazon S3, or equivalent managed services from other cloud providers). Managed services provide better reliability, automated backups, monitoring, scaling, and reduced operational overhead.

The Pharia AI Quick Start Helm charts in this directory provide essential **persistence and infrastructure services** that run inside your Kubernetes cluster to support the Pharia AI application stack. These charts deploy and manage:

- **🐘 PostgreSQL**: Highly available relational database clusters with connection pooling for application data persistence
- **⚡ Redis**: In-memory data stores for caching, session management, and queue processing
- **🪣 MinIO**: S3-compatible object storage for files, artifacts, and large data objects

### Purpose

These infrastructure components are designed to provide:

1. **Data Persistence**: Reliable storage for application data, configurations, and state
2. **High Availability**: Clustered deployments with automatic failover and replication
3. **Performance Optimization**: Connection pooling, caching, and efficient data access patterns
4. **Isolation**: Dedicated resources per application with proper access control
5. **Kubernetes-Native**: Fully integrated with Kubernetes using operators and custom resources
6. **Automated Secret Management**: Each chart automatically generates Kubernetes secrets containing connection credentials and endpoints

### Automated Secret Generation

**A key feature of these Helm charts is the built-in mechanism to auto-generate Kubernetes secrets** with connection data for all infrastructure services:

- **PostgreSQL Secrets**: Contain database credentials (username, password), connection endpoints (host, port), database names, and complete connection URLs for each application role
- **Redis Secrets**: Contain Redis instance credentials, hostnames, and port information for cache access
- **MinIO Secrets**: Contain S3-compatible access keys, secret keys, endpoint URLs, and bucket names for object storage

**Integration with Pharia AI Applications:**

These auto-generated secrets are designed to be **directly referenced in the `values.yaml` of the Pharia AI Helm chart** to connect Pharia applications to their respective infrastructure services. This approach provides:

- **Zero manual credential management**: No need to manually create or manage passwords and connection strings
- **Secure credential storage**: All sensitive data is stored as Kubernetes secrets
- **Consistent naming convention**: Predictable secret names following the pattern `qs-{service}-access-{application}`
- **Automatic updates**: Secrets are preserved during upgrades, ensuring connection stability
- **Ready-to-use references**: Simply reference the secret name and key in your Pharia AI application configuration

**Example Integration:**

```yaml
# In Pharia AI values.yaml - PostgreSQL Connection
document-index:
  databaseConfig:
    external:
      existingSecret: "qs-postgresql-cluster-access-document-index"
    secretKeys:
      hostKey: host
      portKey: port
      userKey: user
      passwordKey: password
      databaseNameKey: databaseName
      databaseUrlKey: databaseUrl

# Redis Connection
pharia-assistant-api:
  redisConfig:
    external:
      existingSecret: "qs-redis-pharia-assistant-api"
    secretKeys:
      hostKey: host
      portKey: port
      usernameKey: username
      passwordKey: password

# MinIO / S3 Connection
pharia-data-api:
  storageConfig:
    internalBucket:
      external:
        existingSecret: "qs-minio-access-pharia-data-internal"
      secretKeys:
        bucketNameKey: "bucket"
        bucketUserKey: "user"
        bucketPasswordKey: "password"
    externalBucket:
      external:
        existingSecret: "qs-minio-access-pharia-data-external"
      secretKeys:
        bucketNameKey: "bucket"
        bucketUserKey: "user"
        bucketPasswordKey: "password"
```

> **⚠️ Important:** Before adding these secret references to your Pharia AI Helm chart `values.yaml`, **verify that the respective `qs-*` secrets have been correctly generated** by the infrastructure chart deployment jobs. You can check secret creation with:
> ```bash
> # List all generated secrets
> kubectl get secrets -n pharia-ai -l app.kubernetes.io/managed-by=Helm
>
> # Verify a specific secret exists
> kubectl get secret qs-postgresql-cluster-access-document-index -n pharia-ai
> kubectl get secret qs-redis-pharia-assistant-api -n pharia-ai
> kubectl get secret qs-minio-access-pharia-data-internal -n pharia-ai
>
> # Check secret content (decode base64)
> kubectl get secret qs-postgresql-cluster-access-document-index -n pharia-ai -o jsonpath='{.data.host}' | base64 -d
> ```
> If secrets are missing, check the secret generation job logs for errors:
> ```bash
> kubectl logs -n pharia-ai -l app.kubernetes.io/component=create-secrets
> ```

This seamless integration eliminates the need for manual credential configuration and ensures that Pharia AI applications are automatically connected to their infrastructure dependencies.

### Installation Prerequisites

**Important:** All support charts must be installed **before** deploying the Pharia AI application helm charts.

**Namespace Requirement:** Install all infrastructure components in the **same namespace** where you plan to deploy the Pharia AI stack. The default namespace used in this documentation is `pharia-ai`.

**Installation Order:**

1. **Operators First**: Install the required operators (PostgreSQL operator, Redis operator)
2. **Infrastructure Services**: Deploy the infrastructure resources (PostgreSQL clusters, Redis instances, MinIO deployments)
3. **Pharia AI Applications**: Finally, deploy the Pharia AI application helm charts

**Example Namespace Setup:**

```bash
# Create the namespace for Pharia AI and its infrastructure
kubectl create namespace pharia-ai

# Set as default namespace for convenience (optional)
kubectl config set-context --current --namespace=pharia-ai
```

**Why This Order Matters:**

- Operators must be running before their Custom Resource Definitions (CRDs) can be used
- Infrastructure services must be ready before applications attempt to connect
- Secrets generated during infrastructure deployment are required by Pharia AI applications
- Applications will fail to start if their database, cache, or storage dependencies are unavailable

The following sections detail the installation process for each infrastructure component in the recommended order.

---

## 🐘 PostgreSQL Setup

The PostgreSQL setup provides a highly available database infrastructure with connection pooling via PgBouncer. It consists of two separate PostgreSQL clusters: one for Pharia applications and one for Temporal workflow engine.

### Architecture

The PostgreSQL setup uses CloudNativePG operator and includes the following components:

```mermaid
graph TB
    subgraph "PostgreSQL Infrastructure"
        subgraph "Pharia Cluster"
            PG1[Primary PostgreSQL<br/>Instance]
            PG2[Replica PostgreSQL<br/>Instance 1]
            PG3[Replica PostgreSQL<br/>Instance 2]
            PG1 -.->|Replication| PG2
            PG1 -.->|Replication| PG3

            PGB_TX[PgBouncer Pooler<br/>Transaction Mode]
            PGB_TX -->|Connection Pool| PG1
        end

        subgraph "Temporal Cluster"
            TG1[Primary PostgreSQL<br/>Instance]
            TG2[Replica PostgreSQL<br/>Instance 1]
            TG3[Replica PostgreSQL<br/>Instance 2]
            TG1 -.->|Replication| TG2
            TG1 -.->|Replication| TG3

            TGB_SESSION[PgBouncer Pooler<br/>Session Mode]
            TGB_SESSION -->|Connection Pool| TG1
        end
    end

    subgraph "Applications"
        APP1[Pharia Applications]
        APP2[Temporal Workflows]
    end

    APP1 -->|Port 5432| PGB_TX
    APP2 -->|Port 5432| TGB_SESSION

    style PG1 fill:#4CAF50
    style TG1 fill:#4CAF50
    style PGB_TX fill:#2196F3
    style TGB_SESSION fill:#2196F3
```

**Key Architecture Points:**
- **PostgreSQL Cluster:** High-availability setup with 3 instances (1 primary, 2 replicas) for automatic failover
- **PgBouncer Pooler:** Integrated connection pooler that efficiently manages database connections
  - **Transaction Mode (Pharia):** Optimized for short-lived transactions, releases connections after each transaction
  - **Session Mode (Temporal):** Maintains connection state for entire client session, required for Temporal workflows
- **Service Endpoints:**
  - Direct cluster connection: `{cluster-name}-rw` (read-write), `{cluster-name}-r` (read-only)
  - Pooler connection: `{cluster-name}-pooler-{pooler-name}` (recommended)

### Prerequisites

The PostgreSQL operator must be installed before deploying the clusters.

#### Cluster Configuration

The PostgreSQL cluster instances are configured through the `qs-postgresql-cluster/values.yaml` file, which defines two separate clusters:

- **`clusterPharia`**: PostgreSQL cluster for Pharia applications (lines 54-308 in values.yaml)
- **`clusterTemporal`**: PostgreSQL cluster for Temporal workflows (lines 310-413 in values.yaml)

Each cluster configuration includes critical parameters such as:
- **Instance count**: Number of PostgreSQL instances (default: 3 for high availability)
- **PostgreSQL version**: Major version to deploy (default: PostgreSQL 17)
- **Storage size**: Persistent volume size per instance (default: 250Gi)
- **Resource limits**: CPU and memory allocation (e.g., 24Gi RAM, 4-8 CPU cores for Pharia cluster)
- **PostgreSQL parameters**: Database tuning parameters (`max_connections`, `shared_buffers`, `effective_cache_size`, etc.)
- **Roles**: Database users and their permissions
- **Poolers**: PgBouncer connection pooling configuration

**Important Configuration Notes:**

> **⚠️ Note:** The default configuration values provided in `values.yaml` are **recommendations for an initial setup only**. These parameters may need to be adapted based on:
> - The specific requirements of your Pharia AI deployment
> - Your expected workload and data volume
> - Available infrastructure resources
> - Performance and sizing considerations
>
> Please review and adjust the configuration according to your environment before deploying to production.

**Additional Resources:**

For detailed information about available configuration parameters and cluster customization, refer to:
- **CloudNativePG Cluster Helm Chart Documentation**: [https://artifacthub.io/packages/helm/cloudnative-pg/cluster](https://artifacthub.io/packages/helm/cloudnative-pg/cluster)
- **CloudNativePG Official Documentation**: [https://cloudnative-pg.io/documentation/1.27/](https://cloudnative-pg.io/documentation/1.27/)

These resources provide comprehensive guidance on:
- PostgreSQL configuration tuning
- Resource management and sizing
- High availability and replication settings
- Backup and recovery configuration
- Storage and performance optimization

#### CRD Installation

CloudNativePG requires Custom Resource Definitions (CRDs) to be installed. The Helm chart includes CRDs by default and will install them automatically. However, for production environments or when you need more control over CRD lifecycle management, you can install CRDs separately before deploying the operator.

**Option 1: Automatic CRD Installation (Default)**

CRDs are automatically included and installed with the Helm chart:

```bash
# Install CloudNativePG operator with CRDs included
helm install qs-postgresql-operator ./qs-postgresql-operator \
  --namespace pharia-ai
```

**Option 2: Manual CRD Installation (Recommended for Production)**

Install CRDs directly from the GitHub source before deploying the Helm chart. This approach gives you better control over CRD lifecycle management and allows CRD updates independent of operator upgrades.

```bash
# Set the CloudNativePG version (should match your chart dependency version)
CNPG_VERSION="0.26.1"

# Install CRDs from GitHub
kubectl apply -f https://raw.githubusercontent.com/cloudnative-pg/charts/cloudnative-pg-v${CNPG_VERSION}/charts/cloudnative-pg/templates/crds/crds.yaml

# Install operator without CRDs (since they're already installed)
helm install qs-postgresql-operator ./qs-postgresql-operator \
  --namespace pharia-ai \
  --set crds.create=false
```

**Note:** When using Option 2, ensure the CRD version matches the operator version specified in `qs-postgresql-operator/Chart.yaml` (currently v0.26.1).

Wait for the operator to be ready:

```bash
kubectl wait --for=condition=available --timeout=300s \
  deployment/qs-postgresql-operator-cloudnative-pg \
  -n pharia-ai
```

### Installation Steps

#### 1. Install PostgreSQL Clusters

```bash
helm install qs-postgresql-cluster ./qs-postgresql-cluster \
  --namespace pharia-ai
```

**What happens during installation:**

1. **Pre-install Hook (RBAC & ServiceAccount):** Creates the ServiceAccount and Role/RoleBinding for secret management
2. **Pre-install Hook (Secret Generation Job):** Executes a Kubernetes Job that:
   - Generates secure random passwords for each database role
   - Creates Kubernetes secrets with connection details (host, port, username, password, database)
   - Labels secrets for lifecycle management
   - Preserves existing passwords on upgrades
3. **Cluster Deployment:** Deploys two CloudNativePG clusters:
   - `qs-postgresql-cluster-pharia`: For Pharia applications (3 instances, transaction pooler)
   - `qs-postgresql-cluster-temporal`: For Temporal workflows (3 instances, session pooler)
4. **Role Creation:** Creates database roles (users) as specified in the cluster configuration
5. **Pooler Deployment:** Deploys PgBouncer poolers for connection management

#### Controlling Secret Generation

By default, the chart automatically generates secrets for all database roles. You can control this behavior using the `secretGenerationJob.enabled` flag:

**Disable automatic secret generation:**
```bash
helm install qs-postgresql-cluster ./qs-postgresql-cluster \
  --namespace pharia-ai \
  --set secretGenerationJob.enabled=false
```

> **⚠️ Important:** When `secretGenerationJob.enabled=false`, you **must manually create all required secrets** before the PostgreSQL clusters can start successfully. The CloudNativePG operator will fail to create database roles if their `passwordSecret` references are missing.

**Manual Secret Creation Requirements:**

When automatic secret generation is disabled, you must create secrets for **each database role** defined in the cluster configuration. The secrets must follow this exact structure:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: qs-postgresql-cluster-access-{role-name}
  namespace: pharia-ai
  labels:
    app.kubernetes.io/managed-by: Helm
    qs-postgresql-cluster/name: {cluster-name}
    qs-postgresql-cluster/type: access-secret
type: Opaque
stringData:
  username: "{role_name}"                    # e.g., "pharia_os", "document_index"
  user: "{role_name}"                        # Alias for username (same value)
  password: "{secure-random-password}"       # At least 16 characters recommended
  host: "{connection-endpoint}"              # Pooler or direct endpoint
  port: "5432"                               # PostgreSQL port
  protocol: "postgres"                       # Connection protocol
  databaseName: "{database-name}"            # Database name for this role
  databaseUrl: "postgres://{username}:{password}@{host}:{port}/{databaseName}"
```

**Required Secrets for Default Configuration:**

<details>
<summary><strong>Pharia Cluster Secrets (14 secrets)</strong></summary>

```bash
# Create secrets for all Pharia cluster roles
kubectl create secret generic qs-postgresql-cluster-access-document-index -n pharia-ai \
  --from-literal=username="document_index" \
  --from-literal=user="document_index" \
  --from-literal=password="$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-25)" \
  --from-literal=host="qs-postgresql-cluster-pharia-pooler-transaction" \
  --from-literal=port="5432" \
  --from-literal=protocol="postgres" \
  --from-literal=databaseName="document-index" \
  --from-literal=databaseUrl="postgres://document_index:PASSWORD@qs-postgresql-cluster-pharia-pooler-transaction:5432/document-index"

# Repeat for all roles: pharia_os, inference_api, pharia_studio,
# pharia_oauth_gateway, pharia_assistant, pharia_chat, pharia_catch,
# zitadel, openfga, dex, pharia_conductor, pharia_numinous,
# pharia_transcribe_app, pharia_data, mlflow
```

</details>

<details>
<summary><strong>Temporal Cluster Secrets (2 secrets)</strong></summary>

```bash
# Create secrets for Temporal cluster roles
kubectl create secret generic qs-postgresql-cluster-access-temporal -n pharia-ai \
  --from-literal=username="temporal" \
  --from-literal=user="temporal" \
  --from-literal=password="$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-25)" \
  --from-literal=host="qs-postgresql-cluster-temporal-pooler-session" \
  --from-literal=port="5432" \
  --from-literal=protocol="postgres" \
  --from-literal=databaseName="temporal" \
  --from-literal=databaseUrl="postgres://temporal:PASSWORD@qs-postgresql-cluster-temporal-pooler-session:5432/temporal"

kubectl create secret generic qs-postgresql-cluster-access-temporal-visibility -n pharia-ai \
  --from-literal=username="temporal_visibility" \
  --from-literal=user="temporal_visibility" \
  --from-literal=password="$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-25)" \
  --from-literal=host="qs-postgresql-cluster-temporal-pooler-session" \
  --from-literal=port="5432" \
  --from-literal=protocol="postgres" \
  --from-literal=databaseName="temporal-visibility" \
  --from-literal=databaseUrl="postgres://temporal_visibility:PASSWORD@qs-postgresql-cluster-temporal-pooler-session:5432/temporal-visibility"
```

</details>

**Important Notes:**
- The `host` field should point to the appropriate endpoint (pooler or direct connection)
- For Pharia cluster roles using transaction pooler: `qs-postgresql-cluster-pharia-pooler-transaction`
- For Temporal cluster roles using session pooler: `qs-postgresql-cluster-temporal-pooler-session`
- For direct connections (bypassing pooler): `qs-postgresql-cluster-{name}-rw`
- The `databaseUrl` must be a complete PostgreSQL connection string
- Ensure passwords meet your security requirements (minimum 16 characters recommended)
- The `username` field should use underscores (e.g., `pharia_os`), matching the role name
- The `databaseName` field should use hyphens (e.g., `pharia-os`), matching the database name

**Secret Cleanup Behavior:**

When `secretGenerationJob.enabled=false`, the automatic secret cleanup on uninstall is also disabled, regardless of the `secretCleanup.retainOnDelete` setting. This ensures consistency - if secrets weren't created by the chart, they won't be deleted by it either.

#### 2. Install Database Resources

After the clusters are ready, install the database resources:

```bash
helm install qs-postgresql-db ./qs-postgresql-db \
  --namespace pharia-ai
```

**What happens during installation:**

1. **Database Creation:** Creates the CloudNativePG Database resources for each application
2. **Post-install Hook (Extension Job):** Executes a Job that enables PostgreSQL extensions (uuid-ossp, pgcrypto, pg_stat_statements, pg_trgm, btree_gin) in each database
3. **Post-install Hook (Isolation Job):** Enforces database isolation by revoking cross-database access

### Adding a New Database with a New Role

To add a new database with a dedicated role to the PostgreSQL cluster, you need to update both the `qs-postgresql-cluster` and `qs-postgresql-db` charts.

#### Step 1: Add the Role to the PostgreSQL Cluster

Edit the `qs-postgresql-cluster/values.yaml` file and add a new role to the appropriate cluster's `roles` section:

```yaml
clusterPharia:
  cluster:
    roles:
      # ... existing roles ...
      - name: "my_new_app"
        connectionLimit: -1
        ensure: present
        inherit: true
        passwordSecret:
          name: "qs-postgresql-cluster-access-my-new-app"
        login: true
        superuser: false
        replication: false
```

**Role Configuration:**
- **name:** The PostgreSQL role/username (use underscores, e.g., `my_new_app`)
- **connectionLimit:** Max concurrent connections (-1 = unlimited)
- **passwordSecret.name:** Secret name following the pattern `qs-postgresql-cluster-access-{role-name}`
- **login:** Set to `true` to allow the role to connect
- **superuser:** Set to `false` for application roles (security best practice)
- **replication:** Set to `false` for application roles

#### Step 2: Add the Database Resource

Edit the `qs-postgresql-db/values.yaml` file and add a new database entry:

```yaml
databases:
  # ... existing databases ...
  - name: "my-new-app"
    enabled: true
    cluster: "qs-postgresql-cluster-pharia"  # or "qs-postgresql-cluster-temporal"
    owner: "my_new_app"
    connectionLimit: 50
    extensions:
      - uuid-ossp
      - pgcrypto
      - pg_stat_statements
      - pg_trgm
      - btree_gin
```

**Database Configuration:**
- **name:** Database name (use hyphens, e.g., `my-new-app`)
- **cluster:** Target cluster name (`qs-postgresql-cluster-pharia` or `qs-postgresql-cluster-temporal`)
- **owner:** The role that owns this database (must match the role name from Step 1)
- **connectionLimit:** Max connections to this database
- **extensions:** PostgreSQL extensions to enable (optional)

#### Step 3: Apply the Changes

Upgrade the Helm releases to apply the changes:

```bash
# Update the cluster to add the new role
helm upgrade qs-postgresql-cluster ./qs-postgresql-cluster \
  --namespace pharia-ai

# Update the database resources to create the new database
helm upgrade qs-postgresql-db ./qs-postgresql-db \
  --namespace pharia-ai
```

#### What Happens During the Upgrade:

1. **Secret Generation:** A pre-upgrade hook creates a new secret `qs-postgresql-cluster-access-my-new-app` with:
   - Random password
   - Connection details (host, port)
   - Database connection URL

2. **Role Creation:** CloudNativePG operator creates the new PostgreSQL role with the password from the secret

3. **Database Creation:** The Database CRD creates the new database owned by the role

4. **Extension Enablement:** A post-upgrade job enables the specified PostgreSQL extensions in the new database

5. **Pooler Configuration:** The role is automatically configured to use the default pooler (or can be customized in `config.rolePoolerMappings`)

#### Step 4: Verify the New Database

Test the new database connection:

```bash
# Run Helm tests to verify connectivity
helm test qs-postgresql-cluster -n pharia-ai
helm test qs-postgresql-db -n pharia-ai

# Check that the secret was created
kubectl get secret qs-postgresql-cluster-access-my-new-app -n pharia-ai

# Verify the database exists
kubectl get database my-new-app -n pharia-ai
```

#### Connection Information for Applications

After the upgrade, applications can connect to the new database using the generated secret:

```yaml
# Example: Use the secret in an application deployment
env:
  - name: DB_HOST
    valueFrom:
      secretKeyRef:
        name: qs-postgresql-cluster-access-my-new-app
        key: host
  - name: DB_PORT
    valueFrom:
      secretKeyRef:
        name: qs-postgresql-cluster-access-my-new-app
        key: port
  - name: DB_USERNAME
    valueFrom:
      secretKeyRef:
        name: qs-postgresql-cluster-access-my-new-app
        key: username
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef:
        name: qs-postgresql-cluster-access-my-new-app
        key: password
  - name: DB_NAME
    valueFrom:
      secretKeyRef:
        name: qs-postgresql-cluster-access-my-new-app
        key: databaseName
  # Or use the complete connection URL
  - name: DATABASE_URL
    valueFrom:
      secretKeyRef:
        name: qs-postgresql-cluster-access-my-new-app
        key: databaseUrl
```

### Pharia Application Connections

The PostgreSQL setup supports the following Pharia applications and components:

#### Pharia Cluster Applications

| Application | Database | User |
|------------|----------|------|
| Document Index | `document-index` | `document_index` |
| Pharia OS | `pharia-os` | `pharia_os` |
| Inference API | `inference-api` | `inference_api` |
| Pharia Studio | `pharia-studio` | `pharia_studio` |
| OAuth Gateway | `pharia-oauth-gateway` | `pharia_oauth_gateway` |
| Pharia Assistant | `pharia-assistant` | `pharia_assistant` |
| Pharia Chat | `pharia-chat` | `pharia_chat` |
| Pharia Catch | `pharia-catch` | `pharia_catch` |
| Pharia Conductor | `pharia-conductor` | `pharia_conductor` |
| Pharia Numinous | `pharia-numinous` | `pharia_numinous` |
| Pharia Transcribe | `pharia-transcribe-app` | `pharia_transcribe_app` |
| Pharia Data | `pharia-data` | `pharia_data` |
| Zitadel | `zitadel` | `zitadel` |
| OpenFGA | `openfga` | `openfga` |
| Dex | `dex` | `dex` |
| MLflow | `mlflow` | `mlflow` |

#### Temporal Cluster Applications

| Application | Database | User |
|------------|----------|------|
| Temporal | `temporal` | `temporal` |
| Temporal Visibility | `temporal-visibility` | `temporal_visibility` |

**Connection Configuration:**
- Applications use the pooler endpoints by default (configured via `config.defaultPooler`)
- Secrets automatically contain the correct connection endpoint based on role-pooler mappings
- Applications can connect using the credentials from their respective secrets

### Secret Content

The secret generation job creates Kubernetes secrets for each database role with the following keys:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: qs-postgresql-cluster-access-{role-name}
  labels:
    app.kubernetes.io/managed-by: Helm
    qs-postgresql-cluster/name: {cluster-name}
    qs-postgresql-cluster/type: access-secret
type: Opaque
data:
  username: {base64-encoded-username}
  user: {base64-encoded-username}      # Alias for username
  password: {base64-encoded-password}  # 25-character random password
  host: {base64-encoded-host}          # Pooler or direct endpoint
  port: {base64-encoded-port}          # Default: 5432
  protocol: {base64-encoded-protocol}  # Default: postgres
  databaseName: {base64-encoded-database}
  databaseUrl: {base64-encoded-url}    # Complete connection URL
```

**Secret Details:**
- **username / user:** Matches the role name (e.g., `pharia_os`, `document_index`). Both keys contain the same value for compatibility.
- **password:** 25-character cryptographically secure random password (preserved across upgrades)
- **host:** Connection endpoint based on role-pooler mapping:
  - Pooler: `{cluster-name}-pooler-{pooler-name}` (e.g., `qs-postgresql-cluster-pharia-pooler-transaction`)
  - Direct: `{cluster-name}-rw` (e.g., `qs-postgresql-cluster-pharia-rw`)
- **port:** PostgreSQL port (default: 5432)
- **protocol:** Connection protocol (default: `postgres`)
- **databaseName:** The database name the user has access to
- **databaseUrl:** Complete PostgreSQL connection string in format: `postgres://{username}:{password}@{host}:{port}/{database}`

**Password Generation:**
- Passwords are generated using OpenSSL: `openssl rand -base64 32 | tr -d "=+/" | cut -c1-25`
- Existing passwords are preserved during helm upgrades
- Each role has a unique password

### Verification

You can verify the PostgreSQL setup using Helm tests:

```bash
# Test the PostgreSQL cluster connectivity
helm test qs-postgresql-cluster -n pharia-ai

# Test the database resources
helm test qs-postgresql-db -n pharia-ai
```

**What the tests verify:**
- PostgreSQL cluster is ready and accepting connections
- All poolers (transaction/session mode) are operational
- Each database role can authenticate successfully
- Roles can connect via their configured endpoint (pooler or direct)
- Roles can connect via all available endpoints (direct cluster, transaction pooler, session pooler)
- Secret configuration matches the role-pooler mappings
- Basic SQL queries execute successfully
- Database extensions are enabled correctly
- Database isolation is enforced

**Test Output Example:**
```
════════════════════════════════════════════════════════════════
  PostgreSQL Cluster Connection Test
  Cluster: Pharia
════════════════════════════════════════════════════════════════

✅ PostgreSQL cluster (direct) is ready
✅ Pooler (transaction mode) is ready

  Testing User: pharia_os
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Test 0: Secret Configuration Validation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Expected host: qs-postgresql-cluster-pharia-pooler-transaction
  Secret host:   qs-postgresql-cluster-pharia-pooler-transaction
  ✅ PASS - Secret contains correct host based on config
  📍 Role uses default pooler

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Connection: Configured Endpoint (from secret)
  Host: qs-postgresql-cluster-pharia-pooler-transaction
  User: pharia_os
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Test 1: Basic connectivity... ✅ PASS
  Test 2: User verification... ✅ PASS
  Test 3: Query execution... ✅ PASS
  Summary: 3 passed, 0 failed

✅ All tests passed successfully!
```

### Backup and Disaster Recovery

The PostgreSQL clusters support automated backups to S3-compatible storage (AWS S3, MinIO, etc.) using CloudNativePG's built-in backup capabilities. Both `clusterPharia` and `clusterTemporal` have identical backup configuration structures.

#### Backup Configuration

Backups are **disabled by default** and must be explicitly enabled and configured. The backup configuration is located in `qs-postgresql-cluster/values.yaml`:

- **`clusterPharia.backups`**: Backup configuration for Pharia applications cluster
- **`clusterTemporal.backups`**: Backup configuration for Temporal workflows cluster

**Key Backup Features:**
- **Continuous WAL Archiving**: Write-Ahead Log files are continuously archived to S3
- **Scheduled Base Backups**: Full database backups on a configurable schedule
- **Point-in-Time Recovery (PITR)**: Restore to any point in time using base backups + WAL files
- **Compression**: WAL and data files are compressed (gzip) to save storage space
- **Retention Policy**: Automatic cleanup of old backups based on configured retention period

#### Enabling Backups

To enable backups for a PostgreSQL cluster, update the `values.yaml` file:

```yaml
# Example for clusterPharia (same structure for clusterTemporal)
clusterPharia:
  backups:
    enabled: true  # Enable backups
    target: prefer-standby  # Run backups on standby replicas to avoid impacting primary
    
    # S3 endpoint (leave empty for AWS S3, set for MinIO or other S3-compatible storage)
    endpointURL: "https://s3.eu-central-1.amazonaws.com"  # or "http://minio.example.com:9000"
    
    # Backup destination path with timestamp for versioning
    destinationPath: "s3://my-backups/postgresql-pharia-2025-11-17/"
    
    # S3 provider configuration
    provider: s3
    s3:
      region: "eu-central-1"
      bucket: "my-backups"
      path: "/"
      accessKey: "YOUR_ACCESS_KEY"
      secretKey: "YOUR_SECRET_KEY"
      # OR use IAM role-based authentication (recommended for AWS):
      inheritFromIAMRole: false  # Set to true to use IAM roles instead of keys
    
    # WAL archiving configuration
    wal:
      compression: gzip
      maxParallel: 8  # Number of parallel WAL archive/restore operations
    
    # Base backup configuration
    data:
      compression: gzip
      jobs: 2  # Number of parallel backup jobs
    
    # Scheduled backup configuration
    scheduledBackups:
      - name: daily-backup
        schedule: "0 0 2 * * *"  # Daily at 2:00 AM (cron format)
        backupOwnerReference: self
        method: barmanObjectStore
    
    # Backup retention policy
    retentionPolicy: "30d"  # Keep backups for 30 days
```

**Important Configuration Notes:**

> **💡 Backup Path Naming Convention:**
> Use timestamp-based paths (e.g., `postgresql-pharia-2025-11-17/`) to enable same-name cluster recovery. This allows the recovery process to read from the old backup path while writing new backups to a fresh timestamped path, preventing WAL archive conflicts.

> **🔒 Security Best Practice:**
> For production, use IAM role-based authentication (`inheritFromIAMRole: true`) instead of hardcoded access keys when running on AWS. For other environments, consider using Kubernetes secrets to manage credentials.

After updating the configuration, apply the changes:

```bash
# Upgrade the PostgreSQL cluster with backup configuration
helm upgrade qs-postgresql-cluster ./qs-postgresql-cluster -n pharia-ai

# Verify backup configuration
kubectl get cluster -n pharia-ai qs-postgresql-cluster-pharia -o jsonpath='{.spec.backup}' | jq
```

#### Verifying Backups

Monitor backup execution and verify backups are working:

```bash
# List all backups
kubectl get backup -n pharia-ai

# Check backup status
kubectl get backup <backup-name> -n pharia-ai -o yaml

# View backup logs
kubectl logs -n pharia-ai -l cnpg.io/cluster=qs-postgresql-cluster-pharia | grep backup
```

**Successful Backup Example:**
```
NAME                                              AGE    CLUSTER                        PHASE       ERROR
qs-postgresql-cluster-pharia-daily-backup-...    5m     qs-postgresql-cluster-pharia   completed   
```

#### Disaster Recovery Guide

Follow these steps to recover a PostgreSQL cluster after a disaster:

##### Step 1: Prepare Recovery Configuration

Update `qs-postgresql-cluster/values.yaml` to configure recovery mode:

```yaml
clusterPharia:
  mode: recovery  # Change from 'standalone' to 'recovery'
  fullnameOverride: qs-postgresql-cluster-pharia  # Keep the SAME cluster name
  
  backups:
    enabled: true
    # NEW timestamp for post-recovery backups
    destinationPath: "s3://my-backups/postgresql-pharia-2025-11-18/"
    # ... (keep same S3 credentials configuration)
  
  recovery:
    method: object_store  # Recover from S3 backup
    
    # The original cluster name in backups (must match the backed-up cluster)
    clusterName: "qs-postgresql-cluster-pharia"
    
    # OLD timestamp to read backups from
    destinationPath: "s3://my-backups/postgresql-pharia-2025-11-17/"
    
    # Recovery target (promote immediately after recovery)
    recoveryTarget: "promote"
    
    # Point-in-Time Recovery (optional)
    pitrTarget:
      time: ""  # Leave empty to recover to latest, or specify RFC3339 timestamp
    
    # S3 configuration (must match backup configuration)
    endpointURL: "https://s3.eu-central-1.amazonaws.com"
    provider: s3
    s3:
      region: "eu-central-1"
      bucket: "my-backups"
      path: "/"
      accessKey: "YOUR_ACCESS_KEY"
      secretKey: "YOUR_SECRET_KEY"
```

**Critical Configuration Points:**

| Configuration | Purpose | Example |
|--------------|---------|---------|
| `mode: recovery` | Enables recovery mode | Required for disaster recovery |
| `backups.destinationPath` | Where NEW backups go | `s3://.../2025-11-18/` (today) |
| `recovery.destinationPath` | Where to READ backups from | `s3://.../2025-11-17/` (yesterday) |
| `recovery.clusterName` | Original cluster name | Must match backed-up cluster |

> **⚠️ Important:** The backup path (`backups.destinationPath`) and recovery path (`recovery.destinationPath`) **must be different** to prevent "Expected empty archive" errors during same-name cluster recovery.

##### Step 2: Delete Old Cluster Resources (if still present)

If the cluster still exists, remove it along with its PVCs:

```bash
# Uninstall the cluster
helm uninstall qs-postgresql-cluster -n pharia-ai

# Delete PVCs (data is in S3 backups)
kubectl delete pvc -n pharia-ai -l cnpg.io/cluster=qs-postgresql-cluster-pharia

# Delete backup resources (optional, data is in S3)
kubectl delete backup -n pharia-ai --all
```

##### Step 3: Install Cluster in Recovery Mode

Deploy the cluster with recovery configuration:

```bash
# Install in recovery mode
helm install qs-postgresql-cluster ./qs-postgresql-cluster -n pharia-ai --timeout=15m

# Monitor recovery progress
kubectl get pods -n pharia-ai -w | grep pharia
```

**Expected Recovery Process:**
1. A recovery job pod (`*-full-recovery-*`) will start
2. The recovery job downloads the base backup from S3
3. WAL files are replayed to reach the recovery target
4. Once complete, the recovery pod shows `Completed` status
5. Primary and replica PostgreSQL pods start normally

```bash
# Check recovery job status
kubectl get pods -n pharia-ai | grep full-recovery

# View recovery logs
kubectl logs -n pharia-ai <recovery-pod-name>
```

##### Step 4: Reinstall Database Resources

After the cluster is recovered, reinstall database definitions:

```bash
# Install database resources (creates databases, extensions, etc.)
helm install qs-postgresql-db ./qs-postgresql-db -n pharia-ai

# Verify databases were created
kubectl get database -n pharia-ai
```

##### Step 5: Verify Data Recovery

Verify that your data was successfully recovered:

```bash
# Connect to the recovered cluster
kubectl exec -n pharia-ai qs-postgresql-cluster-pharia-1 -- psql -U postgres

# Check databases
\l

# Check table data
\c pharia-os
SELECT COUNT(*) FROM your_table;
```

##### Step 6: Switch Back to Standalone Mode

Once recovery is verified, update the configuration for normal operation:

```yaml
clusterPharia:
  mode: standalone  # Switch back to standalone
  # Keep the new backup path for ongoing backups
  backups:
    destinationPath: "s3://my-backups/postgresql-pharia-2025-11-18/"
```

Apply the changes:

```bash
# Upgrade to standalone mode
helm upgrade qs-postgresql-cluster ./qs-postgresql-cluster -n pharia-ai
```

#### Recovery Troubleshooting

**Common Issues:**

| Issue | Cause | Solution |
|-------|-------|----------|
| "Expected empty archive" error | Same path for backup and recovery | Use different `destinationPath` for backups vs recovery |
| "WAL ends before consistent recovery point" | Insufficient WAL files archived | Wait longer after backup before deleting cluster (10-15 min) |
| Recovery pod stuck in Error | Incorrect S3 credentials | Verify `accessKey`, `secretKey`, and `endpointURL` |
| "Backup not found" | Wrong `clusterName` or path | Verify `recovery.clusterName` matches original cluster |

**Recovery Timeline Example:**

```
Day 1 (2025-11-17): Normal Operations
├─ Backups: s3://my-backups/postgresql-pharia-2025-11-17/
└─ Status: Running normally

Day 2 (2025-11-18): DISASTER!
├─ Event: Cluster deleted/corrupted
├─ Action: Configure recovery mode
├─ Recovery FROM: s3://my-backups/postgresql-pharia-2025-11-17/
├─ New backups TO: s3://my-backups/postgresql-pharia-2025-11-18/
└─ Result: Data recovered, cluster operational

Day 3 (2025-11-19): Continue Operations
├─ Switch to: standalone mode
├─ Backups: s3://my-backups/postgresql-pharia-2025-11-19/
└─ Status: Business as usual
```

#### Additional Resources

For detailed backup and recovery configuration options, refer to:
- **CloudNativePG Backup Documentation**: [https://cloudnative-pg.io/documentation/current/backup_recovery/](https://cloudnative-pg.io/documentation/current/backup_recovery/)
- **CloudNativePG Cluster Chart**: [https://github.com/cloudnative-pg/charts/tree/main/charts/cluster](https://github.com/cloudnative-pg/charts/tree/main/charts/cluster)

### Uninstall Process

To uninstall the PostgreSQL setup:

```bash
# Uninstall database resources first
helm uninstall qs-postgresql-db -n pharia-ai

# Uninstall PostgreSQL clusters
helm uninstall qs-postgresql-cluster -n pharia-ai

# Optional: Uninstall the operator (if no other clusters depend on it)
helm uninstall qs-postgresql-operator -n pharia-ai
```

**Important Notes:**
- By default, secrets are **retained** after uninstall (`secretCleanup.retainOnDelete: true`)
- Database data (PVCs) are retained by default according to the cluster's reclaim policy
- To automatically delete secrets on uninstall, set `secretCleanup.retainOnDelete: false`

#### Activating Secret Cleanup

To enable automatic secret deletion on uninstall:

**Option 1: Set during installation**
```bash
helm install qs-postgresql-cluster ./qs-postgresql-cluster \
  --namespace pharia-ai \
  --set secretCleanup.retainOnDelete=false
```

**Option 2: Update existing installation**
```bash
helm upgrade qs-postgresql-cluster ./qs-postgresql-cluster \
  --namespace pharia-ai \
  --set secretCleanup.retainOnDelete=false \
  --reuse-values
```

**What happens when secret cleanup is enabled:**
1. A pre-delete hook Job is executed before uninstallation
2. The Job identifies all secrets with labels:
   - `qs-postgresql-cluster/name={cluster-name}`
   - `qs-postgresql-cluster/type=access-secret`
3. All matching secrets are deleted
4. The cleanup job removes itself after completion

**Warning:** Enable secret cleanup only if you're sure you want to delete all database credentials. This action is irreversible.

### Using Existing Kubernetes Roles

If your cluster has security policies that prevent automatic RBAC resource creation, or if you prefer to manage RBAC separately, you can use existing Kubernetes Roles.

#### Prerequisites

Create a Role with the required permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: my-existing-postgresql-role
  namespace: pharia-ai
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "create", "update", "patch", "delete"]
```

Create a ServiceAccount (if not already existing):

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-existing-serviceaccount
  namespace: pharia-ai
```

Create a RoleBinding:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: my-postgresql-rolebinding
  namespace: pharia-ai
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: my-existing-postgresql-role
subjects:
  - kind: ServiceAccount
    name: my-existing-serviceaccount
    namespace: pharia-ai
```

#### Installation with Existing RBAC

Install the chart using existing RBAC resources:

```bash
helm install qs-postgresql-cluster ./qs-postgresql-cluster \
  --namespace pharia-ai \
  --set rbac.create=false \
  --set rbac.roleName=my-existing-postgresql-role \
  --set serviceAccount.create=false \
  --set serviceAccount.name=my-existing-serviceaccount
```

**Configuration Parameters:**
- `rbac.create=false`: Disables automatic Role creation
- `rbac.roleName`: Name of the existing Role to use
- `serviceAccount.create=false`: Disables automatic ServiceAccount creation
- `serviceAccount.name`: Name of the existing ServiceAccount to use

---

## ⚡ Redis Setup

The Redis setup provides standalone Redis instances for Pharia applications using the Redis Operator.

### Prerequisites

The Redis operator must be installed before deploying Redis instances:

```bash
# Install Redis operator
helm install qs-redis-operator ./qs-redis-operator \
  --namespace pharia-ai \
  --set redis-operator.redisOperator.watchNamespace=pharia-ai
```

> **⚠️ Important - Namespace-Scoped Operator:** The Redis operator is deployed in **namespace-scoped mode only** (not cluster-scoped). This means:
> - The operator will **only watch Redis resources in the namespace specified** by the `watchNamespace` Helm value
> - The `watchNamespace` value **must be set to the same namespace** where you're installing the operator (e.g., `pharia-ai`)
> - If you install the operator in a different namespace, you must update the `watchNamespace` value accordingly
> - The operator **cannot** watch Redis resources in other namespaces or cluster-wide
>
> This namespace-scoped approach provides better security isolation and RBAC control by limiting the operator's permissions to a single namespace.

Wait for the operator to be ready:

```bash
kubectl wait --for=condition=available --timeout=300s \
  deployment/qs-redis-operator-redis-operator \
  -n pharia-ai
```

### Installation Steps

#### Install Redis Instances

```bash
helm install qs-redis ./qs-redis \
  --namespace pharia-ai
```

**What happens during installation:**

1. **Pre-install Hook (RBAC & ServiceAccount):** Creates the ServiceAccount and Role/RoleBinding for secret management
2. **Pre-install Hook (Secret Generation Job):** Executes a Kubernetes Job that:
   - Generates secure random passwords for each Redis instance
   - Creates Kubernetes secrets with connection details (host, port, username, password)
   - Labels secrets for lifecycle management
   - Preserves existing passwords on upgrades
3. **Redis Instance Deployment:** Deploys Redis standalone instances as Custom Resources (Redis CRD)
4. **Operator Processing:** The Redis operator creates the actual Redis StatefulSets and Services

#### Controlling Secret Generation

By default, the chart automatically generates secrets for all Redis instances. You can control this behavior using the `secretGenerationJob.enabled` flag:

**Disable automatic secret generation:**
```bash
helm install qs-redis ./qs-redis \
  --namespace pharia-ai \
  --set secretGenerationJob.enabled=false
```

> **⚠️ Important:** When `secretGenerationJob.enabled=false`, you **must manually create all required secrets** before the Redis instances can start successfully. The Redis operator will fail to create Redis instances if their `redisSecret` references are missing.

**Manual Secret Creation Requirements:**

When automatic secret generation is disabled, you must create secrets for **each Redis instance** defined in the configuration. The secrets must follow this exact structure:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: qs-redis-{application-name}
  namespace: pharia-ai
  labels:
    app.kubernetes.io/managed-by: Helm
    qs-redis/instance: {instance-name}
    qs-redis/type: redis-secret
type: Opaque
stringData:
  host: "{redis-service-name}"               # e.g., "qs-redis-pharia-assistant-api"
  port: "6379"                               # Redis default port
  username: "default"                        # Redis default user
  password: "{secure-random-password}"       # At least 16 characters recommended
```

**Required Secrets for Default Configuration:**

```bash
# Create secret for pharia-assistant-api Redis instance
kubectl create secret generic qs-redis-pharia-assistant-api -n pharia-ai \
  --from-literal=host="qs-redis-pharia-assistant-api" \
  --from-literal=port="6379" \
  --from-literal=username="default" \
  --from-literal=password="$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-25)"

# Create secret for pharia-transcribe-app Redis instance
kubectl create secret generic qs-redis-pharia-transcribe-app -n pharia-ai \
  --from-literal=host="qs-redis-pharia-transcribe-app" \
  --from-literal=port="6379" \
  --from-literal=username="default" \
  --from-literal=password="$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-25)"
```

**Important Notes:**
- The `host` field must match the Redis instance name (the `name` field in `redisStandalone` configuration)
- The default Redis username is `default` - do not change this unless you've configured custom Redis users
- Ensure passwords meet your security requirements (minimum 16 characters recommended)
- The password you set here will be configured in the Redis instance by the Redis operator
- Add appropriate labels to help with secret lifecycle management

**Secret Cleanup Behavior:**

When `secretGenerationJob.enabled=false`, the automatic secret cleanup on uninstall is also disabled, regardless of the `secretCleanup.retainOnDelete` setting. This ensures consistency - if secrets weren't created by the chart, they won't be deleted by it either.

### Supported Applications

The Redis setup provides the following instances for Pharia applications:

| Instance | Secret Name | Application | Description |
|----------|-------------|-------------|-------------|
| `qs-pharia-assistant-api-redis` | `qs-redis-pharia-assistant-api` | Pharia Assistant API | Session storage and caching for assistant service |
| `qs-pharia-transcribe-app-redis` | `qs-redis-pharia-transcribe-app` | Pharia Transcribe App | Queue management for transcription jobs |

**Connection Configuration:**
- **Host:** `{instance-name}` (e.g., `qs-pharia-assistant-api-redis`)
- **Port:** 6379 (default Redis port)
- **Username:** `default` (Redis default user)
- **Authentication:** Password-based authentication enabled

### Secret Content

The secret generation job creates Kubernetes secrets for each Redis instance with the following keys:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: qs-redis-{application-name}
  labels:
    app.kubernetes.io/managed-by: Helm
    qs-redis/instance: {instance-name}
    qs-redis/type: redis-secret
type: Opaque
data:
  host: {base64-encoded-host}          # Redis service name
  port: {base64-encoded-port}          # Default: 6379
  username: {base64-encoded-username}  # Default: "default"
  password: {base64-encoded-password}  # 25-character random password
```

**Secret Details:**
- **Host:** Redis service DNS name within the cluster
- **Port:** Redis port (default: 6379)
- **Username:** Redis username (default: `default`)
- **Password:** 25-character cryptographically secure random password (preserved across upgrades)

**Password Generation:**
- Passwords are generated using OpenSSL: `openssl rand -base64 32 | tr -d "=+/" | cut -c1-25`
- Existing passwords are preserved during helm upgrades
- Each Redis instance has a unique password

### Verification

You can verify the Redis setup using Helm tests:

```bash
# Test Redis connectivity
helm test qs-redis -n pharia-ai
```

**What the tests verify:**
- Redis instances are ready and accepting connections
- Authentication with password works correctly
- Basic Redis commands (PING, SET, GET) execute successfully
- Each instance is accessible from within the cluster

**Test Output Example:**
```
Testing Redis instance: qs-pharia-assistant-api-redis
✅ Redis is ready
✅ Authentication successful
✅ PING command: PONG
✅ SET/GET commands working

Testing Redis instance: qs-pharia-transcribe-app-redis
✅ Redis is ready
✅ Authentication successful
✅ PING command: PONG
✅ SET/GET commands working

All Redis instances are healthy!
```

### Uninstall Process

To uninstall the Redis setup:

```bash
# Uninstall Redis instances
helm uninstall qs-redis -n pharia-ai

# Optional: Uninstall the operator (if no other instances depend on it)
helm uninstall qs-redis-operator -n pharia-ai
```

**Important Notes:**
- By default, secrets are **retained** after uninstall (`secretCleanup.retainOnDelete: true`)
- Redis data (PVCs) may be retained depending on the Redis instance's storage configuration
- To automatically delete secrets on uninstall, set `secretCleanup.retainOnDelete: false`

#### Activating Secret Cleanup

To enable automatic secret deletion on uninstall:

**Option 1: Set during installation**
```bash
helm install qs-redis ./qs-redis \
  --namespace pharia-ai \
  --set secretCleanup.retainOnDelete=false
```

**Option 2: Update existing installation**
```bash
helm upgrade qs-redis ./qs-redis \
  --namespace pharia-ai \
  --set secretCleanup.retainOnDelete=false \
  --reuse-values
```

**What happens when secret cleanup is enabled:**
1. A pre-delete hook Job is executed before uninstallation
2. The Job identifies all secrets with labels:
   - `qs-redis/type=redis-secret`
3. All matching secrets are deleted
4. The cleanup job removes itself after completion

### Using Existing Kubernetes Roles

If your cluster has security policies that prevent automatic RBAC resource creation, you can use existing Kubernetes Roles.

#### Prerequisites

Create a Role with the required permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: my-existing-redis-role
  namespace: pharia-ai
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "create", "update", "patch", "delete"]
```

Create a ServiceAccount and RoleBinding as shown in the PostgreSQL section.

#### Installation with Existing RBAC

```bash
helm install qs-redis ./qs-redis \
  --namespace pharia-ai \
  --set rbac.create=false \
  --set rbac.roleName=my-existing-redis-role \
  --set serviceAccount.create=false \
  --set serviceAccount.name=my-existing-serviceaccount
```

---

## 🪣 MinIO Setup

The MinIO setup provides S3-compatible object storage for Pharia applications.

### Prerequisites

No operator installation required. MinIO instances run as standalone deployments.

### Installation Steps

#### Install MinIO Instances

```bash
helm install qs-minio ./qs-minio \
  --namespace pharia-ai
```

**What happens during installation:**

1. **Pre-install Hook (RBAC & ServiceAccount):** Creates the ServiceAccount and Role/RoleBinding for secret management
2. **Pre-install Hook (Secret Generation Job):** Executes a Kubernetes Job that:
   - Generates secure random credentials for each MinIO instance
   - Creates Kubernetes secrets with access credentials (user, password, host, port)
   - Labels secrets for lifecycle management
   - Preserves existing credentials on upgrades
3. **MinIO Instance Deployment:** Deploys MinIO StatefulSets with the specified bucket configuration
4. **Bucket Creation:** MinIO automatically creates the configured buckets on first startup

#### Controlling Secret Generation

By default, the chart automatically generates secrets for all MinIO instances. You can control this behavior using the `secretGenerationJob.enabled` flag:

**Disable automatic secret generation:**
```bash
helm install qs-minio ./qs-minio \
  --namespace pharia-ai \
  --set secretGenerationJob.enabled=false
```

> **⚠️ Important:** When `secretGenerationJob.enabled=false`, you **must manually create all required secrets** before the MinIO instances can start successfully. MinIO instances reference these secrets for authentication configuration and will fail to start without them.

**Manual Secret Creation Requirements:**

When automatic secret generation is disabled, you must create secrets for **each MinIO instance and its buckets** defined in the configuration. The automatic generation creates two types of secrets per instance:

1. **Instance-level secret:** Contains access credentials for the entire MinIO instance
2. **Bucket-specific secrets:** Contains the same credentials plus the bucket name for each configured bucket

**Instance-level Secret Structure:**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: qs-minio-access-{application-name}
  namespace: pharia-ai
  labels:
    app.kubernetes.io/managed-by: Helm
    qs-minio/instance: {application-name}
    qs-minio/type: access-secret
type: Opaque
stringData:
  user: "{minio-username}"                   # e.g., "pharia-data"
  password: "{secure-random-password}"       # At least 16 characters recommended
  endpointUrl: "{protocol}://{host}:{port}"  # e.g., "http://qs-minio-pharia-data:9000"
```

**Bucket-specific Secret Structure:**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: qs-minio-access-{application-name}-{bucket-name}
  namespace: pharia-ai
  labels:
    app.kubernetes.io/managed-by: Helm
    qs-minio/instance: {application-name}
    qs-minio/type: access-secret
type: Opaque
stringData:
  user: "{minio-username}"                   # Same as instance secret
  password: "{secure-random-password}"       # Same as instance secret
  endpointUrl: "{protocol}://{host}:{port}"  # Same as instance secret
  bucket: "{bucket-name}"                    # Specific bucket name
```

**Required Secrets for Default Configuration:**

<details>
<summary><strong>Pharia Data MinIO Secrets (3 secrets)</strong></summary>

```bash
# Generate password once for this instance
PHARIA_DATA_PASSWORD=$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-25)

# Instance-level secret
kubectl create secret generic qs-minio-access-pharia-data -n pharia-ai \
  --from-literal=user="pharia-data" \
  --from-literal=password="$PHARIA_DATA_PASSWORD" \
  --from-literal=endpointUrl="http://qs-minio-pharia-data:9000"

# Bucket-specific secret for "internal" bucket
kubectl create secret generic qs-minio-access-pharia-data-internal -n pharia-ai \
  --from-literal=user="pharia-data" \
  --from-literal=password="$PHARIA_DATA_PASSWORD" \
  --from-literal=endpointUrl="http://qs-minio-pharia-data:9000" \
  --from-literal=bucket="internal"

# Bucket-specific secret for "external" bucket
kubectl create secret generic qs-minio-access-pharia-data-external -n pharia-ai \
  --from-literal=user="pharia-data" \
  --from-literal=password="$PHARIA_DATA_PASSWORD" \
  --from-literal=endpointUrl="http://qs-minio-pharia-data:9000" \
  --from-literal=bucket="external"
```

</details>


**Important Notes:**
- All secrets for a single MinIO instance **must use the same username and password**
- The `user` field should match the `auth.user` value in the MinIO instance configuration
- The `endpointUrl` format is `{protocol}://{instance-name}:{port}` (e.g., `http://qs-minio-pharia-data:9000`)
- The protocol and port are configurable via `minio.protocol` and `minio.port` in values.yaml (defaults: `http`, `9000`)
- Ensure passwords meet your security requirements (minimum 16 characters recommended)
- The `bucket` field is only present in bucket-specific secrets, not in instance-level secrets
- These credentials will be used to configure the MinIO instance's root user
- Add appropriate labels to help with secret lifecycle management

**Secret Cleanup Behavior:**

When `secretGenerationJob.enabled=false`, the automatic secret cleanup on uninstall is also disabled, regardless of the `secretCleanup.retainOnDelete` setting. This ensures consistency - if secrets weren't created by the chart, they won't be deleted by it either.

### Supported Applications

The MinIO setup provides the following instances for Pharia applications:

| Instance | Secret Name | Buckets | Application | Description |
|----------|-------------|---------|-------------|-------------|
| `qs-minio-pharia-data` | `qs-minio-access-pharia-data` | `internal`, `external` | Pharia Data | General data storage |


**Connection Configuration:**
- **Protocol:** HTTP (configurable via `minio.protocol`)
- **Port:** 9000 (default MinIO API port)
- **Endpoint:** `{instance-name}:{port}` (e.g., `qs-minio-pharia-data:9000`)
- **Access Style:** Path-style (e.g., `http://qs-minio-pharia-data:9000/bucket-name/object-key`)

### Secret Content

The secret generation job creates two types of Kubernetes secrets for each MinIO instance:

#### 1. MinIO Instance Secret

A main secret for accessing the entire MinIO instance:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: qs-minio-access-{application-name}
  labels:
    app.kubernetes.io/managed-by: Helm
    qs-minio/instance: {instance-name}
    qs-minio/type: access-secret
type: Opaque
data:
  user: {base64-encoded-username}           # e.g., "pharia-data"
  password: {base64-encoded-password}       # 25-character random password
  endpointUrl: {base64-encoded-endpoint}    # Complete endpoint URL
```

**Example:** `qs-minio-access-pharia-data` provides access to the entire MinIO instance

#### 2. Bucket-Specific Secrets

Additional secrets created for each configured bucket, containing the same credentials plus the bucket name:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: qs-minio-access-{application-name}-{bucket-name}
  labels:
    app.kubernetes.io/managed-by: Helm
    qs-minio/instance: {instance-name}
    qs-minio/type: access-secret
type: Opaque
data:
  user: {base64-encoded-username}           # Same as instance secret
  password: {base64-encoded-password}       # Same as instance secret
  endpointUrl: {base64-encoded-endpoint}    # Same as instance secret
  bucket: {base64-encoded-bucket}           # Specific bucket name
```

**Examples:**
- `qs-minio-access-pharia-data-internal` → for the `internal` bucket
- `qs-minio-access-pharia-data-external` → for the `external` bucket

#### Secret Key Details:
- **user:** MinIO access key / username (e.g., `pharia-data`)
- **password:** MinIO secret key - 25-character cryptographically secure random password (preserved across upgrades)
- **endpointUrl:** Complete MinIO endpoint URL in format `protocol://host:port` (e.g., `http://qs-minio-pharia-data:9000`)
- **bucket:** Specific bucket name - only present in bucket-specific secrets, allows applications to know exactly which bucket to use

**Password Generation:**
- Passwords are generated using OpenSSL: `openssl rand -base64 32 | tr -d "=+/" | cut -c1-25`
- Existing passwords are preserved during helm upgrades
- Each MinIO instance has unique credentials

### Verification

You can verify the MinIO setup using Helm tests:

```bash
# Test MinIO connectivity
helm test qs-minio -n pharia-ai
```

**What the tests verify:**
- MinIO instances are ready and accepting connections
- Authentication with access credentials works correctly
- Configured buckets exist and are accessible
- Basic S3 operations (list buckets, upload/download objects) work correctly
- Each instance is accessible from within the cluster

**Test Output Example:**
```
Testing MinIO instance: qs-minio-pharia-data
✅ MinIO is ready
✅ Authentication successful
✅ Buckets exist: internal, external
✅ Upload/download test successful

```

### Uninstall Process

To uninstall the MinIO setup:

```bash
# Uninstall MinIO instances
helm uninstall qs-minio -n pharia-ai
```

**Important Notes:**
- By default, secrets are **retained** after uninstall (`secretCleanup.retainOnDelete: true`)
- MinIO data (PVCs) are retained by default according to the storage class reclaim policy
- To automatically delete secrets on uninstall, set `secretCleanup.retainOnDelete: false`
- **Warning:** Uninstalling MinIO will delete all stored objects unless you have backups

#### Activating Secret Cleanup

To enable automatic secret deletion on uninstall:

**Option 1: Set during installation**
```bash
helm install qs-minio ./qs-minio \
  --namespace pharia-ai \
  --set secretCleanup.retainOnDelete=false
```

**Option 2: Update existing installation**
```bash
helm upgrade qs-minio ./qs-minio \
  --namespace pharia-ai \
  --set secretCleanup.retainOnDelete=false \
  --reuse-values
```

**What happens when secret cleanup is enabled:**
1. A pre-delete hook Job is executed before uninstallation
2. The Job identifies all secrets with labels:
   - `qs-minio/type=access-secret`
3. All matching secrets are deleted
4. The cleanup job removes itself after completion

### Using Existing Kubernetes Roles

If your cluster has security policies that prevent automatic RBAC resource creation, you can use existing Kubernetes Roles.

#### Prerequisites

Create a Role with the required permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: my-existing-minio-role
  namespace: pharia-ai
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "create", "update", "patch", "delete"]
```

Create a ServiceAccount and RoleBinding as shown in the PostgreSQL section.

#### Installation with Existing RBAC

```bash
helm install qs-minio ./qs-minio \
  --namespace pharia-ai \
  --set rbac.create=false \
  --set rbac.roleName=my-existing-minio-role \
  --set serviceAccount.create=false \
  --set serviceAccount.name=my-existing-serviceaccount
```

---

## 📝 Additional Notes

### Secret Management Best Practices

1. **Backup Secrets:** Always backup secrets before upgrading or uninstalling:
   ```bash
   kubectl get secrets -n pharia-ai -l app.kubernetes.io/managed-by=Helm -o yaml > secrets-backup.yaml
   ```

2. **Rotate Passwords:** To rotate a password, delete the secret and run helm upgrade:
   ```bash
   kubectl delete secret qs-postgresql-cluster-access-pharia-os -n pharia-ai
   helm upgrade qs-postgresql-cluster ./qs-postgresql-cluster -n pharia-ai
   ```

3. **External Secrets:** For production environments, consider using external secret management solutions (e.g., HashiCorp Vault, AWS Secrets Manager) instead of Kubernetes secrets

### Monitoring and Troubleshooting

**Check operator status:**
```bash
# Check PostgreSQL operator
kubectl get pods -n pharia-ai -l app.kubernetes.io/name=cloudnative-pg

# Check Redis operator
kubectl get pods -n pharia-ai -l app.kubernetes.io/name=redis-operator
```

**View cluster status:**
```bash
kubectl get clusters -n pharia-ai
kubectl get redis -n pharia-ai
```

**Check secret generation job logs:**
```bash
kubectl logs -n pharia-ai -l app.kubernetes.io/component=create-secrets
```

**View connection details from secrets:**
```bash
kubectl get secret qs-postgresql-cluster-access-pharia-os -n pharia-ai -o jsonpath='{.data.host}' | base64 -d
```
