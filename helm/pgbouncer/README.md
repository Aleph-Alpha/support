# PgBouncer Helm Chart

A Helm chart for deploying PgBouncer, a lightweight connection pooler for PostgreSQL.

## Overview

This chart deploys PgBouncer on a Kubernetes cluster using the Helm package manager. PgBouncer is a connection pooler that sits between your application and PostgreSQL database, reducing connection overhead and improving database performance.

## Features

- **High Availability**: Configurable replica count with pod anti-affinity
- **Connection Pooling**: Transaction, session, and statement-level pooling modes
- **TLS Support**: Client and server TLS configuration
- **Monitoring**: Optional Prometheus metrics exporter and ServiceMonitor
- **Security**: Pod security context and container security controls
- **Flexible Configuration**: Full PgBouncer configuration options exposed

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- PostgreSQL database (CloudNativePG recommended)

## Installation

### Basic Installation

```bash
helm install my-pgbouncer . -n <namespace>
```

### Install with Custom Values

```bash
helm install my-pgbouncer . -n <namespace> -f custom-values.yaml
```

## Configuration

### Basic Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `nameOverride` | Override the chart name | `"pgbouncer"` |
| `replicaCount` | Number of PgBouncer replicas | `1` |
| `image.repository` | PgBouncer container image | `ghcr.io/cloudnative-pg/pgbouncer` |
| `image.tag` | PgBouncer image tag | `1.24.0-14` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |

### High Availability Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `antiAffinity` | Pod anti-affinity (soft/hard) | `hard` |
| `maxUnavailable` | PodDisruptionBudget max unavailable | `1` |
| `nodeAffinity` | Node affinity configuration | `{}` |
| `tolerations` | Tolerations for node taints | `[]` |
| `nodeSelector` | Node selector for pod assignment | `{}` |

### Deployment Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `deployment.containerPort` | Port PgBouncer listens on | `6432` |
| `deployment.terminationGracePeriodSeconds` | Graceful shutdown timeout | `120` |
| `deployment.readinessProbe.enabled` | Enable readiness probe | `true` |
| `deployment.livenessProbe.enabled` | Enable liveness probe | `true` |
| `deployment.strategy.type` | Deployment strategy | `RollingUpdate` |

### Service Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.type` | Service type | `ClusterIP` |
| `service.ports[0].port` | Service port | `5432` |
| `service.ports[0].targetPort` | Container target port | `6432` |

### Database Configuration

Configure database connections in the `databases` section:

```yaml
databases:
  my-database:
    host: "postgres.example.com"
    port: 5432
    dbname: mydb
    user: myuser
    pool_mode: transaction
    pool_size: 20
```

### PgBouncer Configuration

Key PgBouncer settings under the `pgbouncer` section:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `pgbouncer.pool_mode` | Pooling mode (session/transaction/statement) | `transaction` |
| `pgbouncer.max_client_conn` | Maximum client connections | `300` |
| `pgbouncer.default_pool_size` | Default pool size per user/database | `20` |
| `pgbouncer.auth_type` | Authentication type | `scram-sha-256` |
| `pgbouncer.auth_file` | Authentication file path | `/etc/pgbouncer/userlist.txt` |
| `pgbouncer.log_connections` | Log connections | `0` |
| `pgbouncer.log_disconnections` | Log disconnections | `0` |
| `pgbouncer.log_pooler_errors` | Log pooler errors | `1` |

### Resource Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `resources.limits.cpu` | CPU limit | `"1"` |
| `resources.requests.cpu` | CPU request | `"1"` |
| `resources.requests.memory` | Memory request | `20Mi` |

### Security Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `security.runAsUser` | User ID for PgBouncer | `998` |
| `security.fsGroup` | Group ID for filesystem | `996` |
| `containerSecurityContext.runAsNonRoot` | Run as non-root | `true` |
| `containerSecurityContext.allowPrivilegeEscalation` | Allow privilege escalation | `false` |

### Monitoring Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceMonitor.enabled` | Enable ServiceMonitor | `false` |
| `serviceMonitor.interval` | Scrape interval | `30s` |
| `serviceMonitor.scrapeTimeout` | Scrape timeout | `10s` |
| `serviceMonitor.path` | Metrics endpoint path | `/metrics` |

## Examples

### Basic PgBouncer with Database Connection

```yaml
databases:
  my-app:
    host: "postgres-cluster-rw.default.svc.cluster.local"
    port: 5432
    dbname: myapp
    pool_mode: transaction
    pool_size: 25

userlist:
  secret: my-pgbouncer-userlist

replicaCount: 3
antiAffinity: soft

resources:
  limits:
    cpu: "2"
    memory: 1Gi
  requests:
    cpu: "500m"
    memory: 256Mi
```

### PgBouncer with Monitoring

```yaml
databases:
  "*":
    host: "postgres-cluster-rw"
    port: 5432

userlist:
  secret: pgbouncer-userlist

pgbouncerExporter:
  - name: metrics-exporter
    image: quay.io/prometheuscommunity/pgbouncer-exporter:v0.11.0
    ports:
      - name: metrics
        containerPort: 9127
    args:
      - --web.listen-address=:9127
      - --web.telemetry-path=/metrics
      - --log.level=error
      - --pgBouncer.connectionString=postgres://$(PGBOUNCER_USER):$(PGBOUNCER_PWD)@localhost:6432/pgbouncer?sslmode=disable&connect_timeout=10
    env:
      - name: PGBOUNCER_USER
        valueFrom:
          secretKeyRef:
            name: "pgbouncer-credentials"
            key: user
      - name: PGBOUNCER_PWD
        valueFrom:
          secretKeyRef:
            name: "pgbouncer-credentials"
            key: password

serviceMonitor:
  enabled: true
  interval: 15s
```

### High Availability Configuration

```yaml
replicaCount: 5
antiAffinity: hard

deployment:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 2

maxUnavailable: 2

nodeAffinity:
  requiredDuringSchedulingIgnoredDuringExecution:
    nodeSelectorTerms:
    - matchExpressions:
      - key: node-role.kubernetes.io/database
        operator: In
        values:
        - "true"

resources:
  limits:
    cpu: "4"
    memory: 2Gi
  requests:
    cpu: "1"
    memory: 512Mi
```

### Custom PgBouncer Configuration

```yaml
pgbouncer:
  pool_mode: transaction
  max_client_conn: 500
  default_pool_size: 30
  min_pool_size: 5
  reserve_pool_size: 5
  reserve_pool_timeout: 3
  
  # Timeouts
  server_idle_timeout: 600
  query_wait_timeout: 120
  
  # Logging
  log_connections: 1
  log_disconnections: 1
  log_pooler_errors: 1
  
  # Authentication
  auth_type: scram-sha-256
  auth_file: /etc/pgbouncer/userlist.txt
```

## Architecture

```
┌──────────────┐
│   Clients    │
└──────┬───────┘
       │
       │ Port 5432 (Service)
       │
       ▼
┌──────────────────────────────┐
│   PgBouncer Deployment       │
│   ┌────────┐  ┌────────┐    │
│   │  Pod 1 │  │  Pod 2 │    │
│   │  6432  │  │  6432  │    │
│   └────────┘  └────────┘    │
└──────────┬───────────────────┘
           │
           │ Backend Connection
           │
           ▼
    ┌──────────────┐
    │  PostgreSQL  │
    │   Database   │
    └──────────────┘
```

## Authentication

PgBouncer requires a userlist file containing username/password pairs. This should be provided as a Kubernetes Secret.

### Create Userlist Secret

Generate userlist from PostgreSQL:

```bash
psql -Atq -U postgres -d postgres -c \
  "SELECT concat('\"', usename, '\" \"', passwd, '\"') FROM pg_shadow;" \
  > userlist.txt

kubectl create secret generic pgbouncer-userlist \
  --from-file=userlist.txt=userlist.txt \
  -n <namespace>
```

Reference the secret in values.yaml:

```yaml
userlist:
  secret: pgbouncer-userlist
```

## Pooling Modes

PgBouncer supports three pooling modes:

- **Session**: Connection returned to pool after client disconnects (most compatible)
- **Transaction**: Connection returned after transaction ends (recommended)
- **Statement**: Connection returned after each statement (not recommended for prepared statements)

## Troubleshooting

### Check PgBouncer Logs

```bash
kubectl logs -n <namespace> -l app.kubernetes.io/name=pgbouncer
```

### Verify Configuration

```bash
kubectl exec -n <namespace> <pgbouncer-pod> -- cat /etc/pgbouncer/pgbouncer.ini
```

### Test Connection

```bash
psql -h <pgbouncer-service> -p 5432 -U <username> -d <database>
```

### Check PgBouncer Stats

Connect to the pgbouncer admin database:

```bash
psql -h <pgbouncer-service> -p 5432 -U <admin-user> pgbouncer
```

Then run:
```sql
SHOW POOLS;
SHOW DATABASES;
SHOW STATS;
```

## Uninstall

```bash
helm uninstall my-pgbouncer -n <namespace>
```

## References

- [PgBouncer Documentation](https://www.pgbouncer.org/)
- [PgBouncer Configuration](https://www.pgbouncer.org/config.html)
- [CloudNativePG PgBouncer Containers](https://github.com/cloudnative-pg/pgbouncer-containers)
- [PgBouncer Usage Guide](https://www.pgbouncer.org/usage.html)

## License

See [LICENSE](../../LICENSE) file.

