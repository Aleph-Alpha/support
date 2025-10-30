# QS PgBouncer Helm Chart

A Helm chart that deploys multiple PgBouncer instances for connection pooling to PostgreSQL clusters.

## Overview

This chart is a wrapper that deploys multiple PgBouncer instances, each configured to connect to different PostgreSQL clusters:

- **PgBouncer Pharia**: Connection pooler for the Pharia PostgreSQL cluster
- **PgBouncer Temporal**: Connection pooler for the Temporal PostgreSQL cluster

Each instance can be independently enabled/disabled and configured with its own resource limits, replica counts, and monitoring settings.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.0+
- PostgreSQL clusters (CloudNativePG recommended)
- Secrets containing user authentication information

## Installation

### Add Dependencies

First, ensure the pgbouncer subchart is available:

```bash
helm dependency update
```

### Install the Chart

```bash
helm install qs-pgbouncer . -n <namespace>
```

### Install with Custom Values

```bash
helm install qs-pgbouncer . -n <namespace> -f custom-values.yaml
```

## Configuration

### Basic Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `nameOverride` | Override the chart name | `""` |

### PgBouncer Pharia Instance

| Parameter | Description | Default |
|-----------|-------------|---------|
| `pgbouncerPharia.enabled` | Enable PgBouncer for Pharia | `true` |
| `pgbouncerPharia.replicaCount` | Number of replicas | `3` |
| `pgbouncerPharia.antiAffinity` | Pod anti-affinity (soft/hard) | `soft` |
| `pgbouncerPharia.databases.*` | Database connection settings | See values.yaml |
| `pgbouncerPharia.userlist.secret` | Secret containing userlist | `pgbouncer-pharia-userlist` |
| `pgbouncerPharia.resources` | Resource limits and requests | See values.yaml |

### PgBouncer Temporal Instance

| Parameter | Description | Default |
|-----------|-------------|---------|
| `pgbouncerTemporal.enabled` | Enable PgBouncer for Temporal | `true` |
| `pgbouncerTemporal.replicaCount` | Number of replicas | `3` |
| `pgbouncerTemporal.antiAffinity` | Pod anti-affinity (soft/hard) | `soft` |
| `pgbouncerTemporal.databases.*` | Database connection settings | See values.yaml |
| `pgbouncerTemporal.userlist.secret` | Secret containing userlist | `pgbouncer-temporal-userlist` |
| `pgbouncerTemporal.resources` | Resource limits and requests | See values.yaml |

### Monitoring

Both PgBouncer instances support Prometheus monitoring via:

- **pgbouncerExporter**: Metrics exporter container configuration
- **serviceMonitor**: Prometheus Operator ServiceMonitor configuration

To enable monitoring, configure the `pgbouncerExporter` and `serviceMonitor` sections for each instance.

## Architecture

```
┌─────────────────────────────────────────────────┐
│             qs-pgbouncer Chart                  │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌──────────────────┐  ┌───────────────────┐  │
│  │ PgBouncer Pharia │  │ PgBouncer Temporal│  │
│  │   (3 replicas)   │  │    (3 replicas)   │  │
│  └────────┬─────────┘  └─────────┬─────────┘  │
│           │                       │             │
└───────────┼───────────────────────┼─────────────┘
            │                       │
            ▼                       ▼
    ┌───────────────┐       ┌──────────────┐
    │ Pharia        │       │ Temporal     │
    │ PostgreSQL    │       │ PostgreSQL   │
    └───────────────┘       └──────────────┘
```

## Examples

### Disable Temporal Instance

```yaml
pgbouncerTemporal:
  enabled: false
```

### Increase Pharia Resources

```yaml
pgbouncerPharia:
  resources:
    limits:
      cpu: "8"
      memory: 4Gi
    requests:
      cpu: "2"
      memory: 1Gi
```

### Enable Monitoring

```yaml
pgbouncerPharia:
  serviceMonitor:
    enabled: true
    interval: 15s
```

## Testing

The chart includes Helm tests to verify PgBouncer connectivity and authentication.

### Run Tests

After installing the chart, run the tests:

```bash
helm test qs-pgbouncer -n <namespace>
```

### What Tests Verify

For each enabled PgBouncer instance, the tests will:

1. **PgBouncer Connectivity** - Verify connection to PgBouncer service
2. **User Authentication** - Confirm each user from userlist can authenticate
3. **Database Selection** - Verify correct database routing
4. **Query Execution** - Test basic SQL query execution

The tests parse the userlist secret and automatically test all configured users, applying the database naming logic:
- Users with underscores (e.g., `pharia_studio_db`) → database `pharia-studio-db`
- Users without underscores (e.g., `payment`) → database `payment`

### Test Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `tests.image` | Container image for tests | `postgres:17` |
| `tests.sslMode` | SSL mode for connections | `prefer` |

## Uninstall

```bash
helm uninstall qs-pgbouncer -n <namespace>
```

## References

- [PgBouncer Documentation](https://www.pgbouncer.org/)
- [CloudNativePG](https://cloudnative-pg.io/)
- [PgBouncer Container Images](https://github.com/cloudnative-pg/pgbouncer-containers)

## License

See [LICENSE](../../LICENSE) file.

