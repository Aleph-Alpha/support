# Redis Operator - Quick Start Guide

## What is RedisFailover?

**RedisFailover** is a high-availability Redis deployment pattern that uses Redis Sentinel to provide automatic failover capabilities. This ensures your Redis instance remains available even when the master node fails.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RedisFailover Cluster                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Redis Nodes (Master-Replica)         Sentinel Monitors     │
│  ┌──────────┐                         ┌──────────┐          │
│  │  Master  │◄────────monitors────────│Sentinel 1│          │
│  │  Redis   │                         └──────────┘          │
│  └────┬─────┘                         ┌──────────┐          │
│       │                               │Sentinel 2│          │
│       │ replicates                    └──────────┘          │
│       ↓                               ┌──────────┐          │
│  ┌──────────┐                         │Sentinel 3│          │
│  │ Replica  │                         └──────────┘          │
│  │  Redis   │                              ↓                │
│  └──────────┘                         Auto-failover         │
│  ┌──────────┐                         on master failure     │
│  │ Replica  │                                               │
│  │  Redis   │                                               │
│  └──────────┘                                               │
└─────────────────────────────────────────────────────────────┘
```

### How It Works

1. **Normal Operation:**
   - One Redis instance acts as **Master** (accepts writes)
   - Other Redis instances are **Replicas** (read-only, sync from master)
   - Sentinel instances **monitor** the master's health

2. **When Master Fails:**
   - Sentinels detect the master is down
   - Sentinels hold an election and agree on the failure
   - Sentinels **automatically promote** a replica to be the new master
   - Other replicas are reconfigured to replicate from the new master
   - Applications are redirected to the new master

3. **Self-Healing:**
   - The old master (when recovered) rejoins as a replica
   - No manual intervention required!

## Example RedisFailover Resource

Here's a simple example of creating a RedisFailover:

```yaml
apiVersion: databases.spotahome.com/v1
kind: RedisFailover
metadata:
  name: my-redis-cluster
  namespace: default
spec:
  # Redis Configuration
  redis:
    replicas: 3                    # 1 master + 2 replicas
    resources:
      requests:
        cpu: 100m
        memory: 128Mi
      limits:
        cpu: 400m
        memory: 512Mi
    storage:
      persistentVolumeClaim:
        metadata:
          name: redis-data
        spec:
          accessModes:
            - ReadWriteOnce
          resources:
            requests:
              storage: 1Gi
  
  # Sentinel Configuration
  sentinel:
    replicas: 3                    # 3 sentinels for quorum
    resources:
      requests:
        cpu: 50m
        memory: 64Mi
      limits:
        cpu: 100m
        memory: 128Mi
```

## Connecting to RedisFailover

Applications connect through the **Sentinel service** (not directly to Redis):

```bash
# Service name format: rfs-<NAME>
# Port: 26379 (Sentinel default)
# Master name: mymaster

redis-cli -h rfs-my-redis-cluster -p 26379
SENTINEL get-master-addr-by-name mymaster
```

Your application should use a **Sentinel-aware Redis client** that:
- Connects to Sentinels
- Asks for the current master
- Automatically switches when failover occurs

## Common Use Cases

| Use Case | Configuration |
|----------|---------------|
| **Development** | 1 Redis + 1 Sentinel (minimal) |
| **Production** | 3+ Redis + 3+ Sentinels (HA) |
| **High Traffic** | 5+ Redis + 3 Sentinels (read scaling) |

## Key Benefits

✅ **Automatic Failover** - No manual intervention needed
✅ **High Availability** - Minimal downtime during failures  
✅ **Read Scaling** - Multiple replicas for read queries
✅ **Data Persistence** - Optional persistent volumes
✅ **Monitoring** - Built-in health checks

## Installation

```bash
# Install the operator (includes CRD)
helm install redis-operator ./helm/qs-redis-operator

# Create a RedisFailover instance
kubectl apply -f my-redisfailover.yaml

# Check status
kubectl get redisfailover
kubectl get pods -l app.kubernetes.io/part-of=my-redis-cluster
```

## For More Information

- [Spotahome Redis Operator GitHub](https://github.com/spotahome/redis-operator)
- [Redis Sentinel Documentation](https://redis.io/docs/management/sentinel/)

