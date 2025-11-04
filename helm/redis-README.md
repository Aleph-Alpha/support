# Redis Charts - OT-CONTAINER-KIT Operator

This directory contains Helm charts for deploying Redis using the **OT-CONTAINER-KIT Redis Operator**.

**Official Documentation:** https://redis-operator.opstree.dev/  
**GitHub:** https://github.com/OT-CONTAINER-KIT/redis-operator

---

## Available Charts

| Chart | When to Install | Purpose |
|-------|----------------|---------|
| **qs-redis-operator-ot** | ✅ **Always (once)** | The operator itself |
| **qs-redis-standalone** | ✅ **For your use case** | Simple Redis |
| **qs-redis-sentinel** | ⚠️ **Only if HA needed** | Redis with automatic failover |
| **qs-redis-cluster** | ⚠️ **Only if sharding needed** | Distributed Redis |

---

## How It Works (Operator Pattern)

```
Step 1: Install Operator (once)
┌────────────────────────────────────┐
│  qs-redis-operator-ot              │
│  - Installs CRDs                   │
│  - Runs operator pod               │
│  - Watches for Redis resources     │
└────────┬───────────────────────────┘
         │
         │ manages
         ↓
Step 2: Deploy Redis (choose one or more)
┌────────────────────────────────────┐
│  qs-redis-standalone               │
│  → Single Redis pod (no Sentinel)  │
└────────────────────────────────────┘
┌────────────────────────────────────┐
│  qs-redis-sentinel                 │
│  → 3 Redis + 3 Sentinels (HA)     │
└────────────────────────────────────┘
┌────────────────────────────────────┐
│  qs-redis-cluster                  │
│  → Redis Cluster (sharding)        │
└────────────────────────────────────┘
```

---

## Chart Details

### qs-redis-operator-ot (The Operator)

**Install:** Once per Kubernetes cluster  
**Purpose:** Manages all Redis instances

**What it creates:**
- Custom Resource Definitions (CRDs)
- Operator deployment (1 pod)
- RBAC resources

---

### qs-redis-standalone

**Install:** Once per Redis instance you need  
**Purpose:** Single Redis pod (no high availability)

**Use Cases:**
- Development/staging environments
- Caching (can tolerate brief downtime)
- Session storage
- Simple key-value store

**What it creates:**
- 1 Redis pod
- 1 Service (ClusterIP)
- Optional: PersistentVolumeClaim
- Optional: Redis Exporter (monitoring)

**Pros:**
- ✅ Simple setup
- ✅ No code changes (direct connection)
- ✅ Low resource usages

**Cons:**
- ⚠️ No automatic failover
- ⚠️ Manual recovery if pod fails

---

### qs-redis-sentinel (High Availability)

**Install:** When you need automatic failover  
**Purpose:** Redis with Sentinel for HA

**Use Cases:**
- Production systems
- Critical data
- Automatic failover requirements
- Cannot tolerate downtime

**What it creates:**
- 3 Redis pods (1 master + 2 replicas)
- 3 Sentinel pods (monitor Redis)
- Services for Redis and Sentinel
- Automatic failover capability

**Pros:**
- ✅ Automatic failover (~30 seconds)
- ✅ High availability
- ✅ Read scaling (replicas)
- ✅ Self-healing

**Cons:**
- ⚠️ Code changes required (Sentinel client)
- ⚠️ More complex setup
- ⚠️ Higher resource usage (6+ pods)

**Connection Example:**
```python
from redis.sentinel import Sentinel

# Sentinel-aware connection
sentinel = Sentinel([('my-redis-sentinel', 26379)], password='secret')
redis_client = sentinel.master_for('mymaster', password='secret', db=0)
```
---

### qs-redis-cluster (Sharding)

**Install:** When you need horizontal scaling  
**Purpose:** Distributed Redis with sharding

**Use Cases:**
- Very large datasets (> 50GB)
- Need horizontal scaling
- High throughput requirements
- Data sharding across nodes

**What it creates:**
- Multiple Redis shards (master + replica per shard)
- Cluster-aware configuration
- Automatic data distribution

**Pros:**
- ✅ Horizontal scaling
- ✅ Data sharding
- ✅ High throughput
- ✅ Built-in HA per shard

**Cons:**
- ⚠️ Code changes required (cluster client)
- ⚠️ Most complex setup
- ⚠️ Highest resource usage
- ⚠️ Some Redis commands not supported in cluster mode

**Connection Example:**
```python
from rediscluster import RedisCluster

startup_nodes = [{"host": "my-redis-cluster", "port": "6379"}]
redis_client = RedisCluster(startup_nodes=startup_nodes)
```
---

## Comparison Table

| Feature | Standalone | Sentinel | Cluster |
|---------|------------|----------|---------|
| **Setup Complexity** | Low | Medium | High |
| **Code Changes** | ❌ No | ✅ Yes | ✅ Yes |
| **High Availability** | ❌ No | ✅ Yes | ✅ Yes |
| **Automatic Failover** | ❌ No | ✅ Yes (~30s) | ✅ Yes |
| **Read Scaling** | ❌ No | ⚠️ Limited | ✅ Yes |
| **Write Scaling** | ❌ No | ❌ No | ✅ Yes |
| **Data Sharding** | ❌ No | ❌ No | ✅ Yes |
| **Pods Required** | 1-2 | 6-9 | 9+ |
| **Resource Usage** | Low | Medium | High |
| **Connection** | Direct | Via Sentinel | Cluster-aware |
| **Best For** | Simple use cases | Production HA | Large scale |

---