# qs-pgbouncer Helm Chart

A Helm chart that orchestrates multiple PgBouncer connection pooler instances ("Pharia" and "Temporal") backed by the upstream `pgbouncer` sub‑chart. It adds opinionated multi‑instance management, secret automation, and test hooks.

## ✨ Features
- Multi‑instance support (independent configuration blocks for `pgbouncerPharia` and `pgbouncerTemporal`)
- Automatic discovery of CloudNativePG (or similarly labeled) PostgreSQL user credentials to build `userlist.txt`
- Creation of admin secret with distinct `adminUser` / `adminPassword` keys
- Optional per‑instance pooling mode overrides (e.g. `pharia-os` forced to session pool)
- Pre‑install / pre‑upgrade hooks to (re)generate secrets before dependent pods roll
- Affinity and anti‑affinity defaults for improved HA distribution
- Init container validation of `userlist.txt` presence + non‑empty check
- Helm test pods perform connectivity + basic credential rotation validation
- Metrics exporter sidecar enablement and ServiceMonitor support (when CRD present)

## 📦 Dependencies
Two aliased dependencies on upstream `pgbouncer` chart (version `4.0.2`):
```
pgbouncerPharia  -> condition: pgbouncerPharia.enabled
pgbouncerTemporal -> condition: pgbouncerTemporal.enabled
```
Each is rendered only if its `enabled` flag is true.

## ✅ Requirements
- Kubernetes ≥ 1.23
- Existing PostgreSQL clusters exposing secrets labeled:
  - `app.kubernetes.io/name=qs-postgresql-cluster`
  - `qs-postgresql-cluster/name=<cluster-name>` (e.g. `cluster-pharia`, `cluster-temporal`)
- A Prometheus stack (optional) if metrics scraping is desired

## 🚀 Installation
```bash
helm repo add aleph-alpha-support <your-repo-url>
helm repo update
helm install my-pgbouncer ./qs-pgbouncer \
  --set pgbouncerPharia.enabled=true \
  --set pgbouncerTemporal.enabled=true
```

## 🔄 Upgrading
Secrets are regenerated on every upgrade via Helm hooks. If credential content changes the corresponding PgBouncer deployment is safely restarted using `kubectl rollout restart` logic from the hook jobs.

```bash
helm upgrade my-pgbouncer ./qs-pgbouncer -f custom-values.yaml
```

Run tests after upgrade:
```bash
helm test my-pgbouncer
```

## 🛠 Configuration Overview
Below is a condensed reference (see `values.yaml` for full inline documentation). Only the most relevant knobs are listed.

| Key | Description | Default |
|-----|-------------|---------|
| `fullnameOverride` | Release-wide name override | `qs-pgbouncer` |
| `tests.image` | Image for Helm tests | `postgres:17` |
| `pgbouncerPharia.enabled` | Enable Pharia instance | `true` |
| `pgbouncerPharia.replicaCount` | Replica count | `3` |
| `pgbouncerPharia.config.databases["*"]` | Default host/port routing | `cluster-pharia-rw:5432` |
| `pgbouncerPharia.config.databases["pharia-os"].pool_mode` | Per-db override | `session` |
| `pgbouncerPharia.config.pgbouncer.pool_mode` | Base pool mode | `transaction` |
| `pgbouncerPharia.config.pgbouncer.max_client_conn` | Max clients | `300` |
| `pgbouncerPharia.config.existingUserlistSecret` | Userlist secret name | `pgbouncer-pharia-userlist` |
| `pgbouncerPharia.config.existingAdminSecret` | Admin secret name | `pgbouncer-pharia-admin` |
| `pgbouncerPharia.resources.requests.cpu` | CPU request | `50m` |
| `pgbouncerPharia.affinity.podAntiAffinity` | Spreads pods | Preferred anti-affinity |
| `pgbouncerPharia.pgbouncerExporter.enabled` | Metrics sidecar | `true` |
| `pgbouncerTemporal.enabled` | Enable Temporal instance | `true` |
| `pgbouncerTemporal.replicaCount` | Replica count | `3` |
| `pgbouncerTemporal.config.pgbouncer.pool_mode` | Pool mode | `session` |
| `pgbouncerTemporal.config.pgbouncer.max_client_conn` | Max clients | `200` |
| `pgbouncerTemporal.pdb.maxUnavailable` | PDB disruption budget | `1` |
| `pgbouncerTemporal.config.existingAdminSecret` | Admin secret | `pgbouncer-temporal-admin` |
| `pgbouncerTemporal.config.existingUserlistSecret` | Userlist secret | `pgbouncer-temporal-userlist` |

### Secret Automation
Hook jobs inspect PostgreSQL cluster secrets for fields (`username` or `user`, plus `password`) to assemble `userlist.txt`. The PgBouncer user (`pgbouncer`) is reused for the admin secret:
```
adminSecret:
  adminUser: pgbouncer
  adminPassword: <same as discovered password>
```

### Restart Semantics
Deployments restart only when secret content truly changes (comparison before replacement). Rollouts use:
```
kubectl rollout restart deployment pgbouncer-pharia
kubectl rollout restart deployment pgbouncer-temporal
```

## 🔐 Production Readiness Assessment
This chart has many solid building blocks but a few gaps remain before calling it "production grade" in stricter environments.

### Strengths
- Multi-instance abstraction keeps concerns separated
- Affinity + PDB (Temporal) improve resilience
- Resource requests/limits defined
- Secret content change detection avoids noisy restarts
- SCRAM authentication assumed (secure hashing)
- Tests exercise connectivity

### Gaps & Recommendations
| Area | Current State | Recommendation |
|------|---------------|----------------|
| Liveness/Readiness Probes | Not explicitly set (rely on dependency defaults?) | Add explicit `readinessProbe` using `pg_isready` and a simple TCP `livenessProbe` override via values passthrough. |
| securityContext / podSecurityContext | Not exposed in wrapper values | Surface `podSecurityContext` and `securityContext` to enforce non-root UID/GID, drop capabilities (e.g. `NET_RAW`), readOnlyRootFilesystem. |
| NetworkPolicy | None provided | Add optional `networkPolicy.enabled` to restrict ingress to application namespaces and Prometheus. |
| TLS Between Clients and PgBouncer | Not documented; assumes cluster TLS only | Optionally mount client CA, enforce `client_tls_sslmode=require`, provide toggle. |
| Metrics ServiceMonitor | Only references exporter + expects external handling | Add top-level `serviceMonitor.enabled` + labels/interval configuration for both instances. |
| Horizontal Pod Autoscaling | Static replica counts | Offer HPA block (`enabled`, `minReplicas`, `maxReplicas`, CPU/connection-based metrics). |
| Logging Configuration | Stdout only | Allow override of log level and exporter verbosity. |
| Versioning | Chart version still `0.1.0` | Adopt semantic versioning; bump after each change; add CHANGELOG entries. |
| Tests | Functional connection only | Add test verifying number of pooled connections and rejection when exceeding `max_client_conn`. |
| Secret Rotation Policy | Manual (on upgrade) | Document procedures; optionally add CronJob to periodically rebuild userlist. |
| Resource Consumption Observability | Basic metrics only | Add Grafana dashboard pointers + alerts (pool saturation, auth failures). |
| Graceful Shutdown | Not documented | Ensure `terminationGracePeriodSeconds` configurable and `SIGINT` handling (the dependency may do this). |

### Suggested Next Steps
1. Expose probe + security contexts in `values.yaml` (wrapper pass-through to dependency).
2. Add optional `NetworkPolicy` template.
3. Implement `serviceMonitor` per instance (already partial) with robust label selection.
4. Provide `hpa.yaml` guarded by `pgbouncerPharia.hpa.enabled` / `pgbouncerTemporal.hpa.enabled`.
5. Add connection saturation and latency tests into `tests/test-connection.yaml`.
6. Bump chart version and document in `CHANGELOG.md`.

## 🔧 Example Customization
```yaml
pgbouncerPharia:
  replicaCount: 4
  config:
    pgbouncer:
      pool_mode: transaction
      max_client_conn: 500
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 500m
      memory: 512Mi
  pgbouncerExporter:
    enabled: true

pgbouncerTemporal:
  pdb:
    maxUnavailable: 1
  config:
    pgbouncer:
      pool_mode: session
      default_pool_size: 50
      max_client_conn: 400
```

## 🧪 Testing
```bash
helm test my-pgbouncer
kubectl logs job/my-pgbouncer-userlist-pharia   # Inspect secret creation
kubectl logs job/my-pgbouncer-userlist-temporal # Inspect secret creation
```

## 🩺 Troubleshooting
| Symptom | Possible Cause | Action |
|---------|----------------|--------|
| Pods CrashLoop | Missing secrets | Verify hook jobs succeeded; check logs. |
| Authentication failures | Stale `userlist.txt` | Run `helm upgrade --force` or manually delete userlist secret to regenerate. |
| High latency | Pool saturation | Increase `default_pool_size` or `max_client_conn`; monitor exporter metrics. |
| No metrics | Exporter disabled or not scraped | Ensure `pgbouncerExporter.enabled=true` and Service/ServiceMonitor created. |

## 🔒 Security Hardening Tips
- Enforce namespace isolation + NetworkPolicies
- Run with non-root UID (already 1001 in jobs; ensure same for dependency pods)
- Restrict secret RBAC to only needed verbs (done) and namespace
- Enable TLS termination at ingress if clients external
- Consider sealing secrets via ExternalSecrets controller (future enhancement)

## 📄 License
See repository top-level `LICENSE`.

## 📚 References
- PgBouncer Docs: https://www.pgbouncer.org
- Connection Pooling Modes: https://www.pgbouncer.org/features.html
- Helm Hooks: https://helm.sh/docs/topics/charts_hooks/

---
_Contributions & improvements welcome—add templates for probes, network policy, and autoscaling to reach full production maturity._
