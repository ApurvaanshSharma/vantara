# Vantara

**AI-native Security Operations Center platform** — an open-source SIEM/SOAR system built to demonstrate SOC engineering, detection engineering, and applied ML for threat detection.

> 🚧 Under active development. Design docs land in [`docs/architecture`](docs/architecture) as each phase is built.

## Status

- [x] Phase 1 — Repo scaffolding & infrastructure skeleton
- [ ] Phase 2 — Backend foundation (FastAPI, Postgres, JWT auth)
- [ ] Phase 3 — Ingestion & normalization pipeline (Redis Streams, Celery, OpenSearch)
- [ ] Phase 4 — Detection engine (Sigma, YARA, MITRE ATT&CK mapping)
- [ ] Phase 5 — Threat intelligence enrichment (AbuseIPDB, AlienVault OTX)
- [x] Phase 6 — ML-based anomaly detection (Isolation Forest, Random Forest, SHAP)
- [x] Phase 7 — Frontend dashboards (Next.js)
- [x] Phase 8 — Case management & SOAR playbooks
- [ ] Phase 9 — Testing, CI/CD hardening, documentation

## Stack

FastAPI · Next.js · PostgreSQL · Redis · OpenSearch · Sigma · YARA · scikit-learn · Docker Compose

## Local development

```bash
cp .env.example .env
docker compose up -d
docker compose ps        # confirm postgres, redis, opensearch, opensearch-dashboards are all "healthy"
```

OpenSearch Dashboards: http://localhost:5601
Vantara dashboard: http://localhost:3000

**Linux/WSL only — do this before first run**, or the `opensearch` container will crash-loop:

```bash
sudo sysctl -w vm.max_map_count=262144
```

To make it permanent, add `vm.max_map_count=262144` to `/etc/sysctl.conf`.

## Architecture

Diagrams added starting Phase 2.

## License

MIT — see [LICENSE](LICENSE).
