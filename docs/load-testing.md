# PatchPilot Load Testing Guide

Target: 2,000 concurrent devices, 50 dashboard users.

## Prerequisites

```bash
pip install locust
```

## Test Scenarios

### 1. Device Check-in (2,000 concurrent)

Each device sends inventory delta + KB baseline every 15 minutes.
Peak load: ~133 requests/second (2000 devices / 15 min).

```python
# locustfile_devices.py
from locust import HttpUser, task, between

class DeviceCheckin(HttpUser):
    wait_time = between(840, 960)  # 14-16 min jitter

    @task(10)
    def checkin(self):
        self.client.post(
            "/api/v1/devices/checkin",
            json={"os_build": "10.0.19045", "kbs": [], "apps": []},
            headers={
                "x-device-cert-cn": f"device-{self.device_id}.{self.org_id}",
                "x-device-cert-fingerprint": self.fingerprint,
            },
        )

    @task(1)
    def next_command(self):
        # BLPOP long-poll — 55s timeout
        self.client.get(
            "/api/v1/devices/next-command",
            headers={
                "x-device-cert-cn": f"device-{self.device_id}.{self.org_id}",
                "x-device-cert-fingerprint": self.fingerprint,
            },
            timeout=60,
        )
```

### 2. Dashboard API (50 concurrent users)

Dashboard users browse fleet overview, exposures, deployments.

```python
# locustfile_dashboard.py
from locust import HttpUser, task, between

class DashboardUser(HttpUser):
    wait_time = between(2, 5)

    @task(5)
    def fleet_overview(self):
        self.client.get(f"/api/v1/orgs/{self.org_id}/metrics/mttrem?period=30d")

    @task(3)
    def exposures(self):
        self.client.get(f"/api/v1/orgs/{self.org_id}/exposures?status=exposed&limit=20")

    @task(2)
    def deployments(self):
        self.client.get(f"/api/v1/orgs/{self.org_id}/deployments")

    @task(1)
    def executive_report(self):
        self.client.get(f"/api/v1/orgs/{self.org_id}/reports/mttrem-executive?period=30d")
```

### 3. Running Tests

```bash
# Device load test
locust -f locustfile_devices.py --users 2000 --spawn-rate 100 \
  --host https://api.patchpilot.com --run-time 30m

# Dashboard load test
locust -f locustfile_dashboard.py --users 50 --spawn-rate 10 \
  --host https://api.patchpilot.com --run-time 15m
```

## Connection Pool Sizing

### PostgreSQL (SQLAlchemy async)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `pool_size` | 20 | Base connections for steady-state |
| `max_overflow` | 10 | Burst headroom (30 total max) |
| `pool_pre_ping` | True | Detect stale PgBouncer connections |
| `pool_recycle` | 3600 | Rotate hourly (Supabase idle timeout) |

**Capacity:** 30 max connections. At ~133 req/s peak with ~10ms avg query time, theoretical max is 3,000 req/s per connection pool. 30 connections provides 10x headroom.

### Redis (Upstash)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `max_connections` | 100 | 2,000 devices + rate limiting + revocation checks |
| `socket_keepalive` | True | Prevent Upstash idle disconnects |
| `decode_responses` | True | String operations (no binary blobs in Redis) |

**Operations breakdown:**
- BLPOP long-poll: 2,000 concurrent (1 per device)
- Rate limiting: ~133 INCR/s (device checkin) + ~25 INCR/s (dashboard)
- Revocation checks: ~133/s (one SISMEMBER per checkin)
- Total: ~2,290 concurrent ops — 100 connections with pipelining handles this comfortably

## Rate Limiting Configuration

| Tier | Limit | Key | Purpose |
|------|-------|-----|---------|
| Device | 10 req/min | `x-device-cert-cn` | Prevent runaway agents |
| Org API | 100 req/min | org_id from URL | Dashboard abuse prevention |

**Exclusions:**
- `/api/v1/devices/next-command` — BLPOP long-poll (55s), excluded to prevent false 429s
- `/health` — Fly.io health checks
- `/api/v1/auth/` — SSO callbacks
- `/api/v1/enrollment/` — Device enrollment (one-time)

**Graceful degradation:** If Redis is unavailable, rate limiting is bypassed (requests allowed). This prevents Redis outages from causing a full API outage.

## Performance Targets

| Metric | Target | Rationale |
|--------|--------|-----------|
| Checkin p95 latency | < 200ms | Delta hashing minimises payload |
| Command delivery | < 35s | BLPOP timeout 55s, target < 35s |
| Dashboard API p95 | < 500ms | SQLAlchemy async, indexed queries |
| MTTRem report p95 | < 2s | Multiple aggregation queries |
| WebSocket delivery | < 3s | Redis pub/sub to connected clients |

## Monitoring

Key metrics to watch during load tests:
- PostgreSQL: `active_connections`, `waiting_connections`, `query_duration_p95`
- Redis: `connected_clients`, `used_memory`, `instantaneous_ops_per_sec`
- Fly.io: `request_duration`, `5xx_rate`, `connection_pool_exhausted`
- Celery: `worker_prefetch_count`, `task_success_rate`, `queue_length`
