"""Per-job telemetry snapshot (before + after).

Metrics:
- cpu_percent_1s (psutil)
- crash_events_24h (Event Log: IDs 6008, 1001, 41)
- reboots_7d (Event Log: IDs 6009, 1074)
- system_disk_free_gb (psutil)

Stored in deployment_jobs.telemetry_before/after JSONB.

Implementation: Phase 1C
"""
