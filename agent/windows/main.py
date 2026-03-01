"""PatchPilot Windows Agent — entry point.

Lifecycle:
1. Load config (API URL, cert paths)
2. Start mTLS check-in loop (checkin.py)
3. Long-poll for commands via BLPOP (Invariant #12)
4. Execute jobs via patch_executor.py
5. Report telemetry snapshots before/after each job
"""


def main():
    """Agent entry point — will be implemented in Phase 1C."""
    raise NotImplementedError("Agent implementation starts in Phase 1C")


if __name__ == "__main__":
    main()
