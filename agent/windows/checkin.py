"""mTLS check-in loop with BLPOP long-poll and delta hashing.

- mTLS client cert for device authentication (Invariant #6: mTLS only, no JWT)
- Inventory delta: hash each section (apps, kbs, os) independently
- Send only changed sections each check-in
- Daily forced full send at 03:00 local time regardless of hash
- Long-poll via Redis BLPOP (Invariant #12): timeout 55s, {command: null} on timeout

Implementation: Phase 1C
"""
