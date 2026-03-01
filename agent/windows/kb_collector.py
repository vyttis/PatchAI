"""Dual-method KB collection with cache fallback.

Methods:
1. WUA COM API (authoritative, cap 2000 entries, timeout-guarded)
2. CBS registry + DISM /get-packages (fast, deterministic)
3. Local JSON cache fallback (stale after 8h)

Payload includes: collection_method, stale bool, cached_at timestamp.
Server annotates vulnerability matches as "uncertain KB baseline" when stale=true.

Implementation: Phase 1C
"""
