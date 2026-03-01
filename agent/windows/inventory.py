"""OS identity and registry-based application inventory.

Collects:
- OS build, edition, architecture
- Installed applications from registry (HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall)
- Section hashing for delta check-in (Invariant: hash delta, full send daily at 03:00)

Implementation: Phase 1C
"""
