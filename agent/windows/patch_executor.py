"""Winget + fallback chain for patch execution.

Three-path fallback:
1. winget upgrade --silent (if winget_available from last check-in)
2. Relay node download (if relay_node_available)
3. Direct MSI download with SHA256 verification

SYSTEM context workaround: schtasks to run winget as NETWORK SERVICE.

Implementation: Phase 1C
"""
