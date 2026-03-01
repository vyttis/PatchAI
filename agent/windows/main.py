"""PatchPilot Windows Agent — entry point.

Lifecycle:
1. Load config from agent.json
2. If not enrolled: generate CSR, POST /enroll, save cert+key+ca
3. Start mTLS check-in loop (checkin.py)
4. Long-poll for commands via BLPOP (Invariant #12) — Phase 3B
5. Execute jobs via patch_executor.py — Phase 3A
6. Report telemetry snapshots before/after each job
"""

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import httpx

logger = logging.getLogger(__name__)

CONFIG_DIR = Path(r"C:\ProgramData\PatchPilot")
CONFIG_PATH = CONFIG_DIR / "agent.json"
CERT_PATH = CONFIG_DIR / "device.crt"
KEY_PATH = CONFIG_DIR / "device.key"
CA_CERT_PATH = CONFIG_DIR / "ca.crt"


def load_config() -> dict[str, Any]:
    """Load agent config from agent.json."""
    if not CONFIG_PATH.exists():
        logger.error("Config file not found: %s", CONFIG_PATH)
        sys.exit(1)
    return json.loads(CONFIG_PATH.read_text())


def is_enrolled() -> bool:
    """Check if the device has a valid enrollment (cert + key + CA cert)."""
    return CERT_PATH.exists() and KEY_PATH.exists() and CA_CERT_PATH.exists()


def generate_csr(hostname: str) -> tuple[bytes, bytes]:
    """Generate an RSA-2048 key pair and CSR for enrollment.

    Returns (csr_pem, private_key_pem).
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, hostname)])
        )
        .sign(private_key, hashes.SHA256())
    )

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return csr_pem, key_pem


async def enroll(server_url: str, enrollment_token: str, hostname: str) -> dict[str, Any]:
    """Enroll this device with the PatchPilot API.

    Generates CSR, posts to /enroll, saves cert+key+CA locally.
    Returns enrollment response dict (device_id, server_url, checkin_interval).
    """
    csr_pem, key_pem = generate_csr(hostname)

    async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
        resp = await client.post(
            f"{server_url.rstrip('/')}/api/v1/enrollment/enroll",
            json={
                "token": enrollment_token,
                "csr_pem": csr_pem.decode(),
            },
        )
        resp.raise_for_status()

    result = resp.json()

    # Save enrollment artifacts
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    KEY_PATH.write_bytes(key_pem)
    CERT_PATH.write_text(result["cert_pem"])
    CA_CERT_PATH.write_text(result["ca_cert_pem"])

    logger.info("Enrollment complete. Device ID: %s", result["device_id"])
    return result


def collect_full_inventory() -> dict[str, Any]:
    """Collect full inventory: OS identity, installed apps, KB articles."""
    from agent.windows.inventory import get_installed_apps, get_os_identity
    from agent.windows.kb_collector import KBCollector

    kb_collector = KBCollector()
    kbs, kb_meta = kb_collector.collect()

    return {
        "os": get_os_identity(),
        "apps": get_installed_apps(),
        "kbs": {"articles": sorted(kbs), "meta": kb_meta},
    }


async def run(config: dict[str, Any]) -> None:
    """Main agent run loop."""
    from agent.windows.checkin import CheckinClient

    server_url = config["server_url"]
    hostname = config.get("hostname", "unknown")

    if not is_enrolled():
        enrollment_token = config.get("enrollment_token")
        if not enrollment_token:
            logger.error("Not enrolled and no enrollment_token in config")
            sys.exit(1)
        result = await enroll(server_url, enrollment_token, hostname)
        # Update config with device_id
        config["device_id"] = result["device_id"]
        CONFIG_PATH.write_text(json.dumps(config, indent=2, default=str))

    client = CheckinClient(
        server_url=server_url,
        cert_path=str(CERT_PATH),
        key_path=str(KEY_PATH),
        ca_cert_path=str(CA_CERT_PATH),
        device_id=config.get("device_id", "unknown"),
        hostname=hostname,
    )

    try:
        await client.run_loop(collect_inventory_fn=collect_full_inventory)
    finally:
        await client.close()


def main():
    """Agent entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    config = load_config()
    asyncio.run(run(config))


if __name__ == "__main__":
    main()
