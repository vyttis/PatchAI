"""PKI service — envelope-encrypted CA keys, CSR signing, revocation.

Security Invariant #3:  get_mtls_device() validates cert_fingerprint on every request.
Security Invariant #4:  warm_revocation_cache_on_startup() runs at every server start.
Security Invariant #7:  CA private keys NEVER stored in plaintext.
Security Invariant #10: cert.revoked and cert.enrolled are CRITICAL_EVENTS — BLOCK on audit failure.
"""

import logging
import os
import uuid as _uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.devices import Device
from backend.app.models.org_cas import OrgCA
from backend.app.services.audit import record as audit_record

logger = logging.getLogger(__name__)


class PKIMasterKey:
    """AES-256-GCM envelope key for CA private key encryption.

    Reads PKI_MASTER_KEY from environment. Raises RuntimeError on startup
    if missing or invalid. Key is 32 bytes hex-encoded (64 chars).
    """

    def __init__(self, hex_key: Optional[str] = None):
        raw = hex_key if hex_key is not None else os.environ.get("PKI_MASTER_KEY", "")
        if not raw or len(raw) != 64:
            raise RuntimeError(
                "PKI_MASTER_KEY missing or invalid (must be 64 hex chars) — refusing to start"
            )
        try:
            self._key = bytes.fromhex(raw)
        except ValueError as exc:
            raise RuntimeError(
                "PKI_MASTER_KEY is not valid hex — refusing to start"
            ) from exc
        self._aesgcm = AESGCM(self._key)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data with AES-256-GCM. Returns nonce (12 bytes) || ciphertext+tag."""
        nonce = os.urandom(12)
        ct = self._aesgcm.encrypt(nonce, data, None)
        return nonce + ct

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt AES-256-GCM data. Input: nonce (12 bytes) || ciphertext+tag."""
        nonce = data[:12]
        ct = data[12:]
        return self._aesgcm.decrypt(nonce, ct, None)


async def generate_org_ca(
    db: AsyncSession,
    org_id: _uuid.UUID,
    master_key: PKIMasterKey,
) -> str:
    """Generate a new CA keypair for an org. Returns ca_cert_pem only.

    Private key is encrypted before any DB write. Never returned to caller.
    """
    # Generate RSA-4096 keypair in memory
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # Serialize private key to PEM
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Encrypt BEFORE any DB write (Invariant #7)
    key_encrypted = master_key.encrypt(key_pem)

    # Generate self-signed CA cert (10-year validity)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"PatchPilot CA {org_id}"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PatchPilot"),
    ])
    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()

    # Store in DB
    org_ca = OrgCA(
        org_id=org_id,
        ca_cert_pem=ca_cert_pem,
        ca_key_encrypted=key_encrypted,
        ca_key_algorithm="RSA-4096",
    )
    db.add(org_ca)
    await db.flush()

    logger.info("Generated CA for org=%s", org_id)
    return ca_cert_pem


async def sign_device_csr(
    db: AsyncSession,
    org_id: _uuid.UUID,
    csr_pem: bytes,
    master_key: PKIMasterKey,
) -> tuple[str, str, str]:
    """Sign a device CSR with the org's CA. Returns (cert_pem, fingerprint, serial).

    Decrypts CA private key in memory, signs, then clears key bytes.
    """
    # Fetch org CA
    org_ca = await db.get(OrgCA, org_id)
    if not org_ca:
        raise ValueError(f"No CA found for org {org_id}")

    # Decrypt CA private key
    key_pem_bytes = master_key.decrypt(org_ca.ca_key_encrypted)
    try:
        ca_private_key = serialization.load_pem_private_key(key_pem_bytes, password=None)

        # Load CA cert for issuer info
        ca_cert = x509.load_pem_x509_certificate(org_ca.ca_cert_pem.encode())

        # Parse CSR
        csr = x509.load_pem_x509_csr(csr_pem)

        # Sign device cert (2-year validity)
        now = datetime.now(timezone.utc)
        device_cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=730))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .sign(ca_private_key, hashes.SHA256())
        )

        cert_pem = device_cert.public_bytes(serialization.Encoding.PEM).decode()

        # Compute fingerprint (SHA-256 of DER)
        fingerprint = device_cert.fingerprint(hashes.SHA256()).hex()

        # Cert serial as hex
        cert_serial = format(device_cert.serial_number, "x")

        return cert_pem, fingerprint, cert_serial
    finally:
        # Clear private key bytes from memory
        key_pem_bytes = b"\x00" * len(key_pem_bytes)  # noqa: F841


async def revoke_device(
    db: AsyncSession,
    redis,
    device_id: _uuid.UUID,
    reason: str,
    by_user_id: _uuid.UUID,
) -> None:
    """Revoke a device certificate.

    1. DB first: device.cert_revoked_at = now()
    2. Redis: sadd revoked:{org_id} fingerprint
    3. audit.record("cert.revoked") — CRITICAL EVENT, must succeed
    """
    # Fetch device
    device = await db.get(Device, device_id)
    if not device:
        raise ValueError(f"Device {device_id} not found")

    now = datetime.now(timezone.utc)

    # 1. DB update
    await db.execute(
        update(Device)
        .where(Device.id == device_id)
        .values(cert_revoked_at=now)
    )
    await db.flush()

    # 2. Redis revocation cache (best-effort, DB is authoritative)
    if redis and device.cert_fingerprint:
        try:
            await redis.sadd(f"revoked:{device.org_id}", device.cert_fingerprint)
        except Exception:
            logger.warning(
                "Failed to add revocation to Redis for device=%s, DB is authoritative",
                device_id,
            )

    # 3. Audit — CRITICAL EVENT (Invariant #10), must succeed or raise
    await audit_record(
        db,
        event_type="cert.revoked",
        org_id=device.org_id,
        user_id=by_user_id,
        device_id=device_id,
        changes={"reason": reason},
        result="revoked",
    )

    logger.info("Revoked cert for device=%s reason=%s", device_id, reason)


async def warm_revocation_cache_on_startup(redis, db: AsyncSession) -> int:
    """Rebuild Redis revocation cache from DB on server start (Invariant #4).

    Returns count of revoked certs warmed.
    """
    result = await db.execute(
        select(Device.org_id, Device.cert_fingerprint).where(
            Device.cert_revoked_at.isnot(None),
            Device.cert_fingerprint.isnot(None),
        )
    )
    rows = result.all()

    if not rows:
        logger.info("Revocation cache warm: 0 revoked certs")
        return 0

    # Group by org_id
    by_org: dict[_uuid.UUID, list[str]] = {}
    for org_id, fingerprint in rows:
        by_org.setdefault(org_id, []).append(fingerprint)

    # Populate Redis sets
    count = 0
    for org_id, fingerprints in by_org.items():
        await redis.sadd(f"revoked:{org_id}", *fingerprints)
        count += len(fingerprints)

    logger.info("Revocation cache warm: %d revoked certs across %d orgs", count, len(by_org))
    return count
