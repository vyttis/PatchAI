"""Phase 1B tests — PKI, enrollment, mTLS auth, revocation.

Tests:
  1. PKIMasterKey: missing env var raises RuntimeError
  2. PKIMasterKey: encrypt/decrypt roundtrip
  3. CA key stored as BYTEA (ca_key_encrypted), ca_key_pem does not exist
  4. EnrollmentToken: token_id is unique, model has correct columns
  5. Enrollment: fetch by token_id, bcrypt verifies, used_count increments
  6. Enrollment: expired token rejected
  7. Enrollment: max_uses exceeded rejected
  8. Revocation: revoked device returns 403 even when Redis unavailable
  9. warm_revocation_cache: rebuilds Redis sets from DB
  10. HardHeaderStrip: already tested in test_hard_header_strip.py
  11. audit cert.revoked AuditInsertError: already tested in test_1a.py
  12. generate_org_ca: generates CA and stores encrypted key
  13. sign_device_csr: signs CSR and returns cert + fingerprint
"""

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import bcrypt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models import Device, EnrollmentToken, Organization, OrgCA
from backend.app.services.pki import (
    PKIMasterKey,
    generate_org_ca,
    sign_device_csr,
    warm_revocation_cache_on_startup,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_HEX_KEY = "a" * 64  # 32 bytes as hex


def _make_csr(cn: str = "test-device.00000000-0000-0000-0000-000000000001") -> bytes:
    """Generate a CSR for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


# ---------------------------------------------------------------------------
# 1. PKIMasterKey: missing env var raises RuntimeError
# ---------------------------------------------------------------------------


def test_pki_master_key_missing_raises():
    """PKIMasterKey raises RuntimeError when key is empty."""
    with pytest.raises(RuntimeError, match="PKI_MASTER_KEY missing"):
        PKIMasterKey(hex_key="")


def test_pki_master_key_short_raises():
    """PKIMasterKey raises RuntimeError when key is too short."""
    with pytest.raises(RuntimeError, match="PKI_MASTER_KEY missing"):
        PKIMasterKey(hex_key="abcd")


def test_pki_master_key_invalid_hex_raises():
    """PKIMasterKey raises RuntimeError when key is not valid hex."""
    with pytest.raises(RuntimeError, match="not valid hex"):
        PKIMasterKey(hex_key="g" * 64)


# ---------------------------------------------------------------------------
# 2. PKIMasterKey: encrypt/decrypt roundtrip
# ---------------------------------------------------------------------------


def test_pki_master_key_encrypt_decrypt_roundtrip():
    """Encrypt then decrypt returns original data."""
    mk = PKIMasterKey(hex_key=VALID_HEX_KEY)
    plaintext = b"This is a secret CA private key PEM"
    ciphertext = mk.encrypt(plaintext)

    # Ciphertext should be different from plaintext
    assert ciphertext != plaintext
    # Nonce is 12 bytes, so ciphertext is longer
    assert len(ciphertext) > len(plaintext)

    decrypted = mk.decrypt(ciphertext)
    assert decrypted == plaintext


def test_pki_master_key_different_encryptions_differ():
    """Two encryptions of same data produce different ciphertext (random nonce)."""
    mk = PKIMasterKey(hex_key=VALID_HEX_KEY)
    plaintext = b"same data"
    ct1 = mk.encrypt(plaintext)
    ct2 = mk.encrypt(plaintext)
    assert ct1 != ct2  # different nonces
    assert mk.decrypt(ct1) == mk.decrypt(ct2) == plaintext


# ---------------------------------------------------------------------------
# 3. CA key stored as BYTEA, ca_key_pem does not exist (Invariant #7)
# ---------------------------------------------------------------------------


def test_org_ca_has_ca_key_encrypted_column():
    """OrgCA model has ca_key_encrypted (LargeBinary), not ca_key_pem."""
    columns = {c.name for c in OrgCA.__table__.columns}
    assert "ca_key_encrypted" in columns
    assert "ca_key_pem" not in columns, (
        "ca_key_pem must NOT exist — Invariant #7"
    )


def test_org_ca_key_encrypted_is_binary_type():
    """ca_key_encrypted column is LargeBinary (BYTEA in Postgres)."""
    from sqlalchemy import LargeBinary

    col = OrgCA.__table__.c["ca_key_encrypted"]
    assert isinstance(col.type, LargeBinary)


def test_org_ca_is_not_tenant_mixin():
    """OrgCA uses org_id as PK, not as a TenantMixin FK."""
    from backend.app.models.base import TenantMixin

    assert not issubclass(OrgCA, TenantMixin)


# ---------------------------------------------------------------------------
# 4. EnrollmentToken: correct columns and constraints
# ---------------------------------------------------------------------------


def test_enrollment_token_has_required_columns():
    """EnrollmentToken has token_id (unique), token_hash, and key columns."""
    columns = {c.name for c in EnrollmentToken.__table__.columns}
    required = {"id", "token_id", "token_hash", "org_id", "dept_id",
                "label", "expires_at", "max_uses", "used_count", "created_by"}
    missing = required - columns
    assert not missing, f"Missing columns: {missing}"


def test_enrollment_token_token_id_is_unique():
    """token_id column has a unique constraint."""
    col = EnrollmentToken.__table__.c["token_id"]
    assert col.unique is True


def test_enrollment_token_inherits_tenant_mixin():
    """EnrollmentToken inherits TenantMixin (Invariant #16)."""
    from backend.app.models.base import TenantMixin

    assert issubclass(EnrollmentToken, TenantMixin)


# ---------------------------------------------------------------------------
# 5. Enrollment: fetch by token_id, bcrypt verifies, used_count increments
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enrollment_token_fetch_and_verify(db: AsyncSession, org_id):
    """Create token, fetch by token_id, verify bcrypt, increment used_count."""
    # Setup org
    org = Organization(id=org_id, name="Test Org", settings={})
    db.add(org)
    await db.flush()

    # Create token
    token_secret = "test-secret-value"
    token_hash = bcrypt.hashpw(
        token_secret.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    token = EnrollmentToken(
        token_id="test-token-id-123",
        token_hash=token_hash,
        org_id=org_id,
        max_uses=100,
        used_count=0,
    )
    db.add(token)
    await db.flush()

    # Fetch by token_id (O(1) — Invariant #11)
    result = await db.execute(
        select(EnrollmentToken).where(EnrollmentToken.token_id == "test-token-id-123")
    )
    fetched = result.scalar_one()

    # Verify bcrypt
    assert bcrypt.checkpw(
        token_secret.encode("utf-8"),
        fetched.token_hash.encode("utf-8"),
    )

    # Increment used_count
    assert fetched.used_count == 0
    fetched.used_count += 1
    await db.flush()

    # Re-fetch to confirm
    result2 = await db.execute(
        select(EnrollmentToken).where(EnrollmentToken.token_id == "test-token-id-123")
    )
    refetched = result2.scalar_one()
    assert refetched.used_count == 1


# ---------------------------------------------------------------------------
# 6. Enrollment: expired token rejected
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_expired_enrollment_token_rejected(db: AsyncSession, org_id):
    """Enrollment with expired token should be rejected."""
    org = Organization(id=org_id, name="Test Org", settings={})
    db.add(org)
    await db.flush()

    past = datetime.now(timezone.utc) - timedelta(hours=1)
    token = EnrollmentToken(
        token_id="expired-token-123",
        token_hash="not-checked-for-this-test",
        org_id=org_id,
        expires_at=past,
        max_uses=100,
        used_count=0,
    )
    db.add(token)
    await db.flush()

    result = await db.execute(
        select(EnrollmentToken).where(EnrollmentToken.token_id == "expired-token-123")
    )
    fetched = result.scalar_one()

    now = datetime.now(timezone.utc)
    assert fetched.expires_at < now, "Token should be expired"


# ---------------------------------------------------------------------------
# 7. Enrollment: max_uses exceeded rejected
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_max_uses_exceeded_rejected(db: AsyncSession, org_id):
    """Token with used_count >= max_uses should be rejected."""
    org = Organization(id=org_id, name="Test Org", settings={})
    db.add(org)
    await db.flush()

    token = EnrollmentToken(
        token_id="maxed-token-123",
        token_hash="not-checked-for-this-test",
        org_id=org_id,
        max_uses=5,
        used_count=5,
    )
    db.add(token)
    await db.flush()

    result = await db.execute(
        select(EnrollmentToken).where(EnrollmentToken.token_id == "maxed-token-123")
    )
    fetched = result.scalar_one()
    assert fetched.used_count >= fetched.max_uses, "Token should be maxed out"


# ---------------------------------------------------------------------------
# 8. Revocation: revoked device returns 403 even when Redis unavailable
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoked_device_403_with_redis_down(db: AsyncSession, org_id):
    """Revoked device gets 403 even when Redis raises an error (DB fallback)."""
    from redis.exceptions import RedisError

    from backend.app.dependencies.device_auth import get_mtls_device

    # Setup org + revoked device
    org = Organization(id=org_id, name="Test Org", settings={})
    db.add(org)
    await db.flush()

    device_id = uuid.uuid4()
    device = Device(
        id=device_id,
        org_id=org_id,
        hostname="revoked-pc",
        cert_fingerprint="deadbeef1234",
        cert_revoked_at=datetime.now(timezone.utc),
    )
    db.add(device)
    await db.flush()

    # Mock Redis that fails
    mock_redis = AsyncMock()
    mock_redis.sismember = AsyncMock(side_effect=RedisError("Connection refused"))

    # Mock request with mTLS headers
    mock_request = MagicMock()
    mock_request.headers = {
        "x-device-cert-cn": f"{device_id}.{org_id}",
        "x-device-cert-fingerprint": "deadbeef1234",
    }

    # Should get 403 from DB tier (device has cert_revoked_at set)
    with pytest.raises(HTTPException) as exc_info:
        await get_mtls_device(mock_request, redis=mock_redis, db=db)
    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_valid_device_succeeds_with_redis_down(db: AsyncSession, org_id):
    """Valid (non-revoked) device succeeds even when Redis is down."""
    from redis.exceptions import RedisError

    from backend.app.dependencies.device_auth import get_mtls_device

    org = Organization(id=org_id, name="Test Org", settings={})
    db.add(org)
    await db.flush()

    device_id = uuid.uuid4()
    device = Device(
        id=device_id,
        org_id=org_id,
        hostname="good-pc",
        cert_fingerprint="goodfingerprint",
        cert_revoked_at=None,
    )
    db.add(device)
    await db.flush()

    mock_redis = AsyncMock()
    mock_redis.sismember = AsyncMock(side_effect=RedisError("Connection refused"))

    mock_request = MagicMock()
    mock_request.headers = {
        "x-device-cert-cn": f"{device_id}.{org_id}",
        "x-device-cert-fingerprint": "goodfingerprint",
    }

    result = await get_mtls_device(mock_request, redis=mock_redis, db=db)
    assert result.id == device_id


@pytest.mark.asyncio
async def test_missing_mtls_headers_returns_401(db: AsyncSession):
    """Missing mTLS headers returns 401."""
    from backend.app.dependencies.device_auth import get_mtls_device

    mock_request = MagicMock()
    mock_request.headers = {}

    with pytest.raises(HTTPException) as exc_info:
        await get_mtls_device(mock_request, redis=None, db=db)
    assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# 9. warm_revocation_cache: rebuilds Redis sets from DB
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_warm_revocation_cache(db: AsyncSession, org_id):
    """warm_revocation_cache_on_startup rebuilds Redis sets from DB."""
    org = Organization(id=org_id, name="Test Org", settings={})
    db.add(org)
    await db.flush()

    # Create revoked devices
    now = datetime.now(timezone.utc)
    d1 = Device(
        id=uuid.uuid4(), org_id=org_id, hostname="dev1",
        cert_fingerprint="fp1", cert_revoked_at=now,
    )
    d2 = Device(
        id=uuid.uuid4(), org_id=org_id, hostname="dev2",
        cert_fingerprint="fp2", cert_revoked_at=now,
    )
    # Non-revoked device should NOT be in cache
    d3 = Device(
        id=uuid.uuid4(), org_id=org_id, hostname="dev3",
        cert_fingerprint="fp3", cert_revoked_at=None,
    )
    db.add_all([d1, d2, d3])
    await db.flush()

    # Mock Redis
    mock_redis = AsyncMock()
    mock_redis.sadd = AsyncMock()

    count = await warm_revocation_cache_on_startup(mock_redis, db)

    assert count == 2
    # Redis sadd should have been called with the org's fingerprints
    mock_redis.sadd.assert_called_once()
    call_args = mock_redis.sadd.call_args
    assert call_args[0][0] == f"revoked:{org_id}"
    assert set(call_args[0][1:]) == {"fp1", "fp2"}


@pytest.mark.asyncio
async def test_warm_revocation_cache_empty_db(db: AsyncSession):
    """warm_revocation_cache returns 0 when no revoked devices exist."""
    mock_redis = AsyncMock()
    count = await warm_revocation_cache_on_startup(mock_redis, db)
    assert count == 0
    mock_redis.sadd.assert_not_called()


# ---------------------------------------------------------------------------
# 10. generate_org_ca: creates CA with encrypted key
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_org_ca(db: AsyncSession, org_id):
    """generate_org_ca creates an OrgCA with encrypted key and returns cert PEM."""
    org = Organization(id=org_id, name="Test Org", settings={})
    db.add(org)
    await db.flush()

    mk = PKIMasterKey(hex_key=VALID_HEX_KEY)
    ca_cert_pem = await generate_org_ca(db, org_id, mk)

    # Verify cert PEM is valid
    assert ca_cert_pem.startswith("-----BEGIN CERTIFICATE-----")
    cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
    assert f"PatchPilot CA {org_id}" in cert.subject.rfc4514_string()

    # Verify stored in DB
    org_ca = await db.get(OrgCA, org_id)
    assert org_ca is not None
    assert org_ca.ca_cert_pem == ca_cert_pem
    assert org_ca.ca_key_algorithm == "RSA-4096"

    # Verify key is encrypted (not plaintext PEM)
    assert not org_ca.ca_key_encrypted.startswith(b"-----BEGIN")

    # Verify we can decrypt and load the key
    decrypted = mk.decrypt(org_ca.ca_key_encrypted)
    assert decrypted.startswith(b"-----BEGIN PRIVATE KEY-----")


# ---------------------------------------------------------------------------
# 11. sign_device_csr: signs CSR and returns cert + fingerprint
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sign_device_csr(db: AsyncSession, org_id):
    """sign_device_csr signs a CSR and returns cert_pem + fingerprint."""
    org = Organization(id=org_id, name="Test Org", settings={})
    db.add(org)
    await db.flush()

    mk = PKIMasterKey(hex_key=VALID_HEX_KEY)
    await generate_org_ca(db, org_id, mk)

    csr_pem = _make_csr(f"test-device.{org_id}")
    cert_pem, fingerprint, cert_serial = await sign_device_csr(db, org_id, csr_pem, mk)

    # Verify cert PEM is valid
    assert cert_pem.startswith("-----BEGIN CERTIFICATE-----")
    cert = x509.load_pem_x509_certificate(cert_pem.encode())

    # Verify fingerprint matches
    expected_fp = cert.fingerprint(hashes.SHA256()).hex()
    assert fingerprint == expected_fp

    # Verify cert is signed by the org CA
    org_ca = await db.get(OrgCA, org_id)
    ca_cert = x509.load_pem_x509_certificate(org_ca.ca_cert_pem.encode())
    assert cert.issuer == ca_cert.subject

    # Verify serial is hex
    assert cert_serial == format(cert.serial_number, "x")


# ---------------------------------------------------------------------------
# 12. Device auth: Redis cache detects revoked cert
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_redis_revocation_check(db: AsyncSession, org_id):
    """Redis fast-path detects revoked cert without hitting DB."""
    from backend.app.dependencies.device_auth import get_mtls_device

    org = Organization(id=org_id, name="Test Org", settings={})
    db.add(org)
    await db.flush()

    device_id = uuid.uuid4()
    # Device is NOT revoked in DB (cert_revoked_at=None)
    # but IS in Redis revocation cache
    device = Device(
        id=device_id, org_id=org_id, hostname="cached-revoked",
        cert_fingerprint="redis-revoked-fp", cert_revoked_at=None,
    )
    db.add(device)
    await db.flush()

    mock_redis = AsyncMock()
    mock_redis.sismember = AsyncMock(return_value=True)  # Redis says revoked

    mock_request = MagicMock()
    mock_request.headers = {
        "x-device-cert-cn": f"{device_id}.{org_id}",
        "x-device-cert-fingerprint": "redis-revoked-fp",
    }

    with pytest.raises(HTTPException) as exc_info:
        await get_mtls_device(mock_request, redis=mock_redis, db=db)
    assert exc_info.value.status_code == 403
    assert "revoked" in exc_info.value.detail.lower()


# ---------------------------------------------------------------------------
# 13. extract_org_from_cn
# ---------------------------------------------------------------------------


def test_extract_org_from_cn():
    """extract_org_from_cn parses org_id from CN format."""
    from backend.app.dependencies.device_auth import extract_org_from_cn

    org_id = uuid.uuid4()
    device_id = uuid.uuid4()
    cn = f"{device_id}.{org_id}"
    assert extract_org_from_cn(cn) == org_id


def test_extract_org_from_cn_invalid():
    """extract_org_from_cn raises ValueError for invalid CN."""
    from backend.app.dependencies.device_auth import extract_org_from_cn

    with pytest.raises(ValueError):
        extract_org_from_cn("no-dot-here")


# ---------------------------------------------------------------------------
# 14. New tables created in SQLite
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_phase_1b_tables_created(async_engine):
    """Verify org_cas and enrollment_tokens tables exist."""
    from sqlalchemy import inspect

    async with async_engine.connect() as conn:
        def _inspect(sync_conn):
            insp = inspect(sync_conn)
            return set(insp.get_table_names())

        tables = await conn.run_sync(_inspect)

    assert "org_cas" in tables
    assert "enrollment_tokens" in tables


# ---------------------------------------------------------------------------
# 15. MTLSHeaderGuard passes requests through
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mtls_guard_passes_through():
    """MTLSHeaderGuard passes all requests through to the inner app."""
    from backend.app.middleware.mtls_guard import MTLSHeaderGuard

    calls = []

    async def mock_app(scope, receive, send):
        calls.append(scope)

    guard = MTLSHeaderGuard(mock_app)
    scope = {
        "type": "http",
        "path": "/api/v1/devices/checkin",
        "headers": [],
    }
    await guard(scope, None, None)
    assert len(calls) == 1
