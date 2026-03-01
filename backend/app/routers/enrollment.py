"""Enrollment router — token creation and device enrollment.

POST /api/v1/enrollment/tokens   — JWT auth, org_admin role
POST /api/v1/enrollment/enroll   — no auth, uses enrollment token

Security Invariant #11: Two-part token format (token_id + token_secret).
                        Fetch by token_id (O(1)), verify one bcrypt hash.
"""

import secrets
import uuid as _uuid
from datetime import datetime, timezone

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database import get_db
from backend.app.dependencies.auth import get_org_scope, require_role
from backend.app.models.devices import Device
from backend.app.models.enrollment_tokens import EnrollmentToken
from backend.app.models.org_cas import OrgCA
from backend.app.schemas.auth import CurrentUser, OrgScope
from backend.app.schemas.enrollment import (
    EnrollmentTokenCreate,
    EnrollmentTokenResponse,
    EnrollRequest,
    EnrollResponse,
)
from backend.app.services.audit import record as audit_record
from backend.app.services.pki import PKIMasterKey, generate_org_ca, sign_device_csr

router = APIRouter(prefix="/api/v1/enrollment", tags=["enrollment"])


@router.post(
    "/tokens",
    response_model=EnrollmentTokenResponse,
    status_code=201,
)
async def create_enrollment_token(
    body: EnrollmentTokenCreate,
    current_user: CurrentUser = Depends(require_role("org_admin")),
    scope: OrgScope = Depends(get_org_scope),
    db: AsyncSession = Depends(get_db),
):
    """Create an enrollment token. Returns full token shown ONCE."""
    token_id = secrets.token_urlsafe(12)  # ~16 chars
    token_secret = secrets.token_urlsafe(32)  # ~43 chars
    token_hash = bcrypt.hashpw(
        token_secret.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    token = EnrollmentToken(
        token_id=token_id,
        token_hash=token_hash,
        org_id=scope.org_id,
        dept_id=body.dept_id,
        label=body.label,
        expires_at=body.expires_at,
        max_uses=body.max_uses,
        created_by=current_user.id,
    )
    db.add(token)
    await db.commit()

    full_token = f"{token_id}.{token_secret}"

    return EnrollmentTokenResponse(
        token=full_token,
        token_id=token_id,
        org_id=scope.org_id,
        expires_at=body.expires_at,
        max_uses=body.max_uses,
    )


@router.post(
    "/enroll",
    response_model=EnrollResponse,
    status_code=201,
)
async def enroll_device(
    body: EnrollRequest,
    db: AsyncSession = Depends(get_db),
):
    """Enroll a new device using an enrollment token + CSR.

    No JWT auth — authentication is via the enrollment token.
    """
    # Parse two-part token
    parts = body.token.split(".", 1)
    if len(parts) != 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token format",
        )
    token_id, token_secret = parts

    # Fetch by token_id (O(1) — Invariant #11)
    result = await db.execute(
        select(EnrollmentToken).where(EnrollmentToken.token_id == token_id)
    )
    token_row = result.scalar_one_or_none()
    if not token_row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid enrollment token",
        )

    # Verify bcrypt hash
    if not bcrypt.checkpw(
        token_secret.encode("utf-8"),
        token_row.token_hash.encode("utf-8"),
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid enrollment token",
        )

    # Check expiry
    now = datetime.now(timezone.utc)
    if token_row.expires_at and token_row.expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Enrollment token expired",
        )

    # Check max_uses
    if token_row.used_count >= token_row.max_uses:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Enrollment token max uses exceeded",
        )

    # Increment used_count
    token_row.used_count += 1
    await db.flush()

    # Ensure org has a CA; generate if not
    org_id = token_row.org_id
    master_key = PKIMasterKey()
    org_ca = await db.get(OrgCA, org_id)
    if not org_ca:
        await generate_org_ca(db, org_id, master_key)
        org_ca = await db.get(OrgCA, org_id)

    # Sign device CSR
    csr_pem = body.csr_pem.encode("utf-8")
    cert_pem, fingerprint, cert_serial = await sign_device_csr(
        db, org_id, csr_pem, master_key
    )

    # Extract CN from CSR for device_id.org_id format
    from cryptography import x509 as cx509

    csr = cx509.load_pem_x509_csr(csr_pem)
    cn_attr = csr.subject.get_attributes_for_oid(cx509.oid.NameOID.COMMON_NAME)
    hostname = cn_attr[0].value if cn_attr else "unknown"

    # Create Device
    device_id = _uuid.uuid4()
    device = Device(
        id=device_id,
        org_id=org_id,
        dept_id=token_row.dept_id,
        hostname=hostname,
        cert_fingerprint=fingerprint,
        cert_serial=cert_serial,
    )
    db.add(device)
    await db.flush()

    # Audit — CRITICAL EVENT (Invariant #10)
    await audit_record(
        db,
        event_type="cert.enrolled",
        org_id=org_id,
        device_id=device_id,
        changes={
            "token_id": token_id,
            "fingerprint": fingerprint,
        },
        result="enrolled",
    )

    await db.commit()

    return EnrollResponse(
        device_id=device_id,
        cert_pem=cert_pem,
        ca_cert_pem=org_ca.ca_cert_pem,
    )
