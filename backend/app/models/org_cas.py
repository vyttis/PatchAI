"""OrgCA model — per-org CA with envelope-encrypted private key.

Security Invariant #7: CA private keys NEVER stored in plaintext.
Always AES-256-GCM encrypted with PKI_MASTER_KEY (Fly.io secret, never DB).
DB stores ca_key_encrypted BYTEA. Only patchpilot_pki DB role may read it.
Column ca_key_pem does not exist.
"""

import uuid as _uuid
from datetime import datetime

from sqlalchemy import ForeignKey, LargeBinary, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database import Base


class OrgCA(Base):
    __tablename__ = "org_cas"

    org_id: Mapped[_uuid.UUID] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        primary_key=True,
    )
    ca_cert_pem: Mapped[str] = mapped_column(Text, nullable=False)
    ca_key_encrypted: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False,
        comment="AES-256-GCM encrypted CA private key. NEVER plaintext.",
    )
    ca_key_algorithm: Mapped[str] = mapped_column(
        Text, nullable=False, server_default="RSA-4096"
    )
    created_at: Mapped[datetime] = mapped_column(
        default=None, server_default=func.now(),
    )
