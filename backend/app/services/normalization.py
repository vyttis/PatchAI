"""SoftwareNormalizerV2 — six-level fallback chain for mapping raw inventory
names to CPE vendor/product pairs.

Fallback order (highest confidence first):
1. tenant_override   (1.0)  — admin-confirmed per-org overrides
2. product_code      (0.98) — MSI GUID lookup
3. exact_known_map   (0.95) — publisher+name in KNOWN_MAP
4. publisher_heuristic (0.75) — publisher→vendor, extract product from name
5. fuzzy             (0.5)  — SequenceMatcher > 0.8 against KNOWN_MAP keys
6. unmatched         (0.0)  — logged for admin review

All results logged to SoftwareNormalizationLog (audit trail).
"""

import logging
import re
import uuid as _uuid
from dataclasses import dataclass
from decimal import Decimal
from difflib import SequenceMatcher
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.software_normalization import (
    SoftwareNormalizationLog,
    TenantNormalizationOverride,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class AppRecord:
    """Raw software entry from device inventory."""

    display_name: str
    publisher: str
    version: str
    product_code: Optional[str] = None  # MSI GUID

    @classmethod
    def from_dict(cls, d: dict) -> "AppRecord":
        return cls(
            display_name=d.get("display_name", ""),
            publisher=d.get("publisher", ""),
            version=d.get("version", ""),
            product_code=d.get("product_code"),
        )


@dataclass
class NormalizedSoftware:
    """Result of normalization — vendor/product pair with confidence."""

    vendor: str
    product: str
    confidence: Decimal  # 0.0–1.0
    match_method: str  # tenant_override | product_code | exact_known_map | publisher_heuristic | fuzzy | unmatched


# ---------------------------------------------------------------------------
# Static mapping tables (in-code — no YAML files in this project)
# ---------------------------------------------------------------------------

PUBLISHER_MAP: dict[str, str] = {
    "adobe inc": "adobe",
    "adobe inc.": "adobe",
    "adobe systems": "adobe",
    "adobe systems incorporated": "adobe",
    "google llc": "google",
    "google inc": "google",
    "google inc.": "google",
    "mozilla corporation": "mozilla",
    "mozilla": "mozilla",
    "microsoft corporation": "microsoft",
    "microsoft": "microsoft",
    "oracle corporation": "oracle",
    "oracle": "oracle",
    "apple inc.": "apple",
    "apple inc": "apple",
    "7-zip": "7-zip",
    "igor pavlov": "7-zip",
    "videolan": "videolan",
    "the document foundation": "libreoffice",
    "notepad++ team": "notepad++",
    "don ho": "notepad++",
    "gimp.org": "gimp",
    "python software foundation": "python",
    "node.js foundation": "nodejs",
    "wireshark foundation": "wireshark",
    "putty": "putty",
    "simon tatham": "putty",
    "zoom video communications, inc.": "zoom",
    "zoom": "zoom",
    "slack technologies": "slack",
    "slack technologies, inc.": "slack",
    "git": "git",
    "the git development community": "git",
    "filezilla project": "filezilla",
    "vim developers": "vim",
    "curl": "curl",
    "haxx": "curl",
}

KNOWN_MAP: dict[tuple[str, str], tuple[str, str]] = {
    # Adobe
    ("adobe", "acrobat reader"): ("adobe", "acrobat_reader"),
    ("adobe", "acrobat reader dc"): ("adobe", "acrobat_reader"),
    ("adobe", "acrobat dc"): ("adobe", "acrobat_dc"),
    ("adobe", "acrobat"): ("adobe", "acrobat_dc"),
    ("adobe", "creative cloud"): ("adobe", "creative_cloud"),
    # Google
    ("google", "chrome"): ("google", "chrome"),
    ("google", "google chrome"): ("google", "chrome"),
    ("google", "earth"): ("google", "earth"),
    # Mozilla
    ("mozilla", "firefox"): ("mozilla", "firefox"),
    ("mozilla", "mozilla firefox"): ("mozilla", "firefox"),
    ("mozilla", "thunderbird"): ("mozilla", "thunderbird"),
    # Oracle
    ("oracle", "java"): ("oracle", "jre"),
    ("oracle", "java se"): ("oracle", "jre"),
    ("oracle", "jre"): ("oracle", "jre"),
    ("oracle", "jdk"): ("oracle", "jdk"),
    ("oracle", "virtualbox"): ("oracle", "virtualbox"),
    # 7-Zip
    ("7-zip", "7-zip"): ("7-zip", "7-zip"),
    # VLC
    ("videolan", "vlc"): ("videolan", "vlc_media_player"),
    ("videolan", "vlc media player"): ("videolan", "vlc_media_player"),
    # Notepad++
    ("notepad++", "notepad++"): ("notepad++", "notepad++"),
    # Python
    ("python", "python"): ("python", "python"),
    # Git
    ("git", "git"): ("git", "git"),
    ("git", "git for windows"): ("git", "git"),
    # Zoom
    ("zoom", "zoom"): ("zoom", "zoom"),
    ("zoom", "zoom workplace"): ("zoom", "zoom"),
    # Putty
    ("putty", "putty"): ("putty", "putty"),
    # Wireshark
    ("wireshark", "wireshark"): ("wireshark", "wireshark"),
    # Curl
    ("curl", "curl"): ("curl", "curl"),
}

PRODUCT_CODE_MAP: dict[str, tuple[str, str]] = {
    "{AC76BA86-7AD7-1033-7B44-AC0F074E4100}": ("adobe", "acrobat_reader"),
    "{AC76BA86-1033-F400-7760-000000000006}": ("adobe", "acrobat_reader"),
    "{65CB4C08-C47B-4A7F-A0AB-0D157A2E6F84}": ("7-zip", "7-zip"),
    "{23170F69-40C1-2702-2301-000001000000}": ("7-zip", "7-zip"),
    "{8A69D345-D564-463C-AFF1-A69D9E530F96}": ("google", "chrome"),
    "{4A03706F-666A-4037-7777-5F2748764D10}": ("mozilla", "firefox"),
    "{D70B02A2-862B-45A3-8C84-E87AA2D26765}": ("videolan", "vlc_media_player"),
    "{F0C3E5D1-1ADE-321E-8167-68EF0DE699A5}": ("oracle", "jre"),
}

# Regex to strip version numbers and common suffixes from display names
_VERSION_RE = re.compile(
    r"\s*(?:v(?:ersion)?\s*)?\d[\d.]*(?:\s*(?:x86|x64|64-bit|32-bit|amd64|update\s*\d+))?\s*$",
    re.IGNORECASE,
)
_PAREN_SUFFIX_RE = re.compile(r"\s*\(.*?\)\s*$")


def _clean_name(name: str) -> str:
    """Lowercase, strip version suffixes and parenthetical content."""
    s = name.lower().strip()
    s = _PAREN_SUFFIX_RE.sub("", s)
    s = _VERSION_RE.sub("", s)
    return s.strip()


def _clean_publisher(publisher: str) -> str:
    """Lowercase and strip common suffixes from publisher names."""
    return publisher.lower().strip()


# ---------------------------------------------------------------------------
# SoftwareNormalizerV2
# ---------------------------------------------------------------------------


class SoftwareNormalizerV2:
    """Normalize raw inventory app entries to CPE vendor/product pairs.

    Six-level fallback chain: tenant_override → product_code → exact_known_map
    → publisher_heuristic → fuzzy → unmatched.
    """

    def __init__(self, db: AsyncSession, org_id: _uuid.UUID):
        self._db = db
        self._org_id = org_id

    async def normalize(
        self, raw: AppRecord, device_id: _uuid.UUID | None = None,
    ) -> NormalizedSoftware:
        """Run fallback chain and log result."""
        result = await self._try_tenant_override(raw)
        if result is None:
            result = self._try_product_code(raw)
        if result is None:
            result = self._try_exact_known_map(raw)
        if result is None:
            result = self._try_publisher_heuristic(raw)
        if result is None:
            result = self._try_fuzzy(raw)
        if result is None:
            result = NormalizedSoftware(
                vendor="",
                product="",
                confidence=Decimal("0.00"),
                match_method="unmatched",
            )

        # Log every result to SoftwareNormalizationLog
        log_entry = SoftwareNormalizationLog(
            org_id=self._org_id,
            device_id=device_id or _uuid.UUID(int=0),
            raw_display_name=raw.display_name,
            raw_publisher=raw.publisher,
            product_code=raw.product_code,
            normalized_vendor=result.vendor,
            normalized_product=result.product,
            confidence=result.confidence,
            match_method=result.match_method,
        )
        self._db.add(log_entry)

        return result

    async def _try_tenant_override(self, raw: AppRecord) -> NormalizedSoftware | None:
        """Level 1: Admin-confirmed override for this org."""
        match_key = f"{raw.publisher}::{raw.display_name}"
        stmt = select(TenantNormalizationOverride).where(
            TenantNormalizationOverride.org_id == self._org_id,
            TenantNormalizationOverride.match_key == match_key,
        )
        result = await self._db.execute(stmt)
        override = result.scalar_one_or_none()
        if override:
            return NormalizedSoftware(
                vendor=override.vendor,
                product=override.product,
                confidence=Decimal("1.00"),
                match_method="tenant_override",
            )
        return None

    def _try_product_code(self, raw: AppRecord) -> NormalizedSoftware | None:
        """Level 2: MSI GUID lookup."""
        if not raw.product_code:
            return None
        match = PRODUCT_CODE_MAP.get(raw.product_code)
        if match:
            return NormalizedSoftware(
                vendor=match[0],
                product=match[1],
                confidence=Decimal("0.98"),
                match_method="product_code",
            )
        return None

    def _try_exact_known_map(self, raw: AppRecord) -> NormalizedSoftware | None:
        """Level 3: Normalized publisher + display_name in KNOWN_MAP."""
        clean_pub = _clean_publisher(raw.publisher)
        vendor = PUBLISHER_MAP.get(clean_pub)
        if vendor is None:
            return None
        clean_name = _clean_name(raw.display_name)
        match = KNOWN_MAP.get((vendor, clean_name))
        if match:
            return NormalizedSoftware(
                vendor=match[0],
                product=match[1],
                confidence=Decimal("0.95"),
                match_method="exact_known_map",
            )
        return None

    def _try_publisher_heuristic(self, raw: AppRecord) -> NormalizedSoftware | None:
        """Level 4: Publisher → vendor, extract product from display name."""
        clean_pub = _clean_publisher(raw.publisher)
        vendor = PUBLISHER_MAP.get(clean_pub)
        if vendor is None:
            return None
        # Extract product name by stripping publisher prefix from display name
        clean_name = _clean_name(raw.display_name)
        # Remove vendor/publisher prefixes
        product = clean_name
        for prefix in (vendor, clean_pub, raw.publisher.lower()):
            if product.startswith(prefix):
                product = product[len(prefix):].strip().lstrip("-").strip()
        product = product or clean_name
        # Normalize product: replace spaces/special chars with underscores
        product = re.sub(r"[^a-z0-9+]+", "_", product).strip("_")
        if not product:
            return None
        return NormalizedSoftware(
            vendor=vendor,
            product=product,
            confidence=Decimal("0.75"),
            match_method="publisher_heuristic",
        )

    def _try_fuzzy(self, raw: AppRecord) -> NormalizedSoftware | None:
        """Level 5: Edit distance against KNOWN_MAP keys, threshold > 0.8."""
        clean_pub = _clean_publisher(raw.publisher)
        vendor = PUBLISHER_MAP.get(clean_pub)
        if vendor is None:
            return None
        clean_name = _clean_name(raw.display_name)
        best_score = 0.0
        best_match: tuple[str, str] | None = None
        for (map_vendor, map_product), (cpe_vendor, cpe_product) in KNOWN_MAP.items():
            if map_vendor != vendor:
                continue
            score = SequenceMatcher(None, clean_name, map_product).ratio()
            if score > best_score:
                best_score = score
                best_match = (cpe_vendor, cpe_product)
        if best_match and best_score > 0.8:
            return NormalizedSoftware(
                vendor=best_match[0],
                product=best_match[1],
                confidence=Decimal("0.50"),
                match_method="fuzzy",
            )
        return None
