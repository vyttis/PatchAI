"""Intel feed fetcher framework — base class + 5 feed subclasses + staleness monitor.

Invariant #8:  All intel feed fetches store raw blob BEFORE parsing.
               Parse errors store parse_error status and alert ops.
               Never silently lose provenance.

Invariant #9:  NVD is enrichment ONLY. Never an emergency trigger.
               Cadence: 6h intentional.

Invariant #13: Parse errors ≠ availability failures.
               Store blob, mark parse_error, alert ops.
               Do NOT serve last_good_data on parse error.
"""

from __future__ import annotations

import asyncio
import csv
import gzip
import hashlib
import io
import json
import logging
import uuid as _uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

import httpx
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.models.advisories import Advisory, AdvisoryVulnerability
from backend.app.models.intel_feeds import IntelFeedBlob, IntelFeedHealth, IntelLastGood
from backend.app.models.remediations import (
    Remediation,
    RemediationOsTarget,
    RemediationVulnerability,
)
from backend.app.models.vulnerabilities import Vulnerability
from backend.app.models.vulnerability_products import VulnerabilityProduct

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

class ParseError(Exception):
    """Raised when feed data cannot be parsed — indicates schema drift."""


@dataclass
class FetchResult:
    status: str  # "success" | "dedup_skip" | "parse_error" | "last_good_fallback"
    entity_count: int = 0
    error: str | None = None


# ---------------------------------------------------------------------------
# Base IntelFetcher
# ---------------------------------------------------------------------------

class IntelFetcher:
    """Base class for all intel feed fetchers.

    Subclasses must define:
        FEED_SOURCE: str   — e.g. "kev", "msrc"
        STALENESS_HOURS: int

    And implement:
        async fetch_raw() -> bytes
        _parse(raw: bytes) -> list[dict]   — PURE function, no DB/HTTP
        async _upsert_entities(entities: list[dict]) -> None
    """

    FEED_SOURCE: str = ""
    STALENESS_HOURS: int = 24

    def __init__(self, db: AsyncSession, http: httpx.AsyncClient) -> None:
        self.db = db
        self.http = http

    # ---- Main entry point --------------------------------------------------

    async def run(self) -> FetchResult:
        """Execute the full fetch→store→parse→upsert pipeline."""
        try:
            raw = await self.fetch_raw()
        except Exception as exc:
            await self._update_health(success=False)
            logger.error("Fetch failed for %s: %s", self.FEED_SOURCE, exc)
            return FetchResult(status="fetch_error", error=str(exc))

        if raw is None:
            return FetchResult(status="fetch_error", error="No data returned")

        h = hashlib.sha256(raw).hexdigest()

        # Dedup: skip if blob_hash already exists for this feed
        if await self._blob_exists(h):
            await self._update_health(success=True)
            return FetchResult(status="dedup_skip")

        # Invariant #8: store raw blob BEFORE parsing
        blob_id = await self._store_blob(raw, h)

        try:
            entities = self._parse(raw)
        except ParseError as exc:
            # Invariant #13: parse error ≠ availability failure
            # Store error, alert ops, do NOT serve last_good_data
            await self._record_parse_error(blob_id, exc)
            await self._alert_ops_parse_error(exc)
            return FetchResult(status="parse_error", error=str(exc))

        await self._upsert_entities(entities)
        await self._update_health(success=True)
        await self._store_last_good(raw)
        await self._mark_blob_processed(blob_id, len(entities))

        return FetchResult(status="success", entity_count=len(entities))

    # ---- Subclass hooks (must override) ------------------------------------

    async def fetch_raw(self) -> bytes:
        raise NotImplementedError

    def _parse(self, raw: bytes) -> list[dict]:
        """Parse raw bytes into entity dicts. PURE — no DB, no HTTP."""
        raise NotImplementedError

    async def _upsert_entities(self, entities: list[dict]) -> None:
        raise NotImplementedError

    # ---- Shared helpers ----------------------------------------------------

    async def _blob_exists(self, blob_hash: str) -> bool:
        result = await self.db.execute(
            select(IntelFeedBlob.id).where(
                IntelFeedBlob.blob_hash == blob_hash,
                IntelFeedBlob.feed_source == self.FEED_SOURCE,
            )
        )
        return result.scalar_one_or_none() is not None

    async def _store_blob(self, raw: bytes, blob_hash: str) -> _uuid.UUID:
        blob = IntelFeedBlob(
            id=_uuid.uuid4(),
            feed_source=self.FEED_SOURCE,
            blob_hash=blob_hash,
            byte_size=len(raw),
            status="pending",
        )
        self.db.add(blob)
        await self.db.flush()
        return blob.id

    async def _record_parse_error(self, blob_id: _uuid.UUID, error: Exception) -> None:
        await self.db.execute(
            update(IntelFeedBlob)
            .where(IntelFeedBlob.id == blob_id)
            .values(status="parse_error", error=str(error))
        )
        await self._update_health(success=False, parse_error=str(error))
        await self.db.flush()

    async def _alert_ops_parse_error(self, error: Exception) -> None:
        logger.critical(
            "PARSE ERROR for feed %s — schema drift suspected: %s",
            self.FEED_SOURCE,
            error,
        )

    async def _update_health(
        self, *, success: bool, parse_error: str | None = None
    ) -> None:
        now = datetime.now(timezone.utc)
        result = await self.db.execute(
            select(IntelFeedHealth).where(
                IntelFeedHealth.feed_source == self.FEED_SOURCE
            )
        )
        health = result.scalar_one_or_none()

        if health is None:
            health = IntelFeedHealth(
                feed_source=self.FEED_SOURCE,
                last_fetched_at=now,
                last_success_at=now if success else None,
                consecutive_failures=0 if success else 1,
                parse_failures=0,
                is_stale=False,
            )
            self.db.add(health)
        else:
            health.last_fetched_at = now
            if success:
                health.last_success_at = now
                health.consecutive_failures = 0
                health.is_stale = False
            else:
                health.consecutive_failures += 1

            if parse_error:
                health.parse_failures += 1
                health.last_parse_error = parse_error
                health.last_parse_error_at = now

        await self.db.flush()

    async def _store_last_good(self, raw: bytes) -> None:
        result = await self.db.execute(
            select(IntelLastGood).where(
                IntelLastGood.feed_source == self.FEED_SOURCE
            )
        )
        last_good = result.scalar_one_or_none()
        if last_good is None:
            last_good = IntelLastGood(
                feed_source=self.FEED_SOURCE,
                data=raw,
                stored_at=datetime.now(timezone.utc),
            )
            self.db.add(last_good)
        else:
            last_good.data = raw
            last_good.stored_at = datetime.now(timezone.utc)
        await self.db.flush()

    async def _mark_blob_processed(
        self, blob_id: _uuid.UUID, entity_count: int
    ) -> None:
        await self.db.execute(
            update(IntelFeedBlob)
            .where(IntelFeedBlob.id == blob_id)
            .values(status="processed", entity_count=entity_count)
        )
        await self.db.flush()


# ---------------------------------------------------------------------------
# KEV Fetcher
# ---------------------------------------------------------------------------

class KEVFetcher(IntelFetcher):
    """CISA Known Exploited Vulnerabilities catalog fetcher.

    Cadence: every 4h (emergency trigger).
    KEV entries queue check_fleet_for_kev_exposure for newly-added CVEs.
    """

    FEED_SOURCE = "kev"
    STALENESS_HOURS = 12
    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    async def fetch_raw(self) -> bytes:
        resp = await self.http.get(self.URL)
        resp.raise_for_status()
        return resp.content

    def _parse(self, raw: bytes) -> list[dict]:
        """Parse KEV JSON catalog. Pure function."""
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ParseError(f"KEV JSON decode failed: {exc}") from exc

        vulns = data.get("vulnerabilities")
        if not isinstance(vulns, list):
            raise ParseError("KEV JSON missing 'vulnerabilities' array")

        entities = []
        for entry in vulns:
            cve_id = entry.get("cveID", "").strip()
            if not cve_id.startswith("CVE-"):
                continue

            date_added_str = entry.get("dateAdded", "")
            try:
                kev_added_date = date.fromisoformat(date_added_str) if date_added_str else None
            except ValueError:
                kev_added_date = None

            entities.append({
                "cve_id": cve_id,
                "kev_added_date": kev_added_date,
                "vendor_project": entry.get("vendorProject", ""),
                "product": entry.get("product", ""),
                "vulnerability_name": entry.get("vulnerabilityName", ""),
                "short_description": entry.get("shortDescription", ""),
            })

        return entities

    async def _upsert_entities(self, entities: list[dict]) -> None:
        new_kev_cves: list[str] = []

        for entity in entities:
            cve_id = entity["cve_id"]

            result = await self.db.execute(
                select(Vulnerability).where(Vulnerability.cve_id == cve_id)
            )
            vuln = result.scalar_one_or_none()

            if vuln is None:
                # New vulnerability
                vuln = Vulnerability(
                    cve_id=cve_id,
                    in_cisa_kev=True,
                    kev_added_date=entity["kev_added_date"],
                    description=entity["vulnerability_name"]
                    or entity["short_description"],
                )
                self.db.add(vuln)
                new_kev_cves.append(cve_id)
            elif not vuln.in_cisa_kev:
                # Existing vuln, newly added to KEV
                vuln.in_cisa_kev = True
                vuln.kev_added_date = entity["kev_added_date"]
                new_kev_cves.append(cve_id)
            else:
                # Already in KEV, update date if changed
                if entity["kev_added_date"] and vuln.kev_added_date != entity["kev_added_date"]:
                    vuln.kev_added_date = entity["kev_added_date"]

        await self.db.flush()

        # Enqueue fleet exposure check for NEW KEV entries
        for cve_id in new_kev_cves:
            try:
                from backend.app.workers.tasks import check_fleet_for_kev_exposure
                check_fleet_for_kev_exposure.delay(cve_id)
            except Exception:
                logger.warning(
                    "Could not enqueue check_fleet_for_kev_exposure for %s", cve_id
                )


# ---------------------------------------------------------------------------
# MSRC Fetcher
# ---------------------------------------------------------------------------

class MSRCFetcher(IntelFetcher):
    """Microsoft Security Response Center fetcher.

    Cadence: every 2h (emergency co-trigger).
    Resilience: 5x exponential backoff (BASE=30s, MAX=600s),
    Retry-After header on 429, 2h Redis cache per monthly release,
    intel_last_good fallback on all retries exhausted.
    12h staleness threshold (CRITICAL).
    """

    FEED_SOURCE = "msrc"
    STALENESS_HOURS = 12
    BACKOFF_BASE = 30
    BACKOFF_MAX = 600
    MAX_RETRIES = 5
    BASE_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"

    def __init__(
        self,
        db: AsyncSession,
        http: httpx.AsyncClient,
        redis_client: Any | None = None,
    ) -> None:
        super().__init__(db, http)
        self.redis = redis_client

    async def fetch_raw(self) -> bytes:
        now = datetime.now(timezone.utc)
        cache_key = f"msrc_raw:{now.strftime('%Y-%b')}"

        # Check Redis cache first (2h TTL)
        if self.redis is not None:
            try:
                cached = await self.redis.get(cache_key)
                if cached is not None:
                    return cached if isinstance(cached, bytes) else cached.encode()
            except Exception:
                logger.warning("MSRC Redis cache read failed, proceeding to HTTP")

        from backend.app.config import settings

        headers = {}
        if settings.msrc_api_key:
            headers["api-key"] = settings.msrc_api_key

        last_exc: Exception | None = None
        for attempt in range(self.MAX_RETRIES):
            try:
                resp = await self.http.get(self.BASE_URL, headers=headers)

                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", 0))
                    backoff = min(
                        self.BACKOFF_MAX,
                        max(retry_after, self.BACKOFF_BASE * (2 ** attempt)),
                    )
                    logger.warning(
                        "MSRC 429 on attempt %d/%d, backing off %ds",
                        attempt + 1,
                        self.MAX_RETRIES,
                        backoff,
                    )
                    await asyncio.sleep(backoff)
                    continue

                resp.raise_for_status()
                raw = resp.content

                # Cache in Redis with 2h TTL
                if self.redis is not None:
                    try:
                        await self.redis.set(cache_key, raw, ex=7200)
                    except Exception:
                        logger.warning("MSRC Redis cache write failed")

                return raw

            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 429:
                    last_exc = exc
                    continue
                last_exc = exc
                backoff = min(
                    self.BACKOFF_MAX,
                    self.BACKOFF_BASE * (2 ** attempt),
                )
                logger.warning(
                    "MSRC HTTP error %s on attempt %d/%d, backing off %ds",
                    exc.response.status_code,
                    attempt + 1,
                    self.MAX_RETRIES,
                    backoff,
                )
                await asyncio.sleep(backoff)

            except Exception as exc:
                last_exc = exc
                backoff = min(
                    self.BACKOFF_MAX,
                    self.BACKOFF_BASE * (2 ** attempt),
                )
                logger.warning(
                    "MSRC fetch error on attempt %d/%d: %s, backing off %ds",
                    attempt + 1,
                    self.MAX_RETRIES,
                    exc,
                    backoff,
                )
                await asyncio.sleep(backoff)

        # All retries exhausted — serve intel_last_good + alert ops
        # (Network failure, NOT parse error — serving last_good is allowed)
        logger.critical(
            "MSRC all %d retries exhausted. Serving intel_last_good fallback.",
            self.MAX_RETRIES,
        )
        result = await self.db.execute(
            select(IntelLastGood).where(IntelLastGood.feed_source == self.FEED_SOURCE)
        )
        last_good = result.scalar_one_or_none()
        if last_good and last_good.data:
            self._using_last_good = True
            return last_good.data

        raise last_exc or RuntimeError("MSRC fetch failed, no last_good available")

    def _parse(self, raw: bytes) -> list[dict]:
        """Parse MSRC API response. Pure function."""
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ParseError(f"MSRC JSON decode failed: {exc}") from exc

        # The MSRC updates API returns a list of update entries
        entries = data if isinstance(data, list) else data.get("value", [])
        if not isinstance(entries, list):
            raise ParseError("MSRC response missing expected list structure")

        entities: list[dict] = []
        for entry in entries:
            advisory_id = entry.get("ID", "")
            if not advisory_id:
                continue

            cve_list = entry.get("CvrfUrl", "")
            published_str = entry.get("InitialReleaseDate", "")
            try:
                published_at = (
                    datetime.fromisoformat(published_str.replace("Z", "+00:00"))
                    if published_str
                    else None
                )
            except ValueError:
                published_at = None

            severity = entry.get("Severity", "")
            title = entry.get("DocumentTitle", advisory_id)

            # Extract CVEs if available in the entry
            cves = entry.get("CVEs", []) or []
            # Extract KB articles if available
            kbs = entry.get("KBArticles", []) or []

            entities.append({
                "advisory_id": advisory_id,
                "title": title,
                "severity": severity,
                "published_at": published_at,
                "advisory_url": entry.get("CvrfUrl", ""),
                "cves": cves,
                "kbs": kbs,
            })

        return entities

    async def _upsert_entities(self, entities: list[dict]) -> None:
        for entity in entities:
            ext_id = entity["advisory_id"]

            result = await self.db.execute(
                select(Advisory).where(Advisory.external_id == ext_id)
            )
            advisory = result.scalar_one_or_none()

            if advisory is None:
                advisory = Advisory(
                    source="msrc",
                    external_id=ext_id,
                    title=entity.get("title"),
                    published_at=entity.get("published_at"),
                    severity=entity.get("severity"),
                    advisory_url=entity.get("advisory_url"),
                )
                self.db.add(advisory)
                await self.db.flush()

            # Link CVEs
            for cve_id in entity.get("cves", []):
                if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
                    continue

                vuln_result = await self.db.execute(
                    select(Vulnerability).where(Vulnerability.cve_id == cve_id)
                )
                vuln = vuln_result.scalar_one_or_none()
                if vuln is None:
                    vuln = Vulnerability(cve_id=cve_id)
                    self.db.add(vuln)
                    await self.db.flush()

                # Check if join already exists
                av_result = await self.db.execute(
                    select(AdvisoryVulnerability).where(
                        AdvisoryVulnerability.advisory_id == advisory.id,
                        AdvisoryVulnerability.vuln_id == vuln.id,
                    )
                )
                if av_result.scalar_one_or_none() is None:
                    self.db.add(
                        AdvisoryVulnerability(
                            advisory_id=advisory.id, vuln_id=vuln.id
                        )
                    )

            # Upsert KB remediations
            for kb in entity.get("kbs", []):
                kb_number = kb if isinstance(kb, str) else kb.get("ID", "")
                if not kb_number:
                    continue

                rem_result = await self.db.execute(
                    select(Remediation).where(Remediation.external_id == kb_number)
                )
                rem = rem_result.scalar_one_or_none()
                if rem is None:
                    rem = Remediation(
                        source="msrc",
                        external_id=kb_number,
                        title=f"Security Update {kb_number}",
                        playbook={"type": "patch", "kb": kb_number},
                        released_at=entity.get("published_at"),
                    )
                    self.db.add(rem)
                    await self.db.flush()

        await self.db.flush()

    async def run(self) -> FetchResult:
        """Override to detect last_good fallback scenario."""
        self._using_last_good = False
        result = await super().run()
        if self._using_last_good and result.status == "success":
            result.status = "last_good_fallback"
        return result


# ---------------------------------------------------------------------------
# EPSS Fetcher
# ---------------------------------------------------------------------------

class EPSSFetcher(IntelFetcher):
    """FIRST EPSS scores fetcher.

    Cadence: daily 02:00 (urgency multiplier, not a trigger).
    Large gzipped CSV → stored via storage_path, not inline BYTEA.
    """

    FEED_SOURCE = "epss"
    STALENESS_HOURS = 30
    URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

    def __init__(
        self,
        db: AsyncSession,
        http: httpx.AsyncClient,
        storage_client: Any | None = None,
    ) -> None:
        super().__init__(db, http)
        self.storage_client = storage_client

    async def fetch_raw(self) -> bytes:
        resp = await self.http.get(self.URL)
        resp.raise_for_status()
        return resp.content

    def _parse(self, raw: bytes) -> list[dict]:
        """Parse gzipped EPSS CSV. Pure function."""
        try:
            decompressed = gzip.decompress(raw)
        except (gzip.BadGzipFile, OSError) as exc:
            raise ParseError(f"EPSS gzip decompress failed: {exc}") from exc

        text = decompressed.decode("utf-8", errors="replace")
        lines = text.strip().splitlines()

        # Skip comment/header lines starting with #
        data_lines = [ln for ln in lines if not ln.startswith("#")]
        if not data_lines:
            raise ParseError("EPSS CSV has no data rows after removing comments")

        reader = csv.DictReader(data_lines)
        entities = []

        for row in reader:
            cve_id = row.get("cve", "").strip()
            if not cve_id.startswith("CVE-"):
                continue

            try:
                score = Decimal(row.get("epss", "0"))
                percentile = Decimal(row.get("percentile", "0"))
            except (InvalidOperation, TypeError):
                continue

            if not (Decimal("0") <= score <= Decimal("1")):
                continue
            if not (Decimal("0") <= percentile <= Decimal("1")):
                continue

            entities.append({
                "cve_id": cve_id,
                "epss_score": score,
                "epss_percentile": percentile,
            })

        return entities

    async def _store_blob(self, raw: bytes, blob_hash: str) -> _uuid.UUID:
        """Override: store large EPSS file via storage_path, not inline."""
        storage_path = None
        if self.storage_client is not None:
            storage_path = f"intel/epss/{blob_hash}.csv.gz"
            try:
                await self.storage_client.upload(storage_path, raw)
            except Exception:
                logger.warning("EPSS storage upload failed, blob stored without path")
                storage_path = None

        blob = IntelFeedBlob(
            id=_uuid.uuid4(),
            feed_source=self.FEED_SOURCE,
            blob_hash=blob_hash,
            byte_size=len(raw),
            storage_path=storage_path,
            status="pending",
        )
        self.db.add(blob)
        await self.db.flush()
        return blob.id

    async def _upsert_entities(self, entities: list[dict]) -> None:
        for entity in entities:
            result = await self.db.execute(
                select(Vulnerability).where(
                    Vulnerability.cve_id == entity["cve_id"]
                )
            )
            vuln = result.scalar_one_or_none()
            if vuln is not None:
                vuln.epss_score = entity["epss_score"]
                vuln.epss_percentile = entity["epss_percentile"]
        await self.db.flush()


# ---------------------------------------------------------------------------
# NVD Fetcher
# ---------------------------------------------------------------------------

class NVDFetcher(IntelFetcher):
    """NIST NVD 2.0 API fetcher.

    Cadence: every 6h (Invariant #9: enrichment ONLY — never triggers urgency).
    Rate limit: 0.7s delay between pages, sleep(30) on HTTP 403.
    """

    FEED_SOURCE = "nvd"
    STALENESS_HOURS = 24
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    PAGE_DELAY = 0.7
    FORBIDDEN_DELAY = 30

    async def fetch_raw(self) -> bytes:
        from backend.app.config import settings

        # Determine start date: last_success_at or 24h ago
        result = await self.db.execute(
            select(IntelFeedHealth.last_success_at).where(
                IntelFeedHealth.feed_source == self.FEED_SOURCE
            )
        )
        last_success = result.scalar_one_or_none()
        start_date = last_success or (datetime.now(timezone.utc) - timedelta(hours=24))
        if isinstance(start_date, datetime):
            start_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
        else:
            start_str = start_date

        headers = {}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key

        all_results: list[dict] = []
        start_index = 0
        results_per_page = 2000

        while True:
            params = {
                "lastModStartDate": start_str,
                "lastModEndDate": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%S.000+00:00"
                ),
                "startIndex": str(start_index),
                "resultsPerPage": str(results_per_page),
            }

            try:
                resp = await self.http.get(
                    self.BASE_URL, headers=headers, params=params
                )
                if resp.status_code == 403:
                    logger.warning("NVD 403, sleeping %ds", self.FORBIDDEN_DELAY)
                    await asyncio.sleep(self.FORBIDDEN_DELAY)
                    resp = await self.http.get(
                        self.BASE_URL, headers=headers, params=params
                    )
                resp.raise_for_status()
            except Exception:
                break

            page_data = resp.json()
            vulns = page_data.get("vulnerabilities", [])
            all_results.extend(vulns)

            total = page_data.get("totalResults", 0)
            start_index += results_per_page
            if start_index >= total:
                break

            await asyncio.sleep(self.PAGE_DELAY)

        return json.dumps({"vulnerabilities": all_results}).encode()

    def _parse(self, raw: bytes) -> list[dict]:
        """Parse NVD 2.0 JSON. Pure function.

        NVD is enrichment ONLY (Invariant #9).
        """
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ParseError(f"NVD JSON decode failed: {exc}") from exc

        vulns = data.get("vulnerabilities", [])
        if not isinstance(vulns, list):
            raise ParseError("NVD JSON missing 'vulnerabilities' array")

        entities = []
        for item in vulns:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "").strip()
            if not cve_id.startswith("CVE-"):
                continue

            # Extract CVSS score from metrics
            cvss_score = None
            cvss_vector = None
            metrics = cve_data.get("metrics", {})
            for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(version_key, [])
                if metric_list:
                    cvss_data = metric_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString")
                    break

            # Description
            desc_list = cve_data.get("descriptions", [])
            description = ""
            for desc in desc_list:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Dates
            published_str = cve_data.get("published", "")
            last_modified_str = cve_data.get("lastModified", "")

            try:
                published_at = (
                    datetime.fromisoformat(published_str.replace("Z", "+00:00"))
                    if published_str
                    else None
                )
            except ValueError:
                published_at = None
            try:
                last_modified_at = (
                    datetime.fromisoformat(last_modified_str.replace("Z", "+00:00"))
                    if last_modified_str
                    else None
                )
            except ValueError:
                last_modified_at = None

            # References
            refs = cve_data.get("references", [])

            # CPE configurations
            cpe_matches = []
            for config in cve_data.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if match.get("vulnerable"):
                            cpe_matches.append({
                                "cpe_vendor": _extract_cpe_field(
                                    match.get("criteria", ""), 3
                                ),
                                "cpe_product": _extract_cpe_field(
                                    match.get("criteria", ""), 4
                                ),
                                "version_start_including": match.get(
                                    "versionStartIncluding"
                                ),
                                "version_end_excluding": match.get(
                                    "versionEndExcluding"
                                ),
                                "version_end_including": match.get(
                                    "versionEndIncluding"
                                ),
                            })

            entities.append({
                "cve_id": cve_id,
                "cvss_base_score": (
                    Decimal(str(cvss_score)) if cvss_score is not None else None
                ),
                "cvss_vector": cvss_vector,
                "description": description,
                "published_at": published_at,
                "last_modified_at": last_modified_at,
                "references": refs if refs else None,
                "cpe_matches": cpe_matches,
            })

        return entities

    async def _upsert_entities(self, entities: list[dict]) -> None:
        """NVD is enrichment ONLY (Invariant #9).

        Never set in_cisa_kev. Never enqueue fleet checks.
        Never trigger urgency recalculation.
        """
        for entity in entities:
            cve_id = entity["cve_id"]

            result = await self.db.execute(
                select(Vulnerability).where(Vulnerability.cve_id == cve_id)
            )
            vuln = result.scalar_one_or_none()

            if vuln is None:
                vuln = Vulnerability(
                    cve_id=cve_id,
                    cvss_base_score=entity.get("cvss_base_score"),
                    cvss_vector=entity.get("cvss_vector"),
                    description=entity.get("description"),
                    published_at=entity.get("published_at"),
                    last_modified_at=entity.get("last_modified_at"),
                    references=entity.get("references"),
                    # in_cisa_kev stays default False — NVD never sets KEV
                )
                self.db.add(vuln)
                await self.db.flush()
            else:
                # Enrich existing record — DO NOT touch in_cisa_kev or kev_added_date
                if entity.get("cvss_base_score") is not None:
                    vuln.cvss_base_score = entity["cvss_base_score"]
                if entity.get("cvss_vector"):
                    vuln.cvss_vector = entity["cvss_vector"]
                if entity.get("description"):
                    vuln.description = entity["description"]
                if entity.get("published_at"):
                    vuln.published_at = entity["published_at"]
                if entity.get("last_modified_at"):
                    vuln.last_modified_at = entity["last_modified_at"]
                if entity.get("references"):
                    vuln.references = entity["references"]

            # Upsert CPE matches (VulnerabilityProduct)
            for cpe in entity.get("cpe_matches", []):
                vp_result = await self.db.execute(
                    select(VulnerabilityProduct).where(
                        VulnerabilityProduct.vuln_id == vuln.id,
                        VulnerabilityProduct.cpe_vendor == cpe.get("cpe_vendor"),
                        VulnerabilityProduct.cpe_product == cpe.get("cpe_product"),
                    )
                )
                if vp_result.scalar_one_or_none() is None:
                    self.db.add(
                        VulnerabilityProduct(
                            vuln_id=vuln.id,
                            cpe_vendor=cpe.get("cpe_vendor"),
                            cpe_product=cpe.get("cpe_product"),
                            version_start_including=cpe.get("version_start_including"),
                            version_end_excluding=cpe.get("version_end_excluding"),
                            version_end_including=cpe.get("version_end_including"),
                        )
                    )

        await self.db.flush()


# ---------------------------------------------------------------------------
# GHSA Fetcher
# ---------------------------------------------------------------------------

class GHSAFetcher(IntelFetcher):
    """GitHub Security Advisory Database fetcher.

    Cadence: daily 03:00 (third-party coverage).
    Uses GraphQL API.
    """

    FEED_SOURCE = "ghsa"
    STALENESS_HOURS = 36
    GRAPHQL_URL = "https://api.github.com/graphql"

    QUERY = """
    query($since: DateTime, $cursor: String) {
      securityAdvisories(
        updatedSince: $since,
        first: 100,
        after: $cursor,
        orderBy: {field: UPDATED_AT, direction: ASC}
      ) {
        nodes {
          ghsaId
          summary
          severity
          description
          publishedAt
          identifiers {
            type
            value
          }
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
    """

    async def fetch_raw(self) -> bytes:
        result = await self.db.execute(
            select(IntelFeedHealth.last_success_at).where(
                IntelFeedHealth.feed_source == self.FEED_SOURCE
            )
        )
        last_success = result.scalar_one_or_none()
        since = (
            last_success.isoformat() if last_success
            else (datetime.now(timezone.utc) - timedelta(hours=36)).isoformat()
        )

        all_nodes: list[dict] = []
        cursor = None

        while True:
            variables: dict[str, Any] = {"since": since}
            if cursor:
                variables["cursor"] = cursor

            resp = await self.http.post(
                self.GRAPHQL_URL,
                json={"query": self.QUERY, "variables": variables},
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()

            data = resp.json()
            advisories = (
                data.get("data", {}).get("securityAdvisories", {})
            )
            nodes = advisories.get("nodes", [])
            all_nodes.extend(nodes)

            page_info = advisories.get("pageInfo", {})
            if page_info.get("hasNextPage") and page_info.get("endCursor"):
                cursor = page_info["endCursor"]
            else:
                break

        return json.dumps({"advisories": all_nodes}).encode()

    def _parse(self, raw: bytes) -> list[dict]:
        """Parse GHSA response. Pure function."""
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ParseError(f"GHSA JSON decode failed: {exc}") from exc

        advisories = data.get("advisories", [])
        if not isinstance(advisories, list):
            raise ParseError("GHSA JSON missing 'advisories' array")

        entities = []
        for advisory in advisories:
            ghsa_id = advisory.get("ghsaId", "")
            if not ghsa_id:
                continue

            cve_ids = []
            for ident in advisory.get("identifiers", []):
                if ident.get("type") == "CVE":
                    cve_ids.append(ident.get("value", ""))

            published_str = advisory.get("publishedAt", "")
            try:
                published_at = (
                    datetime.fromisoformat(published_str.replace("Z", "+00:00"))
                    if published_str
                    else None
                )
            except ValueError:
                published_at = None

            entities.append({
                "ghsa_id": ghsa_id,
                "summary": advisory.get("summary", ""),
                "severity": advisory.get("severity", ""),
                "description": advisory.get("description", ""),
                "published_at": published_at,
                "cve_ids": cve_ids,
            })

        return entities

    async def _upsert_entities(self, entities: list[dict]) -> None:
        for entity in entities:
            for cve_id in entity.get("cve_ids", []):
                if not cve_id.startswith("CVE-"):
                    continue

                result = await self.db.execute(
                    select(Vulnerability).where(Vulnerability.cve_id == cve_id)
                )
                vuln = result.scalar_one_or_none()
                if vuln is None:
                    vuln = Vulnerability(
                        cve_id=cve_id,
                        description=entity.get("summary"),
                        published_at=entity.get("published_at"),
                    )
                    self.db.add(vuln)
                elif not vuln.description and entity.get("summary"):
                    vuln.description = entity["summary"]

        await self.db.flush()


# ---------------------------------------------------------------------------
# Staleness Monitor
# ---------------------------------------------------------------------------

STALENESS_THRESHOLDS: dict[str, tuple[int, str]] = {
    "kev": (12, "CRITICAL"),
    "msrc": (12, "CRITICAL"),
    "nvd": (24, "WARNING"),
    "epss": (30, "WARNING"),
    "ghsa": (36, "INFO"),
}


async def check_staleness(db: AsyncSession) -> dict[str, bool]:
    """Check all feeds against staleness thresholds.

    Updates intel_feed_health.is_stale flag and logs at appropriate level.
    Returns dict of {feed_source: is_stale}.
    """
    now = datetime.now(timezone.utc)
    results: dict[str, bool] = {}

    for feed_source, (threshold_hours, severity) in STALENESS_THRESHOLDS.items():
        result = await db.execute(
            select(IntelFeedHealth).where(
                IntelFeedHealth.feed_source == feed_source
            )
        )
        health = result.scalar_one_or_none()

        if health is None:
            # No health record = feed never ran, create one marked stale
            health = IntelFeedHealth(
                feed_source=feed_source,
                is_stale=True,
            )
            db.add(health)
            results[feed_source] = True
            _log_staleness(feed_source, severity, None)
            continue

        if health.last_success_at is None:
            is_stale = True
        else:
            hours_since = (now - health.last_success_at).total_seconds() / 3600
            is_stale = hours_since > threshold_hours

        health.is_stale = is_stale
        results[feed_source] = is_stale

        if is_stale:
            _log_staleness(feed_source, severity, health.last_success_at)

    await db.flush()
    return results


def _log_staleness(
    feed_source: str, severity: str, last_success: datetime | None
) -> None:
    msg = "Feed %s is STALE (last_success: %s)"
    if severity == "CRITICAL":
        logger.critical(msg, feed_source, last_success)
    elif severity == "WARNING":
        logger.warning(msg, feed_source, last_success)
    else:
        logger.info(msg, feed_source, last_success)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_cpe_field(cpe_uri: str, index: int) -> str | None:
    """Extract a field from a CPE 2.3 URI (colon-separated)."""
    parts = cpe_uri.split(":")
    if len(parts) > index:
        val = parts[index]
        return val if val != "*" else None
    return None
