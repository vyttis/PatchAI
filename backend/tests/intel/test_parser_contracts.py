"""Parser contract tests — pinned fixtures, pure function assertions.

These tests verify that each feed parser can parse its pinned fixture file
and extract the expected structural invariants. No DB, no HTTP — pure parsing.
"""

from decimal import Decimal
from pathlib import Path

from backend.app.workers.intel_fetcher import (
    EPSSFetcher,
    KEVFetcher,
    MSRCFetcher,
    NVDFetcher,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# KEV parser contract
# ---------------------------------------------------------------------------


def test_kev_parser_contract():
    """Parse kev_sample.json: 5 entities, all CVE-prefixed, all have dates."""
    raw = FIXTURES_DIR.joinpath("kev_sample.json").read_bytes()
    entities = KEVFetcher._parse(None, raw)  # _parse is pure, self unused for parsing

    assert len(entities) == 5

    for entity in entities:
        assert entity["cve_id"].startswith("CVE-"), f"Bad CVE ID: {entity['cve_id']}"
        assert entity["kev_added_date"] is not None, f"Missing date for {entity['cve_id']}"
        assert entity["vendor_project"], f"Empty vendor_project for {entity['cve_id']}"


# ---------------------------------------------------------------------------
# MSRC parser contract
# ---------------------------------------------------------------------------


def test_msrc_parser_contract():
    """Parse msrc_sample.json: valid advisory structure with CVEs and KBs."""
    raw = FIXTURES_DIR.joinpath("msrc_sample.json").read_bytes()
    entities = MSRCFetcher._parse(None, raw)

    assert len(entities) >= 1

    for entity in entities:
        assert entity["advisory_id"], "Missing advisory_id"
        assert entity["title"], "Missing title"
        assert isinstance(entity.get("cves"), list), "CVEs should be a list"
        assert isinstance(entity.get("kbs"), list), "KBs should be a list"

    # The pinned sample has one advisory with 3 CVEs and 2 KBs
    first = entities[0]
    assert len(first["cves"]) == 3
    for cve in first["cves"]:
        assert cve.startswith("CVE-"), f"Bad CVE: {cve}"
    assert len(first["kbs"]) == 2


# ---------------------------------------------------------------------------
# EPSS parser contract
# ---------------------------------------------------------------------------


def test_epss_parser_contract():
    """Parse epss_sample.csv.gz: 100 rows, all scores in [0, 1]."""
    raw = FIXTURES_DIR.joinpath("epss_sample.csv.gz").read_bytes()
    entities = EPSSFetcher._parse(None, raw)

    assert len(entities) == 100

    for entity in entities:
        assert entity["cve_id"].startswith("CVE-"), f"Bad CVE: {entity['cve_id']}"
        score = entity["epss_score"]
        percentile = entity["epss_percentile"]
        assert Decimal("0") <= score <= Decimal("1"), f"Score out of range: {score}"
        assert Decimal("0") <= percentile <= Decimal("1"), f"Percentile out of range: {percentile}"


# ---------------------------------------------------------------------------
# NVD parser contract
# ---------------------------------------------------------------------------


def test_nvd_parser_contract():
    """Parse nvd_sample.json: 3 CVEs, all have cvss_base_score."""
    raw = FIXTURES_DIR.joinpath("nvd_sample.json").read_bytes()
    entities = NVDFetcher._parse(None, raw)

    assert len(entities) == 3

    for entity in entities:
        assert entity["cve_id"].startswith("CVE-"), f"Bad CVE: {entity['cve_id']}"
        assert entity["cvss_base_score"] is not None, (
            f"Missing cvss_base_score for {entity['cve_id']}"
        )
        assert entity["cvss_base_score"] > 0, (
            f"Invalid score for {entity['cve_id']}: {entity['cvss_base_score']}"
        )

    # Verify CPE data present for entries that have configurations
    cves_with_cpe = [e for e in entities if e.get("cpe_matches")]
    assert len(cves_with_cpe) >= 2, "Expected at least 2 CVEs with CPE matches"
