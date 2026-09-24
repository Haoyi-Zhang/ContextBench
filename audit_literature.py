"""Audit frozen literature records and manuscript/BibTeX closure.

This is deliberately an offline reproducibility check.  It verifies that the
source-verified inventory, calibration matrix, resource ledger, TeX citations,
and BibTeX metadata remain mutually consistent; it does not contact DOI,
publisher, proceedings, standards, or arXiv services during reproduction.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any


class LiteratureAuditError(ValueError):
    """Raised when the literature inventory is internally inconsistent."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LiteratureAuditError(message)


def read_csv(path: Path) -> list[dict[str, str]]:
    require(path.is_file(), f"missing file: {path.name}")
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def normalized_title(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def tex_citations(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    keys: set[str] = set()
    for group in re.findall(r"\\cite\{([^}]*)\}", text):
        keys.update(item.strip() for item in group.split(",") if item.strip())
    return keys


def _balanced_value(text: str, start: int, opener: str, closer: str) -> tuple[str, int]:
    depth = 1
    index = start + 1
    escaped = False
    while index < len(text):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return text[start + 1:index], index + 1
        index += 1
    raise LiteratureAuditError("unterminated BibTeX value")


def bib_entries(path: Path) -> dict[str, dict[str, str]]:
    """Parse the constrained BibTeX database without an external dependency."""
    text = path.read_text(encoding="utf-8")
    entries: dict[str, dict[str, str]] = {}
    index = 0
    while True:
        match = re.search(r"@(\w+)\s*([({])", text[index:])
        if match is None:
            break
        entry_start = index + match.start()
        opener = match.group(2)
        closer = "}" if opener == "{" else ")"
        body_start = index + match.end() - 1
        body, next_index = _balanced_value(text, body_start, opener, closer)
        comma = body.find(",")
        require(comma > 0, f"malformed BibTeX entry near offset {entry_start}")
        key = body[:comma].strip()
        require(key and key not in entries, f"duplicate or empty BibTeX key: {key}")
        fields: dict[str, str] = {"entry_type": match.group(1).casefold()}
        cursor = comma + 1
        while cursor < len(body):
            while cursor < len(body) and (body[cursor].isspace() or body[cursor] == ","):
                cursor += 1
            if cursor >= len(body):
                break
            field_match = re.match(r"([A-Za-z][A-Za-z0-9_-]*)\s*=\s*", body[cursor:])
            require(field_match is not None, f"malformed field in BibTeX entry {key}")
            field = field_match.group(1).casefold()
            cursor += field_match.end()
            if body[cursor] == "{":
                value, cursor = _balanced_value(body, cursor, "{", "}")
            elif body[cursor] == '"':
                value, cursor = _balanced_value(body, cursor, '"', '"')
            else:
                end = body.find(",", cursor)
                if end < 0:
                    end = len(body)
                value = body[cursor:end].strip()
                cursor = end
            require(field not in fields, f"duplicate BibTeX field {field} in {key}")
            fields[field] = value.strip()
        entries[key] = fields
        index = next_index
    return entries


def normalized_bib_text(value: str) -> str:
    value = re.sub(r"\\[\\\"'`^~=.uvHckbdtr]\s*\{?([A-Za-z])\}?", r"\1", value)
    value = re.sub(r"\\[A-Za-z]+\*?(?:\s*\{([^{}]*)\})?", lambda m: m.group(1) or "", value)
    value = value.replace("{", "").replace("}", "")
    value = unicodedata.normalize("NFKD", value)
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def verify_bib_metadata(
    inventory: list[dict[str, str]], entries: dict[str, dict[str, str]]
) -> None:
    for row in inventory:
        key = row["citation_key"]
        require(key in entries, f"BibTeX entry missing for {key}")
        entry = entries[key]
        require(entry.get("year") == row["year"], f"BibTeX year differs for {key}")
        require(
            normalized_bib_text(entry.get("title", "")) == normalized_bib_text(row["title"]),
            f"BibTeX title differs for {key}",
        )
        require(
            normalized_bib_text(entry.get("author", "")) == normalized_bib_text(row["authors"]),
            f"BibTeX author list differs for {key}",
        )
        venue = entry.get("booktitle") or entry.get("journal") or entry.get("howpublished") or ""
        require(
            normalized_bib_text(venue) == normalized_bib_text(row["venue"]),
            f"BibTeX venue differs for {key}",
        )
        if key == "lu2021codexglue":
            require(entry.get("volume") == "1", "CodeXGLUE proceedings volume must be 1")
            require("pages" not in entry, "CodeXGLUE has no verified global page range")
        stable = row["stable_identifier"]
        if stable.startswith("https://doi.org/"):
            expected = stable.removeprefix("https://doi.org/").casefold()
            require(entry.get("doi", "").casefold() == expected, f"BibTeX DOI differs for {key}")
        elif stable.startswith("https://arxiv.org/abs/"):
            expected = stable.rsplit("/", 1)[-1]
            require(entry.get("eprint") == expected, f"BibTeX arXiv id differs for {key}")
            require(entry.get("url") == stable, f"BibTeX stable URL differs for {key}")
        else:
            require(entry.get("url") == stable, f"BibTeX stable URL differs for {key}")


def audit(
    artifact_root: Path,
    *,
    tex_path: Path | None = None,
    bib_path: Path | None = None,
) -> dict[str, Any]:
    inventory = read_csv(artifact_root / "bibliography-inventory.csv")
    matrix = read_csv(artifact_root / "literature-comparison.csv")
    resources = read_csv(artifact_root / "external_resources.csv")

    required_inventory = {
        "citation_key", "title", "authors", "venue", "year", "category",
        "stable_identifier", "record_type", "peer_review_status",
        "verification_date", "verification_basis", "manuscript_use",
        "source_verification",
    }
    require(inventory and required_inventory <= set(inventory[0]), "inventory schema")
    require(len(inventory) >= 55, "manuscript bibliography must contain at least 55 records")
    require(all(all(row.get(field, "").strip() for field in required_inventory) for row in inventory), "empty inventory field")

    keys = [row["citation_key"] for row in inventory]
    titles = [normalized_title(row["title"]) for row in inventory]
    identifiers = [row["stable_identifier"] for row in inventory]
    require(len(set(keys)) == len(keys), "duplicate citation key")
    require(len(set(titles)) == len(titles), "duplicate normalized title")
    require(len(set(identifiers)) == len(identifiers), "duplicate stable identifier")
    require(all(value.startswith("https://") for value in identifiers), "non-HTTPS stable identifier")
    require(all("scholar.google" not in value and "/search" not in value for value in identifiers), "search result used as stable identifier")
    allowed_identifier_hosts = {
        "doi.org", "arxiv.org", "www.usenix.org", "eips.ethereum.org",
        "openreview.net", "proceedings.neurips.cc", "www.cs.cornell.edu",
        "datasets-benchmarks-proceedings.neurips.cc",
    }
    require(all(any(value.startswith(f"https://{host}/") for host in allowed_identifier_hosts) for value in identifiers), "unsupported stable identifier host")
    years = [int(row["year"]) for row in inventory]
    require(all(1900 <= year <= 2026 for year in years), "implausible bibliography year")

    record_type_counts = Counter(row["record_type"] for row in inventory)
    review_counts = Counter(row["peer_review_status"] for row in inventory)
    allowed_record_types = {
        "peer-reviewed publication", "scholarly preprint", "official specification record",
    }
    allowed_review_statuses = {"peer-reviewed", "not peer-reviewed", "not applicable"}
    require(set(record_type_counts) <= allowed_record_types, "unexpected reference record type")
    require(set(review_counts) <= allowed_review_statuses, "unexpected peer-review status")
    scholarly_records = sum(row["record_type"] != "official specification record" for row in inventory)
    peer_reviewed_records = sum(row["peer_review_status"] == "peer-reviewed" for row in inventory)
    require(scholarly_records >= 55, "fewer than 55 scholarly references")
    require(peer_reviewed_records >= 55, "fewer than 55 peer-reviewed references")
    require(record_type_counts["scholarly preprint"] == 1, "preprint count changed")
    require(record_type_counts["official specification record"] == 0, "non-scholarly specification in manuscript bibliography")
    require(all(re.fullmatch(r"2026-09-\d{2}", row["verification_date"]) for row in inventory), "invalid verification-date record")
    require(all(row["verification_basis"].strip() for row in inventory), "missing verification basis")
    by_key = {row["citation_key"]: row for row in inventory}
    require(
        by_key["huang2026semantictrap"]["title"]
        == "Do Fine-Tuned LLMs Understand Vulnerabilities? An Investigation into the Semantic Trap",
        "Semantic Trap title is not the current arXiv title",
    )
    require(
        by_key["huang2026semantictrap"]["peer_review_status"] == "not peer-reviewed",
        "arXiv-only Semantic Trap record is misclassified",
    )
    category_counts = Counter(row["category"] for row in inventory)
    required_categories = {
        "corpus", "detector", "repair", "transformation", "relational",
        "certificate", "semantics-and-assurance", "diagnostics",
    }
    require(set(category_counts) == required_categories, "unexpected bibliography category inventory")

    matrix_by_key = {row["citation_key"]: row for row in matrix}
    require(len(matrix_by_key) == len(matrix), "duplicate literature-matrix citation key")
    require(set(keys) <= set(matrix_by_key), "bibliography record absent from literature matrix")
    require(len(matrix) >= len(inventory), "incomplete literature matrix")
    require(all(row["status"] in {"complete", "claim-verified"} for row in matrix), "invalid reading status")

    def role_count(role: str) -> int:
        return sum(role in row["roles"].split(";") for row in matrix)

    role_counts = {
        "same-track": role_count("same-track"),
        "distinguished": role_count("distinguished"),
        "adjacent": role_count("adjacent"),
        "foundational": role_count("foundational"),
    }
    require(role_counts["same-track"] >= 12, "fewer than twelve same-track calibration papers")
    require(role_counts["distinguished"] >= 5, "fewer than five distinguished/high-visibility papers")
    require(role_counts["adjacent"] >= 5, "fewer than five adjacent top-venue papers")
    require(role_counts["foundational"] >= 3, "fewer than three foundational comparisons")

    resource_urls = {row["primary_url"] for row in resources}
    resource_titles = {normalized_title(row["resource_name"]) for row in resources}
    missing_resources = [
        row["citation_key"] for row in inventory
        if row["stable_identifier"] not in resource_urls
        and normalized_title(row["title"]) not in resource_titles
    ]
    require(not missing_resources, "bibliography records absent from external-resource ledger: " + ", ".join(missing_resources))

    if (tex_path is None) != (bib_path is None):
        raise LiteratureAuditError("--tex and --bib must be supplied together")
    manuscript_source = "supplied manuscript sources"
    if tex_path is None and bib_path is None:
        snapshot_root = artifact_root / "manuscript-records"
        tex_path = snapshot_root / "citations.tex"
        bib_path = snapshot_root / "references.bib"
        manuscript_source = "bundled manuscript-records snapshot"

    require(tex_path.is_file(), f"missing TeX source: {tex_path}")
    require(bib_path.is_file(), f"missing BibTeX source: {bib_path}")
    cited = tex_citations(tex_path)
    bibliography = bib_entries(bib_path)
    require(cited == set(keys), "TeX citation set differs from bibliography inventory")
    require(set(bibliography) == set(keys), "BibTeX key set differs from bibliography inventory")
    verify_bib_metadata(inventory, bibliography)
    manuscript = {
        "source": manuscript_source,
        "unique_citations": len(cited),
        "bib_entries": len(bibliography),
        "metadata_records_checked": len(bibliography),
        "uncited_entries": 0,
        "undefined_citations": 0,
    }

    return {
        "status": "consistent",
        "manuscript_reference_records": len(inventory),
        "calibration_works": len(matrix),
        "reading_statuses": dict(sorted(Counter(row["status"] for row in matrix).items())),
        "category_counts": dict(sorted(category_counts.items())),
        "reference_type_counts": dict(sorted(record_type_counts.items())),
        "peer_review_status_counts": dict(sorted(review_counts.items())),
        "scholarly_reference_records": scholarly_records,
        "peer_reviewed_reference_records": peer_reviewed_records,
        "verification_dates": sorted({row["verification_date"] for row in inventory}),
        "verification_mode": "offline closure against the recorded bibliographic inventory",
        "live_registry_queries_during_reproduction": 0,
        "offline_scope": (
            "cross-file metadata, status, stable-identifier, role, citation, and BibTeX consistency; "
            "not a live publisher or DOI-registry re-query"
        ),
        "calibration_role_counts": role_counts,
        "external_resources": len(resources),
        "manuscript_cross_check": manuscript,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--tex", type=Path)
    parser.add_argument("--bib", type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.artifact_root.resolve(), tex_path=args.tex, bib_path=args.bib), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
