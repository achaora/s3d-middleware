#!/usr/bin/env python3
import argparse
import csv
import json
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union
import requests

# Optional SBOMLoader
def try_import_sbom_loader():
    try:
        from sbom_loader import SBOMLoader  # type: ignore
        return SBOMLoader
    except Exception:
        return None

# -----------------------
# Time / misc helpers
# -----------------------
def utc_minus_4_iso() -> str:
    tz = timezone(timedelta(hours=-4))
    return datetime.now(tz).replace(microsecond=0).isoformat()

def get_osv_version() -> str:
    try:
        out = subprocess.run(
            ["osv-scanner", "--version"],
            capture_output=True, text=True
        )
        return (out.stdout or out.stderr or "").strip() or "unknown"
    except Exception:
        return "unknown"

# -----------------------
# OSV scan
# -----------------------
def run_osv_scan(sbom_path: str, output_path: str) -> Tuple[int, str, str]:
    proc = subprocess.run(
        ["osv-scanner", "scan", "--sbom", sbom_path, "--format", "json", "--output", output_path],
        capture_output=True, text=True
    )
    return proc.returncode, proc.stdout or "", proc.stderr or ""

# -----------------------
# Unwrap SBOM if needed
# -----------------------
def unwrap_sbom_if_needed(sbom_path: str) -> str:
    with open(sbom_path) as f:
        data = json.load(f)
    if "sbom" in data:
        unwrapped = data["sbom"]
        temp_path = "sbom_unwrapped.spdx.json"
        with open(temp_path, "w") as f2:
            json.dump(unwrapped, f2, indent=2)
        print(f"ℹ️  SBOM contained top-level 'sbom' key; unwrapped to {temp_path}")
        return temp_path
    return sbom_path

# -----------------------
# CVSS helpers
# -----------------------
_SEVERITY_MAP = {
    "CRITICAL": 9.5,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 3.1,
}

def _try_float(x: Any) -> Optional[float]:
    try:
        return float(x)
    except Exception:
        return None

def _extract_cvss_from_groups(groups: List[Dict[str, Any]]) -> Optional[float]:
    best = None
    for g in groups or []:
        v = _try_float(g.get("max_severity"))
        if v is not None:
            best = v if best is None else max(best, v)
    return best

def _extract_cvss_from_severity_entries(entries: List[Dict[str, Any]]) -> Optional[float]:
    best = None
    for ent in entries or []:
        score = ent.get("score")
        f = _try_float(score)
        if f is not None:
            best = f if best is None else max(best, f)
    return best

def _extract_cvss_from_database_specific(db_spec: Dict[str, Any]) -> Optional[float]:
    sev = (db_spec or {}).get("severity")
    if isinstance(sev, str):
        sev_up = sev.strip().upper()
        return _SEVERITY_MAP.get(sev_up)
    return None

def extract_cvss_base(vuln: Dict[str, Any], pkg_groups: List[Dict[str, Any]]) -> Optional[float]:
    cvss = _extract_cvss_from_groups(pkg_groups)
    if cvss is not None:
        return cvss
    cvss = _extract_cvss_from_severity_entries(vuln.get("severity", []))
    if cvss is not None:
        return cvss
    cvss = _extract_cvss_from_database_specific(vuln.get("database_specific", {}))
    return cvss

# -----------------------
# EPSS helpers
# -----------------------
def chunk_by_char_limit(items: Iterable[str], max_chars: int = 1800) -> Iterable[List[str]]:
    batch: List[str] = []
    size = 0
    for cve in items:
        add = len(cve) + (1 if batch else 0)
        if size + add > max_chars:
            if batch:
                yield batch
            batch = [cve]
            size = len(cve)
        else:
            batch.append(cve)
            size += add
    if batch:
        yield batch

def query_epss(cve_ids: Iterable[str], timeout: int = 30) -> Dict[str, Dict[str, Any]]:
    epss_map: Dict[str, Dict[str, Any]] = {}
    base = "https://api.first.org/data/v1/epss?cve="
    for batch in chunk_by_char_limit(sorted(set(cve_ids))):
        url = base + ",".join(batch)
        try:
            r = requests.get(url, timeout=timeout)
            r.raise_for_status()
            data = r.json().get("data", [])
            for row in data:
                cve = row.get("cve")
                if cve:
                    epss_map[cve] = {
                        "cve": cve,
                        "epss": _try_float(row.get("epss")) or 0.0,
                        "percentile": _try_float(row.get("percentile")) or 0.0,
                        "date": row.get("date"),
                    }
        except Exception:
            continue
    return epss_map

# -----------------------
# Prioritization
# -----------------------
def compute_prioritization(cvss: Optional[float], epss: Optional[float], s3d: Optional[float],
                           cvss_w: float, epss_w: float, s3d_w: float) -> float:
    # Normalize weights
    total = cvss_w + epss_w + s3d_w
    cvss_w, epss_w, s3d_w = cvss_w / total, epss_w / total, s3d_w / total
    cv = (cvss or 0.0) / 10.0
    ep = epss or 0.0
    s = s3d or 0.0
    return round(cv * cvss_w + ep * epss_w + s * s3d_w, 4)

def prioritization_product(cvss: Optional[float], epss: Optional[float]) -> Optional[float]:
    if cvss is None or epss is None:
        return None
    return round((cvss / 10.0) * epss, 4)

# -----------------------
# Parse OSV results
# -----------------------
def _extract_fixed_versions(vuln: Dict[str, Any]) -> List[str]:
    fixed = set()
    for aff in vuln.get("affected", []):
        for r in aff.get("ranges", []):
            for ev in r.get("events", []):
                fx = ev.get("fixed")
                if fx:
                    fixed.add(fx)
    return sorted(fixed)

def parse_osv_results(osv_json: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
    final_results: List[Dict[str, Any]] = []
    cve_ids: List[str] = []

    for res in osv_json.get("results", []):
        for pkg in res.get("packages", []):
            pinfo = pkg.get("package", {})
            pname = pinfo.get("name", "") or ""
            pver = pinfo.get("version", "") or ""
            ecos = pinfo.get("ecosystem", "") or ""
            groups = pkg.get("groups", []) or []

            for v in pkg.get("vulnerabilities", []):
                vid = v.get("id", "")
                aliases = v.get("aliases", []) or []

                candidate_cves: List[str] = []
                if vid.startswith("CVE-"):
                    candidate_cves.append(vid)
                candidate_cves += [a for a in aliases if isinstance(a, str) and a.startswith("CVE-")]
                cve_ids.extend(candidate_cves)

                cvss = extract_cvss_base(v, groups)

                final_results.append({
                    "package": pname,
                    "version": pver,
                    "ecosystem": ecos,
                    "id": vid,
                    "aliases": aliases,
                    "cves": candidate_cves,
                    "summary": v.get("summary", ""),
                    "cvss": cvss,
                    "epss": None,
                    "epss_percentile": None,
                    "s3d": 0.0,
                    "score_weighted": None,
                    "score_alt": None,
                    "fixed": _extract_fixed_versions(v),
                })

    return final_results, sorted(set(cve_ids))

# -----------------------
# S3D Model 2 fetch
# -----------------------
def fetch_s3d_model2_metrics(deps: List[Dict[str, Any]]) -> Dict[str, Dict[str, float]]:
    # Lazy import for FastAPI client
    from google.cloud import bigquery
    client = bigquery.Client()
    metrics: Dict[str, Dict[str, float]] = {}
    names = [d["package"] for d in deps]
    versions = [d["version"] for d in deps]

    # Query latest per name+version
    query = """
        WITH params AS (
            SELECT name, version
            FROM UNNEST(@names) AS name WITH OFFSET
            JOIN UNNEST(@versions) AS version WITH OFFSET USING(OFFSET)
        ),
        ranked AS (
            SELECT
                t.dependency_name,
                t.dependency_version,
                relative_distribution_name AS relative_distribution,
                percentile_rank_name AS percentile_rank,
                relative_distribution_version AS relative_distribution_version,
                percentile_rank_version AS percentile_rank_version,
                run_date,
                ROW_NUMBER() OVER (
                    PARTITION BY t.dependency_name, t.dependency_version
                    ORDER BY run_date DESC
                ) AS rn
            FROM `s3d_dura_data.s3d_model_2` t
            JOIN params p
            ON t.dependency_name = p.name AND t.dependency_version = p.version
        )
        SELECT *
        FROM ranked
        WHERE rn = 1
    """
    job = client.query(
        query,
        job_config=bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ArrayQueryParameter("names", "STRING", names),
                bigquery.ArrayQueryParameter("versions", "STRING", versions)
            ]
        ),
    )
    for row in job:
        key = f"{row['dependency_name']}@{row['dependency_version']}"
        metrics[key] = {
            "s3d": row.get("relative_distribution_version") or 0.0,
            "s3d_percentile": row.get("percentile_rank_version") or 0.0
        }
    return metrics

# -----------------------
# Save reports
# -----------------------
def save_json_report(path: str, report: Dict[str, Any]) -> None:
    with open(path, "w") as f:
        json.dump(report, f, indent=2)

def save_csv(results: List[Dict[str, Any]], path: str) -> None:
    fieldnames = [
        "package", "version", "ecosystem", "id", "aliases", "cves",
        "summary", "cvss", "epss", "epss_percentile", "s3d", "score_weighted", "score_alt", "fixed"
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "package": r.get("package", ""),
                "version": r.get("version", ""),
                "ecosystem": r.get("ecosystem", ""),
                "id": r.get("id", ""),
                "aliases": ",".join(r.get("aliases", [])),
                "cves": ",".join(r.get("cves", [])),
                "summary": r.get("summary", ""),
                "cvss": r.get("cvss"),
                "epss": r.get("epss"),
                "epss_percentile": r.get("epss_percentile"),
                "s3d": r.get("s3d"),
                "score_weighted": r.get("score_weighted"),
                "score_alt": r.get("score_alt"),
                "fixed": ",".join(r.get("fixed", [])),
            })

# -----------------------
# Main
# -----------------------
def main():
    parser = argparse.ArgumentParser(description="S3D Vulnerability Scanner with OSV + EPSS + S3D")
    parser.add_argument("--sbom", required=True, help="Path to SPDX JSON SBOM")
    parser.add_argument("--json", default="final_report.json", help="JSON report output path")
    parser.add_argument("--csv", nargs="?", const="final_report.csv", help="CSV report output path")
    parser.add_argument("--normalize", action="store_true", help="Normalize SBOM via SBOMLoader if available")
    parser.add_argument("--top", type=int, default=0, help="Print top N vulnerabilities for quick triage")
    parser.add_argument("--cvss-weight", type=float, default=0.75, help="Weight for CVSS (default=0.75)")
    parser.add_argument("--epss-weight", type=float, default=0.25, help="Weight for EPSS (default=0.25)")
    parser.add_argument("--s3d-weight", type=float, default=0.0, help="Weight for S3D (default=0.0)")
    args = parser.parse_args()

    sbom_path = args.sbom

    # Optional SBOM normalization
    if args.normalize:
        SBOMLoader = try_import_sbom_loader()
        if SBOMLoader:
            loader = SBOMLoader(sbom_path).load()
            sbom_dict = loader.get_data()
            sbom_path = "sbom_clean.spdx.json"
            with open(sbom_path, "w") as f:
                json.dump(sbom_dict, f, indent=2)
            print(f"ℹ️  SBOM normalized to {sbom_path}")

    # Automatic unwrap
    sbom_path = unwrap_sbom_if_needed(sbom_path)

    osv_results_path = "osv_results.json"
    code, so, se = run_osv_scan(sbom_path, osv_results_path)
    if code not in (0, 1):
        report = {
            "status": "error",
            "timestamp": utc_minus_4_iso(),
            "sbom_file": args.sbom,
            "sbom_used": sbom_path,
            "osv_scanner_version": get_osv_version(),
            "details": {
                "message": "osv-scanner failed to execute",
                "returncode": code,
                "stdout": so.splitlines()[-20:],
                "stderr": se.splitlines()[-20:]
            },
            "results": []
        }
        save_json_report(args.json, report)
        print("❌ osv-scanner execution failed; see JSON report for details.")
        return
    print(f"✅ osv-scanner completed (exit code {code}).")

    with open(osv_results_path) as f:
        osv_json = json.load(f)

    results, cve_ids = parse_osv_results(osv_json)

    # EPSS
    epss_map = query_epss(cve_ids)
    for r in results:
        primary_cve = r["cves"][0] if r.get("cves") else None
        if primary_cve and primary_cve in epss_map:
            r["epss"] = epss_map[primary_cve]["epss"]
            r["epss_percentile"] = epss_map[primary_cve]["percentile"]

    # S3D Model 2 integration
    s3d_metrics = fetch_s3d_model2_metrics(results)
    for r in results:
        key = f"{r['package']}@{r['version']}"
        r["s3d"] = s3d_metrics.get(key, {}).get("s3d", 0.0)

        # Weighted prioritization
        r["score_weighted"] = compute_prioritization(
            r.get("cvss"), r.get("epss"), r.get("s3d"),
            args.cvss_weight, args.epss_weight, args.s3d_weight
        )
        r["score_alt"] = prioritization_product(r.get("cvss"), r.get("epss"))

    results.sort(key=lambda x: (
        x["score_weighted"] if x["score_weighted"] is not None else -1,
        x["cvss"] if x["cvss"] is not None else -1,
        x["epss"] if x["epss"] is not None else -1,
    ), reverse=True)

    # Quick triage
    if args.top and results:
        print(f"\n🔍 Top {args.top} vulnerabilities by weighted score:")
        for i, r in enumerate(results[:args.top], start=1):
            print(f"{i}. {r['package']}@{r['version']} | ID: {r['id']} | "
                  f"CVSS: {r.get('cvss')} | EPSS: {r.get('epss')} | "
                  f"S3D: {r.get('s3d')} | Score: {r.get('score_weighted')} | "
                  f"Summary: {r.get('summary')[:80]}{'...' if len(r.get('summary',''))>80 else ''}")

    # Save reports
    report = {
        "status": "ok" if results else "empty",
        "timestamp": utc_minus_4_iso(),
        "sbom_file": args.sbom,
        "sbom_used": sbom_path,
        "osv_scanner_version": get_osv_version(),
        "details": {"message": f"Found {len(results)} vulnerabilities" if results else "No vulnerabilities found",
                    "unique_cves": len(cve_ids)},
        "results": results
    }
    save_json_report(args.json, report)
    if args.csv:
        csv_path = args.csv if isinstance(args.csv, str) else "final_report.csv"
        save_csv(results, csv_path)
        print(f"🧾 CSV saved to {csv_path}")
    print(f"📄 JSON saved to {args.json}")


if __name__ == "__main__":
    main()