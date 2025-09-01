#!/usr/bin/env python3
import argparse
import csv
import json
import subprocess
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

import requests

# --------------------------
# Optional SBOM normalization
# --------------------------
def try_import_sbom_loader():
    try:
        from sbom_loader import SBOMLoader  # type: ignore
        return SBOMLoader
    except Exception:
        return None

# --------------------------
# Time / misc helpers
# --------------------------
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

# --------------------------
# OSV scan
# --------------------------
def run_osv_scan(sbom_path: str, output_path: str) -> Tuple[int, str, str]:
    proc = subprocess.run(
        ["osv-scanner", "scan", "--sbom", sbom_path, "--format", "json", "--output", output_path],
        capture_output=True, text=True
    )
    return proc.returncode, proc.stdout or "", proc.stderr or ""

# --------------------------
# Unwrap "sbom" key if present
# --------------------------
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

# --------------------------
# CVSS helpers
# --------------------------
_SEVERITY_MAP = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.1}

def _try_float(x: Any) -> Optional[float]:
    try: return float(x)
    except Exception: return None

def _extract_cvss_from_groups(groups: List[Dict[str, Any]]) -> Optional[float]:
    best = None
    for g in groups or []:
        v = _try_float(g.get("max_severity"))
        if v is not None: best = v if best is None else max(best, v)
    return best

def _extract_cvss_from_severity_entries(entries: List[Dict[str, Any]]) -> Optional[float]:
    best = None
    for ent in entries or []:
        score = ent.get("score")
        f = _try_float(score)
        if f is not None: best = f if best is None else max(best, f)
    return best

def _extract_cvss_from_database_specific(db_spec: Dict[str, Any]) -> Optional[float]:
    sev = (db_spec or {}).get("severity")
    if isinstance(sev, str):
        return _SEVERITY_MAP.get(sev.strip().upper())
    return None

def extract_cvss_base(vuln: Dict[str, Any], pkg_groups: List[Dict[str, Any]]) -> Optional[float]:
    cvss = _extract_cvss_from_groups(pkg_groups)
    if cvss is not None: return cvss
    cvss = _extract_cvss_from_severity_entries(vuln.get("severity", []))
    if cvss is not None: return cvss
    return _extract_cvss_from_database_specific(vuln.get("database_specific", {}))

# --------------------------
# EPSS helpers
# --------------------------
def chunk_by_char_limit(items: Iterable[str], max_chars: int = 1800) -> Iterable[List[str]]:
    batch: List[str] = []
    size = 0
    for cve in items:
        add = len(cve) + (1 if batch else 0)
        if size + add > max_chars:
            if batch: yield batch
            batch = [cve]; size = len(cve)
        else:
            batch.append(cve); size += add
    if batch: yield batch

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
        except Exception: continue
    return epss_map

# --------------------------
# Prioritization
# --------------------------
def compute_prioritization(cvss: Optional[float], epss: Optional[float], s3d: Optional[float],
                           cvss_weight: float, epss_weight: float, s3d_weight: float) -> Optional[float]:
    total = cvss_weight + epss_weight + s3d_weight
    if total == 0: return None
    cvss_norm = (cvss or 0.0) * cvss_weight / total
    epss_norm = (epss or 0.0) * epss_weight / total
    s3d_norm = (s3d or 0.0) * s3d_weight / total
    return round(cvss_norm + epss_norm + s3d_norm, 4)

def prioritization_product(cvss: Optional[float], epss: Optional[float]) -> Optional[float]:
    if cvss is None or epss is None: return None
    return round((cvss / 10.0) * epss, 4)

# --------------------------
# Parse OSV results
# --------------------------
def _extract_fixed_versions(vuln: Dict[str, Any]) -> List[str]:
    fixed = set()
    for aff in vuln.get("affected", []):
        for r in aff.get("ranges", []):
            for ev in r.get("events", []):
                fx = ev.get("fixed")
                if fx: fixed.add(fx)
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
                if vid.startswith("CVE-"): candidate_cves.append(vid)
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
                    "s3d": None,
                    "s3d_percentile": None,
                    "score_weighted": None,
                    "score_alt": None,
                    "fixed": _extract_fixed_versions(v),
                })
    return final_results, sorted(set(cve_ids))

# --------------------------
# Reporting
# --------------------------
def save_json_report(path: str, report: Dict[str, Any]) -> None:
    with open(path, "w") as f: json.dump(report, f, indent=2)

def save_csv(results: List[Dict[str, Any]], path: str) -> None:
    fieldnames = ["package","version","ecosystem","id","cves","summary",
                  "cvss","epss","epss_percentile","s3d","s3d_percentile",
                  "score_weighted","score_alt","fixed"]
    with open(path,"w",newline="") as f:
        writer = csv.DictWriter(f,fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "package": r.get("package",""),
                "version": r.get("version",""),
                "ecosystem": r.get("ecosystem",""),
                "id": r.get("id",""),
                "cves": ",".join(r.get("cves",[])),
                "summary": r.get("summary",""),
                "cvss": r.get("cvss"),
                "epss": r.get("epss"),
                "epss_percentile": r.get("epss_percentile"),
                "s3d": r.get("s3d"),
                "s3d_percentile": r.get("s3d_percentile"),
                "score_weighted": r.get("score_weighted"),
                "score_alt": r.get("score_alt"),
                "fixed": ",".join(r.get("fixed",[])),
            })

# --------------------------
# S3D API fetch with retry
# --------------------------
def fetch_s3d_metrics_api(
    deps: List[Dict[str, Any]],
    api_url: str = "https://s3d-models-api-973562431566.us-east5.run.app/s3d_model_2/metrics",
    max_retries: int = 3,
    backoff: float = 2.0
) -> Dict[str, Dict[str, float]]:
    metrics: Dict[str, Dict[str, float]] = {}
    if not deps: return metrics
    names = [d["package"] for d in deps]
    versions = [d["version"] for d in deps]
    payload = {"dependency_names": names, "dependency_versions": versions}
    attempt = 0
    while attempt < max_retries:
        try:
            r = requests.get(api_url, params=payload, timeout=30)
            r.raise_for_status()
            data = r.json()
            for entry in data:
                key = f"{entry['dependency_name']}@{entry.get('dependency_version') or ''}"
                metrics[key] = {
                    "s3d": entry.get("relative_distribution_version") or 0.0,
                    "s3d_percentile": entry.get("percentile_rank_version") or 0.0
                }
            return metrics
        except requests.RequestException as e:
            attempt += 1
            wait_time = backoff ** attempt
            print(f"⚠️ Attempt {attempt}/{max_retries} failed for S3D API: {e}. Retrying in {wait_time:.1f}s...")
            time.sleep(wait_time)
        except ValueError as e:
            print(f"⚠️ Invalid JSON from S3D API: {e}. Returning empty metrics.")
            return metrics
    print("⚠️ Failed to fetch S3D metrics after retries. Returning empty metrics.")
    return metrics

# --------------------------
# Main
# --------------------------
def main():
    parser = argparse.ArgumentParser(description="Scan SPDX SBOM with OSV + EPSS + S3D metrics, export JSON/CSV")
    parser.add_argument("--sbom", required=True, help="Path to SPDX JSON SBOM (e.g., *.spdx.json)")
    parser.add_argument("--json", default="final_report.json", help="JSON report output path")
    parser.add_argument("--csv", nargs="?", const="final_report.csv", help="CSV report output path")
    parser.add_argument("--normalize", action="store_true", help="Normalize SBOM via SBOMLoader if available")
    parser.add_argument("--top", type=int, default=0, help="Print top N vulnerabilities by weighted score")
    parser.add_argument("--cvss-weight", type=float, default=0.75, help="Weight for CVSS in weighted score")
    parser.add_argument("--epss-weight", type=float, default=0.25, help="Weight for EPSS in weighted score")
    parser.add_argument("--s3d-weight", type=float, default=0.0, help="Weight for S3D metric in weighted score")
    parser.add_argument("--s3d-api", default="https://s3d-models-api-973562431566.us-east5.run.app/s3d_model_2/metrics", help="S3D API URL")
    args = parser.parse_args()

    sbom_path = args.sbom

    # Optional normalization
    if args.normalize:
        SBOMLoader = try_import_sbom_loader()
        if SBOMLoader:
            loader = SBOMLoader(sbom_path).load()
            sbom_dict = loader.get_data()
            sbom_path = "sbom_clean.spdx.json"
            with open(sbom_path, "w") as f: json.dump(sbom_dict, f, indent=2)
            print(f"ℹ️ SBOM normalized to {sbom_path}")

    # Automatic unwrap "sbom" key if present
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
            "details": {"message": "osv-scanner failed", "returncode": code, "stdout": so, "stderr": se},
            "results": []
        }
        save_json_report(args.json, report)
        print("❌ osv-scanner failed; see JSON report.")
        return
    print(f"✅ osv-scanner completed (exit code {code})")

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
        else:
            r["epss"] = None
            r["epss_percentile"] = None

    # S3D metrics
    s3d_map = fetch_s3d_metrics_api(results, api_url=args.s3d_api)
    for r in results:
        key = f"{r['package']}@{r['version'] or ''}"
        if key in s3d_map:
            r["s3d"] = s3d_map[key]["s3d"]
            r["s3d_percentile"] = s3d_map[key]["s3d_percentile"]
        else:
            r["s3d"] = 0.0
            r["s3d_percentile"] = 0.0

        # Compute weighted score
        r["score_weighted"] = compute_prioritization(
            r.get("cvss"),
            r.get("epss"),
            r.get("s3d"),
            args.cvss_weight,
            args.epss_weight,
            args.s3d_weight
        )
        r["score_alt"] = prioritization_product(r.get("cvss"), r.get("epss"))

    # Sort results by weighted score
    results.sort(key=lambda x: (x["score_weighted"] or -1, x["cvss"] or -1, x["epss"] or -1), reverse=True)

    # Quick triage printout
    if args.top and results:
        print(f"\n🔍 Top {args.top} vulnerabilities by weighted score:")
        for i, r in enumerate(results[:args.top], start=1):
            print(f"{i}. {r['package']}@{r['version']} | ID: {r['id']} | "
                  f"CVSS: {r.get('cvss')} | EPSS: {r.get('epss')} | S3D: {r.get('s3d')} | "
                  f"Score: {r.get('score_weighted')} | Summary: {r.get('summary')[:80]}{'...' if len(r.get('summary',''))>80 else ''}")

    status = "ok" if results else "empty"
    message = f"Found {len(results)} vulnerabilities" if results else "No vulnerabilities found."

    report = {
        "status": status,
        "timestamp": utc_minus_4_iso(),
        "sbom_file": args.sbom,
        "sbom_used": sbom_path,
        "osv_scanner_version": get_osv_version(),
        "details": {"message": message, "unique_cves": len(cve_ids)},
        "results": results
    }

    save_json_report(args.json, report)
    if args.csv:
        csv_path = args.csv if isinstance(args.csv, str) else "final_report.csv"
        save_csv(results, csv_path)

    print(f"📄 JSON saved to {args.json}")
    if args.csv: print(f"🧾 CSV saved to {csv_path}")

if __name__ == "__main__":
    main()