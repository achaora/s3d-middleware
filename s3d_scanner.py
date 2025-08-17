import json
import requests
import subprocess
from datetime import datetime, timezone, timedelta
from sbom_loader import load_and_strip_sbom

def utc_minus_4_iso() -> str:
    tz = timezone(timedelta(hours=-4))
    return datetime.now(tz).replace(microsecond=0).isoformat()

def get_osv_version() -> str:
    try:
        result = subprocess.run(
            ["osv-scanner", "--version"],
            capture_output=True, text=True, check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return "unknown"

sbom_file = "sample_sbom.spdx.json"
sbom_clean = "sbom_clean.spdx.json"
osv_version = get_osv_version()

# Preprocess SBOM (strip "sbom" wrapper)
cleaned_sbom_data = load_and_strip_sbom(sbom_file)
with open(sbom_clean, "w") as f:
    json.dump(cleaned_sbom_data, f, indent=2)

# Enumerate SBOM packages for reporting, including versionInfo and SPDXID
sbom_packages = []
for pkg in cleaned_sbom_data.get("packages", []):
    sbom_packages.append({
        "name": pkg["name"],
        "version": pkg.get("versionInfo", ""),
        "SPDXID": pkg.get("SPDXID", "")
    })
sbom_packages.sort(key=lambda x: x["name"].lower())

# 1. Run OSV Scanner
try:
    subprocess.run(
        [
            "osv-scanner",
            f"--sbom={sbom_clean}",
            "--json",
            "--output=osv_results.json"
        ],
        check=True,
        capture_output=True,
        text=True
    )
except subprocess.CalledProcessError as e:
    stdout_lines = e.stdout.strip().splitlines() if e.stdout else []
    stderr_lines = e.stderr.strip().splitlines() if e.stderr else []

    # Extract warnings from stdout
    warnings = [line for line in stdout_lines if "warn" in line.lower()]

    error_report = {
        "status": "error",
        "timestamp": utc_minus_4_iso(),
        "sbom_file": sbom_file,
        "osv_scanner_version": osv_version,
        "details": {
            "message": "osv-scanner failed",
            "returncode": e.returncode,
            "warnings": warnings,
            "stderr": stderr_lines,
            "total_packages": len(sbom_packages)
        },
        "results": [],
        "sbom_packages": sbom_packages
    }
    with open("final_report.json", "w") as f:
        json.dump(error_report, f, indent=2)
    print("❌ osv-scanner failed. See final_report.json for structured details including warnings.")
    exit(0)

# 2. Parse OSV output
with open("osv_results.json") as f:
    osv_data = json.load(f)

# 2a. Enumerate SBOM packages from OSV results, including SPDXID
sbom_packages = []
for result in osv_data.get("results", []):
    for pkg in result.get("packages", []):
        sbom_packages.append({
            "name": pkg["package"]["name"],
            "version": pkg["package"].get("versionInfo", ""),
            "SPDXID": pkg["package"].get("SPDXID", "")
        })
sbom_packages.sort(key=lambda x: x["name"].lower())

# 2b. Collect CVE IDs for EPSS
cve_ids = set()
for result in osv_data.get("results", []):
    for pkg in result.get("packages", []):
        for vuln in pkg.get("vulnerabilities", []):
            if vuln["id"].startswith("CVE-"):
                cve_ids.add(vuln["id"])

# 3. Query EPSS
epss_data = {}
if cve_ids:
    epss_url = "https://api.first.org/data/v1/epss"
    cve_list = ",".join(cve_ids)
    epss_resp = requests.get(f"{epss_url}?cve={cve_list}").json()
    epss_data = epss_resp.get("data", {})

# 4. Merge EPSS into results
final_results = []
for result in osv_data.get("results", []):
    for pkg in result.get("packages", []):
        for vuln in pkg.get("vulnerabilities", []):
            vid = vuln["id"]
            entry = {
                "package": pkg["package"]["name"],
                "version": pkg["package"].get("versionInfo", ""),
                "SPDXID": pkg["package"].get("SPDXID", ""),
                "id": vid,
                "summary": vuln.get("summary", ""),
                "fixed": vuln.get("fixed", []),
                "cvss": vuln.get("severity", []),
                "epss": epss_data.get(vid, {})
            }
            final_results.append(entry)

# 5. Save final report
if final_results:
    report = {
        "status": "ok",
        "timestamp": utc_minus_4_iso(),
        "sbom_file": sbom_file,
        "osv_scanner_version": osv_version,
        "details": {
            "message": f"Found {len(final_results)} vulnerabilities",
            "total_packages": len(sbom_packages)
        },
        "results": final_results,
        "sbom_packages": sbom_packages
    }
    print(f"✅ Found {len(final_results)} vulnerabilities. Report written to final_report.json")
else:
    report = {
        "status": "empty",
        "timestamp": utc_minus_4_iso(),
        "sbom_file": sbom_file,
        "osv_scanner_version": osv_version,
        "details": {
            "message": "No vulnerabilities found in the scanned SBOM.",
            "total_packages": len(sbom_packages)
        },
        "results": [],
        "sbom_packages": sbom_packages
    }
    print("✅ No vulnerabilities found. final_report.json contains a message.")

with open("final_report.json", "w") as f:
    json.dump(report, f, indent=2)