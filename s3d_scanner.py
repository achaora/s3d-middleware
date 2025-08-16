import json
import requests
import subprocess

# 1. Run OSV Scanner
subprocess.run([
    "osv-scanner",
    "--lockfile=package-lock.json",
    "--json",
    "--output=osv_results.json"
])

# 2. Parse OSV output
with open("osv_results.json") as f:
    osv_data = json.load(f)

cve_ids = set()
for result in osv_data.get("results", []):
    for pkg in result.get("packages", []):
        for vuln in pkg.get("vulnerabilities", []):
            if vuln["id"].startswith("CVE-"):
                cve_ids.add(vuln["id"])

# 3. Query EPSS
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
                "version": pkg["package"]["version"],
                "id": vid,
                "summary": vuln.get("summary", ""),
                "fixed": vuln.get("fixed", []),
                "cvss": vuln.get("severity", []),
                "epss": epss_data.get(vid, {})
            }
            final_results.append(entry)

# 5. Save final report
with open("final_report.json", "w") as f:
    json.dump(final_results, f, indent=2)