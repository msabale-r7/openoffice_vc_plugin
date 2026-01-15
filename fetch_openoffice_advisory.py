# ## Updated fetch_openoffice_advisory.p
import os
import json
import re
import requests
from time import sleep
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# -----------------------------
# Configuration
# -----------------------------
BASE_URL = "https://www.openoffice.org/security/bulletin.html"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; OpenOffice-VC-Plugin/1.0)"
}

DATA_DIR = "data"
RAW_DIR = os.path.join(DATA_DIR, "raw")
PARSED_DIR = os.path.join(DATA_DIR, "parsed")
CVES_DIR = os.path.join(PARSED_DIR, "cves")

# -----------------------------
# Utility functions
# -----------------------------
def ensure_directories():
    os.makedirs(RAW_DIR, exist_ok=True)
    os.makedirs(CVES_DIR, exist_ok=True)

def safe_filename(name: str) -> str:
    """Convert CVE IDs or titles into safe filenames."""
    name = name.replace("/", "_")
    name = re.sub(r"\s+", "_", name)
    name = re.sub(r"[^A-Za-z0-9_.-]", "", name)
    return name.strip("_")

def extract_cve_ids(text: str):
    """Extract CVE IDs from a string, e.g., 'CVE-2020-XXXX / CVE-2020-YYYY'"""
    return re.findall(r"CVE-\d{4}-\d+", text)

# -----------------------------
# Fetch advisory page
# -----------------------------
def fetch_advisory_index():
    print("[*] Fetching OpenOffice security bulletin...")
    response = requests.get(BASE_URL, headers=HEADERS, timeout=15)
    response.raise_for_status()

    html_path = os.path.join(RAW_DIR, "openoffice_advisory.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(response.text)

    print(f"[✓] Saved advisory HTML: {html_path}")
    return response.text

# -----------------------------
# Parse vulnerabilities
# -----------------------------
def parse_vulnerabilities(html):
    soup = BeautifulSoup(html, "lxml")
    vulns = []

    for header in soup.find_all("h3"):
        version = header.get_text(strip=True)
        ul = header.find_next_sibling("ul")
        if not ul:
            continue

        for li in ul.find_all("li"):
            a = li.find("a")
            if not a or not a.get("href"):
                continue

            cve_ids = extract_cve_ids(a.get_text(strip=True))
            cve_url = urljoin(BASE_URL, a["href"])
            summary = li.get_text(strip=True)

            for cve_id in cve_ids:
                vulns.append({
                    "cve_id": cve_id,
                    "version": version,
                    "summary": summary,
                    "link": cve_url
                })

    print(f"[✓] Parsed {len(vulns)} CVEs from bulletin")
    return vulns

# -----------------------------
# Fetch individual CVE pages
# -----------------------------
def fetch_and_save_cve(cve, retries=3):
    for attempt in range(1, retries + 1):
        try:
            response = requests.get(cve["link"], headers=HEADERS, timeout=15)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, "lxml")
            paragraphs = soup.select("#content p")

            description = " ".join(
                p.get_text(strip=True) for p in paragraphs
            )
            if not description:
                description = cve["summary"]

            data = {
                "cve_id": cve["cve_id"],
                "affected_version": cve["version"],
                "description": description,
                "source_url": cve["link"]
            }

            filename = safe_filename(cve["cve_id"]) + ".json"
            path = os.path.join(CVES_DIR, filename)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

            print(f"[✓] Saved CVE JSON: {filename}")
            sleep(0.7)
            return

        except requests.exceptions.RequestException as e:
            print(f"[!] Attempt {attempt}/{retries} failed for {cve['cve_id']} – {e}")
            sleep(2)

    print(f"[✗] Skipping CVE after retries: {cve['cve_id']}")

# -----------------------------
# Main
# -----------------------------
def main():
    ensure_directories()
    html = fetch_advisory_index()
    vulns = parse_vulnerabilities(html)

    # Save summary JSON
    summary_path = os.path.join(PARSED_DIR, "openoffice_vulns.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(vulns, f, indent=2)

    for cve in vulns:
        fetch_and_save_cve(cve)

    print("\n✅[✓] CVE fetch process completed!")


if __name__ == "__main__":
    main()

###########################################################################################################################







