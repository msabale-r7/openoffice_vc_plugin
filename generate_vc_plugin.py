## Updated generate_vc_plugin.py
import os
import re
import json
from pathlib import Path
from time import sleep
from datetime import datetime
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from pydantic import BaseModel, Field, HttpUrl
import xml.etree.ElementTree as ET
from typing import Optional

# -----------------------------
# Configuration
# -----------------------------
PRODUCT_NAME = "OpenOffice"

# Data directories
DATA_DIR = Path("data")
RAW_DIR = DATA_DIR / "raw"
PARSED_DIR = DATA_DIR / "parsed"
CVES_DIR = PARSED_DIR / "cves"

# Content directories
CONTENT_ROOT = Path(f"Content/{PRODUCT_NAME}")
CVES_CONTENT_DIR = CONTENT_ROOT / "CVEs"

# Create directories
for d in [RAW_DIR, CVES_DIR, CVES_CONTENT_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Advisory URL
BASE_URL = "https://www.openoffice.org/security/bulletin.html"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; OpenOffice-VC-Plugin/1.0)"
}

# -----------------------------
# Pydantic CVE model
# -----------------------------
class CVE(BaseModel):
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d+$")
    affected_version: str
    description: str
    source_url: Optional[HttpUrl]

# -----------------------------
# Helper functions
# -----------------------------
def safe_filename(name: str) -> str:
    """Convert CVE ID or title into safe filename."""
    name = name.replace("/", "_")
    name = re.sub(r"\s+", "_", name)
    name = re.sub(r"[^A-Za-z0-9_.-]", "", name)
    return name.strip("_")

def write_xml(path: Path, root: ET.Element):
    tree = ET.ElementTree(root)
    tree.write(path, encoding="utf-8", xml_declaration=True)
    print(f"[✓] Saved {path.name}")

def extract_cve_ids(text: str):
    return re.findall(r"CVE-\d{4}-\d+", text)

# -----------------------------
# Fetch advisory page
# -----------------------------
def fetch_advisory_index():
    print("[*] Fetching OpenOffice security bulletin...")
    response = requests.get(BASE_URL, headers=HEADERS, timeout=15)
    response.raise_for_status()

    html_path = RAW_DIR / "openoffice_advisory.html"
    html_content = response.text
    html_path.write_text(html_content, encoding="utf-8")
    print(f"[✓] Saved advisory HTML: {html_path}")
    return html_content

# -----------------------------
# Parse CVEs
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
# Fetch and save individual CVE JSON
# -----------------------------
def fetch_and_save_cve_json(cve, retries=3):
    for attempt in range(1, retries + 1):
        try:
            response = requests.get(cve["link"], headers=HEADERS, timeout=15)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, "lxml")
            paragraphs = soup.select("#content p")
            description = " ".join(p.get_text(strip=True) for p in paragraphs)
            if not description:
                description = cve["summary"]

            data = {
                "cve_id": cve["cve_id"],
                "affected_version": cve["version"],
                "description": description,
                "source_url": cve["link"]
            }

            filename = safe_filename(cve["cve_id"]) + ".json"
            path = CVES_DIR / filename
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            print(f"[✓] Saved CVE JSON: {filename}")
            sleep(0.5)
            return path

        except requests.exceptions.RequestException as e:
            print(f"[!] Attempt {attempt}/{retries} failed for {cve['cve_id']} – {e}")
            sleep(2)

    print(f"[✗] Skipping CVE after retries: {cve['cve_id']}")
    return None

# -----------------------------
# Generate VC plugin files for each CVE
# -----------------------------
def generate_cve_content(cve_json_path: Path):
    try:
        data = json.loads(cve_json_path.read_text(encoding="utf-8"))
        cve_obj = CVE(
            cve_id=data.get("cve_id", "UNKNOWN"),
            affected_version=data.get("affected_version", "UNKNOWN"),
            description=data.get("description", "No description available"),
            source_url=data.get("source_url")
        )
    except Exception as e:
        print(f"[✗] Skipping invalid CVE JSON {cve_json_path.name}: {e}")
        return None

    # XML
    xml_root = ET.Element("VULNERABILITY")
    ET.SubElement(xml_root, "ID").text = cve_obj.cve_id
    ET.SubElement(xml_root, "PRODUCT").text = PRODUCT_NAME
    ET.SubElement(xml_root, "AFFECTED_VERSION").text = cve_obj.affected_version
    ET.SubElement(xml_root, "DESCRIPTION").text = cve_obj.description
    ET.SubElement(xml_root, "REFERENCE").text = str(cve_obj.source_url) if cve_obj.source_url else ""
    write_xml(CVES_CONTENT_DIR / f"{cve_obj.cve_id}.xml", xml_root)

    # SOL
    sol_root = ET.Element("SOLUTION")
    ET.SubElement(sol_root, "CVE").text = cve_obj.cve_id
    ET.SubElement(sol_root, "FIX").text = f"Upgrade to the latest supported {PRODUCT_NAME} version."
    write_xml(CVES_CONTENT_DIR / f"{cve_obj.cve_id}.sol", sol_root)

    # VCK per CVE
    vck_root = ET.Element("VC_PLUGIN_ENTRY")
    ET.SubElement(vck_root, "ID").text = cve_obj.cve_id
    ET.SubElement(vck_root, "PRODUCT").text = PRODUCT_NAME
    ET.SubElement(vck_root, "AFFECTED_VERSION").text = cve_obj.affected_version
    ET.SubElement(vck_root, "DESCRIPTION").text = cve_obj.description
    ET.SubElement(vck_root, "REFERENCE").text = str(cve_obj.source_url) if cve_obj.source_url else ""
    ET.SubElement(vck_root, "GENERATED_AT").text = datetime.utcnow().isoformat() + "Z"
    write_xml(CVES_CONTENT_DIR / f"{cve_obj.cve_id}.vck", vck_root)

    return cve_obj

# -----------------------------
# Generate product-level VCK
# -----------------------------
def generate_product_vck(all_cves):
    vck_root = ET.Element("VC_PLUGIN")
    ET.SubElement(vck_root, "PRODUCT").text = PRODUCT_NAME
    ET.SubElement(vck_root, "VERSION").text = "1.0"
    ET.SubElement(vck_root, "GENERATED_AT").text = datetime.utcnow().isoformat() + "Z"
    ET.SubElement(vck_root, "TOTAL_CVES").text = str(len(all_cves))
    write_xml(CONTENT_ROOT / "product.vck", vck_root)

# -----------------------------
# Main
# -----------------------------
def main():
    html = fetch_advisory_index()
    vulns = parse_vulnerabilities(html)

    validated_cves = []

    for cve in vulns:
        cve_json_path = fetch_and_save_cve_json(cve)
        if cve_json_path:
            cve_obj = generate_cve_content(cve_json_path)
            if cve_obj:
                validated_cves.append(cve_obj)

    generate_product_vck(validated_cves)
    print("\n✅[✓] VC plugin generation completed for all CVEs!")

if __name__ == "__main__":
    main()

