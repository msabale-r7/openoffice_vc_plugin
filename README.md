Expected structure (Rapid7-style learning model)
openoffice_vc_plugin/
├── fetch_openoffice_advisory.py
├── generate_vc_plugin.py
├── models/
│   └── cve.py
├── data/
│   ├── raw/
│   │   └── openoffice_advisory.html
│   └── parsed/
│       ├── openoffice_vulns.json
│       └── cves/
│           └── CVE-XXXX-YYYY.json
├── Content/
│   └── OpenOffice/
│       ├── CVEs/
│       │   ├── CVE-XXXX-YYYY.xml
│       │   ├── CVE-XXXX-YYYY.vck
│       │   └── CVE-XXXX-YYYY.sol
│       └── product.vck
├── requirements.txt
└── README.md
👉 You must create Content/, and README.md manually or via script

Step 1: Setup
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
Step 2: Fetch advisory data
    python3 fetch_openoffice_advisory.py
Step 3: Validate & generate plugin content
    python3 generate_vc_plugin.py
Step 4: Verify output
    Content/OpenOffice/CVEs/
    Content/OpenOffice/product.vck

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 fetch_openoffice_advisory.py
