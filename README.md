# Apache OpenOffice VC Plugin Generation

## Overview

This project demonstrates the **generation of VC plugins** for a selected product (Apache OpenOffice) as part of Rapid7’s content creation workflow.  
The goal is to **fetch advisories, validate them using Pydantic models, and generate content files (.xml, .vck, .sol)** following Rapid7 standards.  

This approach helps gain **hands-on experience with Nexpose architecture** and understanding its components, rather than directly diving into the Nexpose codebase.

---

## Task Objectives

1. **Select a product** covered by Rapid7  
   - For this project: **Apache OpenOffice**

2. **Fetch product advisory data**  
   - Data is extracted from the official Apache OpenOffice security bulletin page  
   - Data is stored locally in `.html` and `.json` formats

3. **Data Validation using Pydantic**  
   - Transform the advisory data into **Pydantic objects**  
   - Validate all fields to ensure consistent structure and correctness

4. **Generate VC Plugin Files**  
   - From the validated Pydantic objects, generate **three content files per CVE**:  
     - `.xml` – XML representation of the advisory  
     - `.vck` – VC plugin file  
     - `.sol` – Solution file  
   - Follow **Rapid7 standards** for file structure and naming

5. **Organize content files**  
   - All generated files are stored locally under the `Content/Apache_OpenOffice` directory  
   - Each CVE gets a separate set of `.xml`, `.vck`, and `.sol` files

---


## Project Structure

openoffice_vc_plugin/
│
├── Content/
│   └── Apache_OpenOffice/
│       ├── CVE-XXXX-XXXX.xml
│       ├── CVE-XXXX-XXXX.vck
│       └── CVE-XXXX-XXXX.sol
│
├── data/
│   ├── raw/
│   │   └── openoffice_advisory.html
│   └── parsed/
│       └── openoffice_advisory.json
│
├── scripts/
│   ├── fetch_openoffice_advisory.py
│   └── generate_vc_plugin.py
│
├── requirements.txt
└── README.md

