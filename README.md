# cyberdudebivash-cms-iv-scanner

**CYBERDUDEBIVASH® Production Apps Suite Tool**  
**CVE-2025-15467 (OpenSSL CMS AuthEnvelopedData Oversized IV) Scanner**

Detects potentially exploitable oversized Initialization Vectors (IVs) in AES-GCM AuthEnvelopedData structures — a key indicator for CVE-2025-15467 stack buffer overflow vulnerability in OpenSSL.

**Version**: 1.0.0 (Production Grade)  
**Release Date**: January 28, 2026  
**Developed & Maintained by**: CYBERDUDEBIVASH®  
**Headquarters**: Bhubaneswar, Odisha, India  
**Copyright © 2026 CyberDudeBivash Pvt. Ltd.** – All Rights Reserved

## Overview

This lightweight, safe scanner parses CMS (PKCS#7 / S/MIME) files using pure ASN.1 decoding — **without invoking vulnerable OpenSSL code** — and checks for IV lengths exceeding safe thresholds in AuthEnvelopedData with AES-GCM ciphers.

**Primary use cases**:
- SOC triage of incoming email attachments / firmware updates
- Bulk scanning of mail gateways, file shares, or backup archives
- Threat hunting for CVE-2025-15467 exploitation attempts
- Pre-processing before feeding files into deeper malware analysis tools

**Key Features**:
- Zero false positives on normal 12–16 byte GCM IVs
- Recursive directory scanning support
- Color-coded console output
- Production-grade error handling & path validation
- No external dependencies beyond `asn1crypto`
- Fully compliant with CYBERDUDEBIVASH® security & branding standards

## Requirements

- Python 3.8+
- `asn1crypto>=1.5.1`

```bash
pip install -r requirements.txt
Installation & Quick Start
Bash# Clone or download from CYBERDUDEBIVASH GitHub
git clone https://github.com/cyberdudebivash/cyberdudebivash-cms-iv-scanner.git
cd cyberdudebivash-cms-iv-scanner

# Install dependencies
pip install asn1crypto

# Scan a single file
python cyberdudebivash-cms-iv-scanner.py suspicious.p7m

# Scan entire directory recursively
python cyberdudebivash-cms-iv-scanner.py --dir /path/to/attachments --recursive
Full Usage
textusage: cyberdudebivash-cms-iv-scanner.py [-h] [path] [--dir DIR] [--recursive] [--threshold THRESHOLD]

CYBERDUDEBIVASH® CVE-2025-15467 CMS IV Scanner

positional arguments:
  path                  Single file to scan

options:
  -h, --help            show this help message and exit
  --dir DIR             Scan all files in directory
  --recursive, -r       Scan subdirectories recursively
  --threshold THRESHOLD
                        IV length threshold in bytes (default: 32)
Examples
Bash# Single suspicious file
python cyberdudebivash-cms-iv-scanner.py malicious.cms

# Scan all files in current directory
python cyberdudebivash-cms-iv-scanner.py --dir .

# Recursive scan of email attachments folder
python cyberdudebivash-cms-iv-scanner.py --dir ~/Downloads/emails --recursive

# Custom threshold (very strict)
python cyberdudebivash-cms-iv-scanner.py --dir . --threshold 16
Output Legend

[VULNERABLE] → Red – Oversized IV detected (> threshold) → Immediate investigation required
[SAFE] → Green – Normal IV size or not applicable structure
Parse errors shown in plain text for debugging

Security Notes

This tool does NOT execute or decrypt any content — it only parses ASN.1 structure
Safe to run on untrusted files (no OpenSSL linkage)
Recommended to run in isolated environment / container for bulk scanning

License
Licensed under the CYBERDUDEBIVASH LICENSE (Version 1.0) — see the LICENSE file for full terms.
Summary: Internal use, modification, and integration permitted. Public redistribution of modified versions, commercial exploitation, or competitive use requires explicit written permission from CyberDudeBivash Pvt. Ltd.

Attribution Required:
Powered by CYBERDUDEBIVASH® – cyberdudebivash.github.io | © 2026 CyberDudeBivash Pvt. Ltd.
Deployment in CYBERDUDEBIVASH® Ecosystem
Recommended locations:


Contact & Support
For enterprise licensing, custom versions, integration support, or premium threat intelligence:

Email: iambivash@cyberdudebivash.com
Website: https://www.cyberdudebivash.com

CYBERDUDEBIVASH®
Global Cybersecurity Tools, Apps, Services, Automation & R&D Platform
Bhubaneswar, Odisha, India | © 2026 CyberDudeBivash Pvt. Ltd.
www.cyberdudebivash.com