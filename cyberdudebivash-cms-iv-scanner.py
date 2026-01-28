#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® Production Apps Suite
Tool: cyberdudebivash-cms-iv-scanner
Purpose: CVE-2025-15467 (OpenSSL CMS AuthEnvelopedData oversized IV) Scanner
Detects oversized Initialization Vector (IV) in AES-GCM AuthEnvelopedData structures
Version: 1.0.0 (Production Grade)

Copyright © 2026 CyberDudeBivash Pvt. Ltd. – Bhubaneswar, Odisha, India
Licensed under the CYBERDUDEBIVASH LICENSE – see LICENSE file for details
All rights reserved. Use only in accordance with the license terms.
"""

import sys
import argparse
from pathlib import Path
from asn1crypto.cms import ContentInfo

# ANSI Colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

# AES-GCM OIDs
GCM_OIDS = {
    '2.16.840.1.101.3.4.1.6',   # aes128-GCM
    '2.16.840.1.101.3.4.1.26',  # aes192-GCM
    '2.16.840.1.101.3.4.1.46',  # aes256-GCM
}

# Threshold: Normal GCM IV = 12 bytes. >32 bytes is highly suspicious
IV_THRESHOLD = 32

def is_vulnerable_cms(filepath: Path):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        content_info = ContentInfo.load(data)

        # Must be AuthEnvelopedData (OID 1.2.840.113549.1.9.16.1.23)
        if content_info['content_type'].dotted != '1.2.840.113549.1.9.16.1.23':
            return False, None, "Not AuthEnvelopedData"

        auth_env_data = content_info['content']

        eci = auth_env_data['encrypted_content_info']
        alg = eci['content_encryption_algorithm']
        alg_oid = alg['algorithm'].dotted

        if alg_oid not in GCM_OIDS:
            return False, None, f"Non-GCM algorithm: {alg_oid}"

        # Extract parameters (GCMParameters)
        params = alg['parameters']
        if not params:
            return False, None, "No parameters found"

        # Try to extract nonce/IV
        iv = None
        if hasattr(params, 'native'):
            native = params.native
            iv = native.get('nonce') or native.get('iv') or native.get('salt')

        if iv and len(iv) > IV_THRESHOLD:
            return True, len(iv), f"Oversized IV detected: {len(iv)} bytes"
        elif iv:
            return False, len(iv), f"Normal IV size: {len(iv)} bytes"
        else:
            return False, None, "No IV found in parameters"

    except Exception as e:
        return False, None, f"Parse error: {str(e)}"


def main():
    parser = argparse.ArgumentParser(
        description="CYBERDUDEBIVASH® CVE-2025-15467 CMS IV Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cyberdudebivash-cms-iv-scanner.py suspicious.p7m
  python cyberdudebivash-cms-iv-scanner.py --dir /path/to/attachments --recursive
        """
    )
    parser.add_argument("path", nargs="?", help="Single file to scan")
    parser.add_argument("--dir", help="Scan all files in directory")
    parser.add_argument("--recursive", "-r", action="store_true", help="Scan subdirectories")
    parser.add_argument("--threshold", type=int, default=IV_THRESHOLD, help=f"IV length threshold (default: {IV_THRESHOLD})")

    args = parser.parse_args()

    if not args.path and not args.dir:
        parser.print_help()
        sys.exit(1)

    vulnerable_files = []

    if args.path:
        files = [Path(args.path)]
    else:
        path = Path(args.dir)
        pattern = "**/*" if args.recursive else "*"
        files = list(path.glob(pattern))

    print(f"{BLUE}[*] CYBERDUDEBIVASH CMS IV Scanner v1.0.0{RESET}")
    print(f"[*] Scanning {len(files)} file(s)...\n")

    for file_path in files:
        if not file_path.is_file():
            continue

        vulnerable, iv_size, message = is_vulnerable_cms(file_path)

        if vulnerable:
            print(f"{RED}[VULNERABLE] {file_path}{RESET}")
            print(f"    IV Size: {iv_size} bytes")
            print(f"    {message}\n")
            vulnerable_files.append(str(file_path))
        else:
            print(f"{GREEN}[SAFE] {file_path}{RESET} → {message}")

    print(f"\n{BLUE}Scan Complete:{RESET}")
    print(f"   Vulnerable files: {len(vulnerable_files)}")
    if vulnerable_files:
        print(f"   {RED}Files to investigate:{RESET}")
        for f in vulnerable_files:
            print(f"     - {f}")

    sys.exit(0 if not vulnerable_files else 1)


if __name__ == "__main__":
    main()