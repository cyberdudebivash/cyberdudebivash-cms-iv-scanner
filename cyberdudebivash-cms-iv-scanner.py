#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® CMS IV Scanner
Enterprise / Research / CVE PoC Edition

Detects malformed or oversized IVs in CMS EnvelopedData
and AuthEnvelopedData structures.

Supported:
- AES-GCM (oversized nonce)
- AES-CBC (invalid IV length)
- Fuzzing detection (8–256 bytes)
- OpenSSL verification
- JSON reporting
- CVE PoC mode

© 2026 CyberDudeBivash Pvt. Ltd.
"""

import sys
import json
import argparse
import subprocess
from asn1crypto import cms

# ---------------------------------------------------------
# Defaults
# ---------------------------------------------------------

GCM_NORMAL_IV = 12
CBC_NORMAL_IV = 16
FUZZ_MIN = 8
FUZZ_MAX = 256

# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def openssl_verify(path):
    try:
        proc = subprocess.run(
            ["openssl", "cms", "-inform", "DER", "-in", path, "-cmsout"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        return proc.returncode == 0, proc.stderr.decode(errors="ignore")
    except Exception as e:
        return False, str(e)

def extract_iv(eci):
    alg = eci["content_encryption_algorithm"]
    params = alg["parameters"]

    if params is None:
        return None, None

    try:
        iv = params.native
    except Exception:
        return None, None

    alg_name = alg["algorithm"].native
    return alg_name, iv

# ---------------------------------------------------------
# Scanner Core
# ---------------------------------------------------------

def scan_file(path, args):
    findings = []

    try:
        with open(path, "rb") as f:
            data = cms.ContentInfo.load(f.read())
    except Exception as e:
        return [{"file": path, "error": f"Parse failed: {e}"}]

    content_type = data["content_type"].native

    if content_type == "enveloped_data":
        cms_obj = data["content"]
        eci = cms_obj["encrypted_content_info"]
        cms_label = "EnvelopedData"

    elif content_type == "auth_enveloped_data":
        cms_obj = data["content"]
        eci = cms_obj["auth_encrypted_content_info"]
        cms_label = "AuthEnvelopedData"

    else:
        return []

    alg_name, iv = extract_iv(eci)

    if not iv or not isinstance(iv, (bytes, bytearray)):
        return []

    iv_len = len(iv)
    issue = None

    # AES-GCM
    if "gcm" in alg_name:
        if iv_len != GCM_NORMAL_IV:
            issue = f"Oversized GCM IV ({iv_len} bytes)"

    # AES-CBC
    if "cbc" in alg_name:
        if iv_len != CBC_NORMAL_IV:
            issue = f"Invalid CBC IV length ({iv_len} bytes)"

    # Fuzzing range
    if args.fuzz and FUZZ_MIN <= iv_len <= FUZZ_MAX:
        issue = f"Fuzzed IV length ({iv_len} bytes)"

    if issue:
        finding = {
            "file": path,
            "cms_type": cms_label,
            "algorithm": alg_name,
            "iv_length": iv_len,
            "issue": issue
        }

        if args.openssl:
            ok, msg = openssl_verify(path)
            finding["openssl_parsed"] = ok
            finding["openssl_error"] = msg.strip()

        findings.append(finding)

    return findings

# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="CYBERDUDEBIVASH CMS IV Scanner (Enterprise Edition)"
    )
    parser.add_argument("files", nargs="+", help="CMS files to scan")
    parser.add_argument("--json", help="Write JSON report to file")
    parser.add_argument("--openssl", action="store_true", help="Verify using OpenSSL")
    parser.add_argument("--fuzz", action="store_true", help="Enable IV fuzzing detection")
    parser.add_argument("--poc", action="store_true", help="CVE-ready PoC output")

    args = parser.parse_args()

    all_findings = []

    print("[*] CYBERDUDEBIVASH CMS IV Scanner v2.0")
    print(f"[*] Scanning {len(args.files)} file(s)...\n")

    for f in args.files:
        results = scan_file(f, args)
        for r in results:
            all_findings.append(r)

            if args.poc:
                print(f"[VULNERABLE] {r['file']}")
                print(f"  CMS Type : {r['cms_type']}")
                print(f"  Algo     : {r['algorithm']}")
                print(f"  IV Size  : {r['iv_length']}")
                print(f"  Issue    : {r['issue']}")
                print()
            else:
                print(f"[VULNERABLE] {r['file']} → {r['issue']}")

    if not all_findings:
        print("[SAFE] No vulnerable CMS IVs detected")

    if args.json:
        with open(args.json, "w") as jf:
            json.dump(all_findings, jf, indent=2)
        print(f"\n[+] JSON report written to {args.json}")

    print("\nScan Complete:")
    print(f"   Vulnerable files: {len(all_findings)}")

if __name__ == "__main__":
    main()
