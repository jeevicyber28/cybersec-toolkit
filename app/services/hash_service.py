import hashlib
import re
from typing import Dict, Any, List, Optional

def generate_hashes(data: bytes) -> Dict[str, str]:
    """
    Computes cryptographic checksums for raw byte payload.
    Supports MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-256, and BLAKE2b.
    """
    return {
        'md5': hashlib.md5(data).hexdigest(),
        'sha1': hashlib.sha1(data).hexdigest(),
        'sha224': hashlib.sha224(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest(),
        'sha384': hashlib.sha384(data).hexdigest(),
        'sha512': hashlib.sha512(data).hexdigest(),
        'sha3_256': hashlib.sha3_256(data).hexdigest(),
        'blake2b': hashlib.blake2b(data).hexdigest()
    }

def identify_hash(raw_hash: str) -> List[Dict[str, Any]]:
    """
    Analyzes an unknown hash string and infers possible cryptographic algorithms,
    bit lengths, and collision/security postures.
    """
    h = raw_hash.strip().lower()
    matches: List[Dict[str, Any]] = []

    # Signature-based prefixes
    if h.startswith(('$2a$', '$2b$', '$2y$', '$2x$')):
        return [{
            'algorithm': 'bcrypt (Blowfish-based KDF)',
            'category': 'Adaptive Password Hash',
            'length_bits': 184,
            'security_level': 'High (Recommended for Password Storage)',
            'status_class': 'success',
            'notes': 'Resistant to GPU brute-force attacks via configurable work factor.'
        }]

    if h.startswith('$argon2'):
        return [{
            'algorithm': 'Argon2 (Password Hashing Winner)',
            'category': 'Memory-Hard KDF',
            'length_bits': 'Variable',
            'security_level': 'Maximum (State-of-the-Art)',
            'status_class': 'success',
            'notes': 'Memory-hard algorithm immune to specialized ASIC/GPU cracking clusters.'
        }]

    if h.startswith('$6$'):
        return [{
            'algorithm': 'SHA-512 Crypt (Unix)',
            'category': 'Operating System Password Hash',
            'length_bits': 512,
            'security_level': 'Good',
            'status_class': 'success',
            'notes': 'Commonly used in modern Linux /etc/shadow files with salt and rounds.'
        }]

    if h.startswith('$5$'):
        return [{
            'algorithm': 'SHA-256 Crypt (Unix)',
            'category': 'Operating System Password Hash',
            'length_bits': 256,
            'security_level': 'Good',
            'status_class': 'info',
            'notes': 'Linux standard /etc/shadow hash format.'
        }]

    if h.startswith('$1$'):
        return [{
            'algorithm': 'MD5 Crypt (Unix)',
            'category': 'Legacy Password Hash',
            'length_bits': 128,
            'security_level': 'Insecure / Obsolete',
            'status_class': 'danger',
            'notes': 'Legacy format from 1990s. Vulnerable to fast GPU cracking.'
        }]

    # Pure Hex length matching
    is_hex = bool(re.fullmatch(r'^[0-9a-fA-F]+$', h))
    length = len(h)

    if not is_hex:
        return [{
            'algorithm': 'Unrecognized Format',
            'category': 'Unknown',
            'length_bits': length * 8,
            'security_level': 'Non-Hex Pattern',
            'status_class': 'warning',
            'notes': 'Input contains non-hexadecimal characters. Ensure input is raw hex digest or standard hash crypt format.'
        }]

    if length == 32:
        matches.append({
            'algorithm': 'MD5 (Message Digest 5)',
            'category': 'Cryptographic Hash',
            'length_bits': 128,
            'security_level': 'Broken (Vulnerable to Collisions)',
            'status_class': 'danger',
            'notes': 'Collisions can be generated in seconds. Do NOT use for digital signatures or passwords.'
        })
        matches.append({
            'algorithm': 'NTLM (Windows NT LAN Manager)',
            'category': 'Authentication Hash',
            'length_bits': 128,
            'security_level': 'Vulnerable (Pass-the-Hash Risk)',
            'status_class': 'danger',
            'notes': 'Unsalted MD4 digest of UTF-16 password. Vulnerable to fast rainbow tables.'
        })
        matches.append({
            'algorithm': 'MD4',
            'category': 'Cryptographic Hash',
            'length_bits': 128,
            'security_level': 'Severely Broken',
            'status_class': 'danger',
            'notes': 'Predecessor to MD5. Cryptographically compromised.'
        })

    elif length == 40:
        matches.append({
            'algorithm': 'SHA-1 (Secure Hash Algorithm 1)',
            'category': 'Cryptographic Hash',
            'length_bits': 160,
            'security_level': 'Weak / Deprecated (SHAttered Collision)',
            'status_class': 'warning',
            'notes': 'Practical collision demonstrated by Google (SHAttered). Deprecated by NIST.'
        })
        matches.append({
            'algorithm': 'RIPEMD-160',
            'category': 'Cryptographic Hash',
            'length_bits': 160,
            'security_level': 'Moderate (Used in Bitcoin addresses)',
            'status_class': 'info',
            'notes': 'Often paired with SHA-256 for Bitcoin address generation.'
        })
        matches.append({
            'algorithm': 'MySQL 5.x / 8.x PASSWORD()',
            'category': 'Database Hash',
            'length_bits': 160,
            'security_level': 'Legacy Double-SHA1',
            'status_class': 'warning',
            'notes': 'Computed as SHA1(SHA1(password)).'
        })

    elif length == 56:
        matches.append({
            'algorithm': 'SHA-224',
            'category': 'SHA-2 Family',
            'length_bits': 224,
            'security_level': 'Strong',
            'status_class': 'success',
            'notes': 'Truncated 32-bit version of SHA-256.'
        })
        matches.append({
            'algorithm': 'SHA3-224 (Keccak)',
            'category': 'SHA-3 Family',
            'length_bits': 224,
            'security_level': 'Strong (Sponge Construction)',
            'status_class': 'success',
            'notes': 'NIST SHA-3 standard resistant to length extension attacks.'
        })

    elif length == 64:
        matches.append({
            'algorithm': 'SHA-256',
            'category': 'SHA-2 Family',
            'length_bits': 256,
            'security_level': 'Industry Standard / Robust',
            'status_class': 'success',
            'notes': 'Widely used in TLS certificates, blockchain (Bitcoin), and file integrity verification.'
        })
        matches.append({
            'algorithm': 'SHA3-256',
            'category': 'SHA-3 Family',
            'length_bits': 256,
            'security_level': 'High Security',
            'status_class': 'success',
            'notes': 'Keccak sponge function; completely distinct mathematical structure from SHA-2.'
        })
        matches.append({
            'algorithm': 'BLAKE2s',
            'category': 'Cryptographic Hash',
            'length_bits': 256,
            'security_level': 'High Security & Blazing Fast',
            'status_class': 'success',
            'notes': 'Optimized for 8-to-32-bit platforms; faster than MD5 yet secure as SHA-3.'
        })

    elif length == 96:
        matches.append({
            'algorithm': 'SHA-384',
            'category': 'SHA-2 Family',
            'length_bits': 384,
            'security_level': 'High Security (NSA Suite B)',
            'status_class': 'success',
            'notes': 'Truncated version of SHA-512.'
        })
        matches.append({
            'algorithm': 'SHA3-384',
            'category': 'SHA-3 Family',
            'length_bits': 384,
            'security_level': 'High Security',
            'status_class': 'success',
            'notes': 'SHA-3 standard.'
        })

    elif length == 128:
        matches.append({
            'algorithm': 'SHA-512',
            'category': 'SHA-2 Family',
            'length_bits': 512,
            'security_level': 'Ultra High Security',
            'status_class': 'success',
            'notes': '64-bit word architecture. Highly resistant to cryptanalysis.'
        })
        matches.append({
            'algorithm': 'SHA3-512',
            'category': 'SHA-3 Family',
            'length_bits': 512,
            'security_level': 'Ultra High Security',
            'status_class': 'success',
            'notes': 'NIST SHA-3 sponge standard.'
        })
        matches.append({
            'algorithm': 'BLAKE2b',
            'category': 'Cryptographic Hash',
            'length_bits': 512,
            'security_level': 'Ultra High & Optimized for 64-bit CPUs',
            'status_class': 'success',
            'notes': 'RFC 7693 standard used in Argon2 and WireGuard.'
        })
        matches.append({
            'algorithm': 'Whirlpool',
            'category': 'Cryptographic Hash',
            'length_bits': 512,
            'security_level': 'Strong (AES-based Block Cipher Hash)',
            'status_class': 'info',
            'notes': 'Created by Vincent Rijmen and Paulo Barreto based on AES S-boxes.'
        })

    else:
        matches.append({
            'algorithm': f'Custom Hex Digest ({length} characters)',
            'category': 'Arbitrary Length',
            'length_bits': length * 4,
            'security_level': 'Unknown',
            'status_class': 'warning',
            'notes': f'Length {length} does not match standard 32, 40, 64, or 128-char algorithms.'
        })

    return matches

def verify_file_checksum(file_bytes: bytes, expected_hash: str) -> Dict[str, Any]:
    """
    Compares uploaded file checksum against expected vendor hash and identifies matching algorithm.
    """
    expected = expected_hash.strip().lower()
    computed = generate_hashes(file_bytes)

    for algo, val in computed.items():
        if val.lower() == expected:
            return {
                'match': True,
                'algorithm': algo.upper(),
                'computed_hash': val,
                'expected_hash': expected,
                'message': f'Checksum Verified! File matches expected {algo.upper()} digest perfectly.'
            }

    # If no match
    inferred = identify_hash(expected)
    likely_algo = inferred[0]['algorithm'] if inferred else 'Unknown'

    return {
        'match': False,
        'algorithm': likely_algo,
        'computed_hashes': computed,
        'expected_hash': expected,
        'message': 'INTEGRITY ALERT: Checksum mismatch! The file may have been modified, truncated, or tampered with.'
    }
