#!/usr/bin/env python3
"""
Generate JSON test vectors from existing binary ECHConfig files
"""

import json
import sys
from pathlib import Path
import struct
import hashlib

def parse_ech_config(data: bytes) -> dict:
    """Parse ECHConfig to extract components"""
    offset = 0
    
    # version (u16)
    version = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    
    # length (u16)
    length = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    
    config_start = offset
    
    # config_id (u8)
    config_id = data[offset]
    offset += 1
    
    # kem_id (u16)
    kem_id = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    
    # public_key length + data
    pk_len = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    public_key = data[offset:offset+pk_len]
    offset += pk_len
    
    # cipher_suites length + data
    cs_len = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    cipher_suites = data[offset:offset+cs_len]
    offset += cs_len
    
    # maximum_name_length (u8)
    max_name_len = data[offset]
    offset += 1
    
    # public_name length + data
    pn_len = data[offset]
    offset += 1
    public_name = data[offset:offset+pn_len].decode('ascii', errors='replace')
    offset += pn_len
    
    # extensions length
    ext_len = struct.unpack('>H', data[offset:offset+2])[0]
    offset += 2
    
    extensions = []
    ext_start = offset
    ext_end = offset + ext_len
    
    signature_info = None
    ech_config_tbs = None
    last_ext_was_ech_auth = False
    
    while offset < ext_end:
        ext_type = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        ext_data_len = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2
        ext_data = data[offset:offset+ext_data_len]
        
        extensions.append({
            "type": ext_type,
            "length": ext_data_len
        })
        
        if ext_type == 0xfe0d:  # ech_auth extension
            # ECHConfig TBS is everything up to (but not including) the ech_auth extension
            # This includes the ECHConfig header and all previous extensions
            ech_config_tbs_end = offset - 4  # Back up to before ext_type and ext_data_len
            ech_config_tbs = data[4:ech_config_tbs_end]  # Skip version(2) + length(2)
            
            # Parse signature
            ext_offset = 0
            method = ext_data[ext_offset]
            ext_offset += 1
            
            not_after = struct.unpack('>Q', ext_data[ext_offset:ext_offset+8])[0]
            ext_offset += 8
            
            auth_len = struct.unpack('>H', ext_data[ext_offset:ext_offset+2])[0]
            ext_offset += 2
            authenticator = ext_data[ext_offset:ext_offset+auth_len]
            ext_offset += auth_len
            
            algorithm = struct.unpack('>H', ext_data[ext_offset:ext_offset+2])[0]
            ext_offset += 2
            
            sig_len = struct.unpack('>H', ext_data[ext_offset:ext_offset+2])[0]
            ext_offset += 2
            signature = ext_data[ext_offset:ext_offset+sig_len]
            
            # Compute SPKI hash for RPK
            spki_hash = None
            if method == 0:  # RPK
                spki_hash = hashlib.sha256(authenticator).hexdigest()
            
            signature_info = {
                "method": "rpk" if method == 0 else "pkix",
                "not_after": not_after,
                "authenticator_hex": authenticator.hex(),
                "algorithm": algorithm,
                "signature_hex": signature.hex(),
                "spki_hash_hex": spki_hash
            }
            last_ext_was_ech_auth = True
        
        offset += ext_data_len
    
    return {
        "version": version,
        "public_name": public_name,
        "ech_config_tbs_hex": ech_config_tbs.hex() if ech_config_tbs else None,
        "signature": signature_info,
        "full_config_hex": data.hex()
    }


def generate_test_vector(file_path: Path, name: str, source: str) -> dict:
    """Generate a test vector from a binary file"""
    data = file_path.read_bytes()
    parsed = parse_ech_config(data)
    
    if not parsed["signature"]:
        return None
    
    sig = parsed["signature"]
    method = sig["method"]
    
    # Determine test type from filename
    test_type = "valid"
    if "bad" in file_path.name.lower():
        test_type = "invalid_signature"
    
    # Create verification context with reasonable defaults
    # Use a time before not_after for valid tests
    current_time = sig["not_after"] - 86400  # 1 day before expiration
    
    trust_anchors = {}
    if method == "rpk":
        trust_anchors["rpk_spki_hashes"] = [sig["spki_hash_hex"]]
    
    test_vector = {
        "name": name,
        "description": f"Test vector from {source} implementation ({method.upper()} method)",
        "method": method,
        "test_type": test_type,
        "ech_config": parsed["ech_config_tbs_hex"],
        "signature": {
            "algorithm": sig["algorithm"],
            "not_after": sig["not_after"],
            "authenticator_hex": sig["authenticator_hex"],
            "signature_hex": sig["signature_hex"]
        },
        "verification": {
            "current_time": current_time,
            "trust_anchors": trust_anchors
        },
        "expected": {
            "valid": test_type == "valid",
            "spki_hash_hex": sig.get("spki_hash_hex"),
            "signed_ech_config_hex": parsed["full_config_hex"]
        },
        "source": source
    }
    
    return test_vector


def main():
    test_vectors_dir = Path("test-vectors")
    
    vectors = []
    
    # Generate from existing test files
    test_files = [
        ("go_signed_rpk.ech", "Go RPK signature verification", "go"),
        ("go_signed_pkix.ech", "Go PKIX signature verification", "go"),
        ("rust_signed_rpk.ech", "Rust RPK signature verification", "rust"),
        ("rust_signed_pkix.ech", "Rust PKIX signature verification", "rust"),
    ]
    
    for filename, name, source in test_files:
        file_path = test_vectors_dir / filename
        if file_path.exists():
            try:
                tv = generate_test_vector(file_path, name, source)
                if tv:
                    vectors.append(tv)
                    print(f"Generated: {name}", file=sys.stderr)
                else:
                    print(f"Skipped (no signature): {name}", file=sys.stderr)
            except Exception as e:
                print(f"Error generating {name}: {e}", file=sys.stderr)
                import traceback
                traceback.print_exc(file=sys.stderr)
        else:
            print(f"File not found: {file_path}", file=sys.stderr)
    
    # Add some negative test cases
    # TODO: Generate these programmatically
    
    # Create test vector file
    output = {
        "version": "1.0.0",
        "description": "ECH Auth interoperability test vectors",
        "test_vectors": vectors
    }
    
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
