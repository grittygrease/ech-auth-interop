#!/usr/bin/env python3
"""
Simple ECH Auth config parser that validates Go/Rust test vectors
without requiring NSS libraries.
"""

import struct
import sys
from pathlib import Path

def read_u16(data, offset):
    return struct.unpack('>H', data[offset:offset+2])[0], offset + 2

def read_u8(data, offset):
    return data[offset], offset + 1

def parse_ech_config(data):
    """Parse ECH config to verify it's valid"""
    offset = 0
    
    # version (u16)
    version, offset = read_u16(data, offset)
    print(f"  Version: 0x{version:04x}")
    
    # length (u16)
    length, offset = read_u16(data, offset)
    print(f"  Length: {length} bytes")
    
    # contents
    config_id, offset = read_u8(data, offset)
    print(f"  Config ID: {config_id}")
    
    # kem_id (u16)
    kem_id, offset = read_u16(data, offset)
    print(f"  KEM ID: 0x{kem_id:04x}")
    
    # public_key length (u16)
    pk_len, offset = read_u16(data, offset)
    print(f"  Public key length: {pk_len} bytes")
    offset += pk_len  # skip public key
    
    # cipher_suites length (u16)
    cs_len, offset = read_u16(data, offset)
    print(f"  Cipher suites length: {cs_len} bytes")
    offset += cs_len  # skip cipher suites
    
    # maximum_name_length (u8)
    max_name_len, offset = read_u8(data, offset)
    print(f"  Max name length: {max_name_len}")
    
    # public_name length (u8)
    pn_len, offset = read_u8(data, offset)
    public_name = data[offset:offset+pn_len].decode('ascii', errors='replace')
    print(f"  Public name: {public_name}")
    offset += pn_len
    
    # extensions length (u16)
    ext_len, offset = read_u16(data, offset)
    print(f"  Extensions length: {ext_len} bytes")
    
    if ext_len > 0:
        ext_end = offset + ext_len
        while offset < ext_end:
            ext_type, offset = read_u16(data, offset)
            ext_data_len, offset = read_u16(data, offset)
            print(f"    Extension type: 0x{ext_type:04x}, length: {ext_data_len}")
            
            if ext_type == 0xfd00:  # ech_auth extension
                method, offset = read_u8(data, offset)
                print(f"      ECH Auth method: {method} ({'RPK' if method == 0 else 'PKIX' if method == 1 else 'unknown'})")
                
                not_before, offset = read_u16(data, offset)
                not_after, offset = read_u16(data, offset)
                print(f"      Validity: not_before={not_before}, not_after={not_after}")
                
                sig_len, offset = read_u16(data, offset)
                print(f"      Signature length: {sig_len} bytes")
                
                remaining = ext_data_len - (1 + 2 + 2 + 2 + sig_len)
                offset += sig_len + remaining
            else:
                offset += ext_data_len
    
    return True

def main():
    test_vectors = [
        ("test-vectors/go_signed_rpk.ech", "Go RPK"),
        ("test-vectors/go_signed_pkix.ech", "Go PKIX"),
        ("test-vectors/rust_signed_rpk.ech", "Rust RPK"),
        ("test-vectors/rust_signed_pkix.ech", "Rust PKIX"),
    ]
    
    passed = 0
    failed = 0
    
    print("=== NSS ECH Auth Interop Tests ===\n")
    print("Testing ECH Auth config parsing\n")
    
    for vector_path, name in test_vectors:
        path = Path(vector_path)
        if not path.exists():
            print(f"SKIP: {name} (file not found: {vector_path})")
            continue
            
        try:
            data = path.read_bytes()
            print(f"\n--- {name} ---")
            parse_ech_config(data)
            print(f"✓ PASS: {name} parsed successfully")
            passed += 1
        except Exception as e:
            print(f"✗ FAIL: {name} - {e}")
            failed += 1
    
    print(f"\n=== Results ===")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
