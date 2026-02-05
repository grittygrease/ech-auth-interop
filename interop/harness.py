#!/usr/bin/env python3
"""
ECH Auth Interop Test Harness

Simple test runner that executes test vectors against multiple implementations.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

VERSION = "1.0.0"


class TestResult:
    def __init__(self, test_name: str, impl_name: str, passed: bool, error: str = "", duration_ms: int = 0):
        self.test_name = test_name
        self.impl_name = impl_name
        self.passed = passed
        self.error = error
        self.duration_ms = duration_ms


class Implementation:
    def __init__(self, name: str, verify_cmd: List[str], working_dir: str = "."):
        self.name = name
        self.verify_cmd = verify_cmd
        self.working_dir = working_dir

    def can_verify(self) -> bool:
        """Check if this implementation supports verification"""
        return len(self.verify_cmd) > 0


def discover_implementations() -> List[Implementation]:
    """Discover available ECH Auth implementations"""
    impls = []

    # Go implementation
    if Path("go/go.mod").exists():
        impls.append(Implementation(
            name="Go",
            verify_cmd=["go", "run", "./cmd/echauth-verify"],
            working_dir="go"
        ))

    # Rust implementation
    if Path("rust/Cargo.toml").exists():
        impls.append(Implementation(
            name="Rust",
            verify_cmd=["cargo", "run", "--quiet", "--bin", "ech-verify", "--"],
            working_dir="rust"
        ))

    # NSS implementation
    if Path("nss/echauth_client").exists():
        impls.append(Implementation(
            name="NSS",
            verify_cmd=["./echauth_client"],
            working_dir="nss"
        ))

    return impls


def load_test_vectors(path: str) -> Tuple[str, List[Dict]]:
    """Load test vectors from JSON file"""
    with open(path, 'r') as f:
        data = json.load(f)
    return data.get('version', 'unknown'), data.get('test_vectors', [])


def build_signed_config(test_vector: Dict) -> Optional[bytes]:
    """Build signed ECHConfig from test vector"""
    # If pre-built signed config is provided, use it
    if 'expected' in test_vector and 'signed_ech_config_hex' in test_vector['expected']:
        hex_str = test_vector['expected']['signed_ech_config_hex']
        return bytes.fromhex(hex_str)
    
    # Otherwise would need to construct from components
    return None


def run_test(impl: Implementation, test_vector: Dict, verbose: bool = False) -> TestResult:
    """Run a single test case"""
    start_time = time.time()
    test_name = test_vector['name']
    
    if not impl.can_verify():
        return TestResult(test_name, impl.name, False, "Implementation does not support verification")
    
    # Create temporary test file
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = os.path.join(tmpdir, "test.ech")
        
        # Build signed config
        signed_config = build_signed_config(test_vector)
        if signed_config is None:
            return TestResult(test_name, impl.name, False, "Signed config not provided in test vector")
        
        with open(config_path, 'wb') as f:
            f.write(signed_config)
        
        # Build command
        cmd = list(impl.verify_cmd)
        cmd.extend(["verify", "--config", config_path])
        
        # Add verification parameters
        if 'verification' in test_vector:
            verification = test_vector['verification']
            if 'current_time' in verification:
                cmd.extend(["--time", str(verification['current_time'])])
            
            if test_vector['method'] == 'rpk':
                trust_anchors = verification.get('trust_anchors', {})
                for spki_hash in trust_anchors.get('rpk_spki_hashes', []):
                    cmd.extend(["--trust-anchor", spki_hash])
        
        # Run command
        try:
            result = subprocess.run(
                cmd,
                cwd=impl.working_dir,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if verbose:
                print(f"    Command: {' '.join(cmd)}")
                print(f"    Output: {result.stdout}")
                if result.stderr:
                    print(f"    Stderr: {result.stderr}")
            
            # Check result
            expected = test_vector.get('expected', {})
            should_pass = expected.get('valid', False)
            
            if should_pass:
                if result.returncode == 0:
                    passed = True
                    error = ""
                else:
                    passed = False
                    error = f"Expected success but got error: {result.stderr}"
            else:
                if result.returncode != 0:
                    # Check error message if specified
                    error_contains = expected.get('error_contains', '')
                    if error_contains:
                        if error_contains in result.stdout or error_contains in result.stderr:
                            passed = True
                            error = ""
                        else:
                            passed = False
                            error = f"Error doesn't contain expected string '{error_contains}': {result.stderr}"
                    else:
                        passed = True
                        error = ""
                else:
                    passed = False
                    error = "Expected failure but verification succeeded"
            
            duration_ms = int((time.time() - start_time) * 1000)
            return TestResult(test_name, impl.name, passed, error, duration_ms)
            
        except subprocess.TimeoutExpired:
            return TestResult(test_name, impl.name, False, "Test timed out after 30 seconds")
        except Exception as e:
            return TestResult(test_name, impl.name, False, f"Exception: {str(e)}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description='ECH Auth Interop Test Harness')
    parser.add_argument('--vectors', default='test-vectors/interop.json',
                       help='Path to test vector JSON file')
    parser.add_argument('--impl', help='Only test specific implementation')
    parser.add_argument('--test', help='Only run tests matching this name')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--list', action='store_true',
                       help='List available tests and exit')
    
    args = parser.parse_args()
    
    # Load test vectors
    try:
        tv_version, test_vectors = load_test_vectors(args.vectors)
    except Exception as e:
        print(f"Error loading test vectors: {e}", file=sys.stderr)
        return 1
    
    if args.list:
        print(f"Test vectors from {args.vectors} (version {tv_version}):")
        for i, tv in enumerate(test_vectors, 1):
            method = tv.get('method', 'unknown')
            test_type = tv.get('test_type', 'unknown')
            print(f"  {i}. {tv['name']} ({method}, {test_type})")
            if 'description' in tv:
                print(f"     {tv['description']}")
        return 0
    
    # Discover implementations
    impls = discover_implementations()
    if args.impl:
        impls = [impl for impl in impls if args.impl.lower() in impl.name.lower()]
    
    if not impls:
        print("No implementations found", file=sys.stderr)
        return 1
    
    print(f"ECH Auth Interop Test Harness v{VERSION}")
    print(f"Test vectors: {args.vectors} (version {tv_version})")
    print(f"Implementations: {len(impls)}")
    print(f"Test vectors: {len(test_vectors)}\n")
    
    # Run tests
    all_results = []
    for impl in impls:
        print(f"Testing {impl.name}:")
        for tv in test_vectors:
            if args.test and args.test not in tv['name']:
                continue
            
            result = run_test(impl, tv, args.verbose)
            all_results.append(result)
            
            status = "✓ PASS" if result.passed else "✗ FAIL"
            print(f"  {status} {tv['name']} ({result.duration_ms}ms)")
            if not result.passed and result.error:
                print(f"      Error: {result.error}")
        print()
    
    # Summary
    passed = sum(1 for r in all_results if r.passed)
    failed = sum(1 for r in all_results if not r.passed)
    
    print("=== Summary ===")
    print(f"Total: {len(all_results)} tests")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    
    return 1 if failed > 0 else 0


if __name__ == '__main__':
    sys.exit(main())
