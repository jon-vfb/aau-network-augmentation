#!/usr/bin/env python3
"""
Test script for input validation functions in augmentations.
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from features.augmentations import InputValidator


def test_project_name_validation():
    """Test project name validation"""
    print("\n" + "="*80)
    print("TESTING PROJECT NAME VALIDATION")
    print("="*80)
    
    test_cases = [
        ("", False, "empty string"),
        ("   ", False, "whitespace only"),
        ("my_project", True, "valid underscore"),
        ("my-project", True, "valid hyphen"),
        ("my project", True, "valid space"),
        ("MyProject123", True, "valid mixed"),
        ("project@name", False, "invalid character @"),
        ("project#name", False, "invalid character #"),
        ("a" * 101, False, "too long (>100 chars)"),
        ("valid_project_123", True, "valid complex name"),
    ]
    
    validator = InputValidator()
    passed = 0
    failed = 0
    
    for name, expected_valid, description in test_cases:
        is_valid, error_msg = validator.validate_project_name(name)
        status = "✓ PASS" if is_valid == expected_valid else "✗ FAIL"
        if is_valid == expected_valid:
            passed += 1
        else:
            failed += 1
        print(f"{status}: {description:30} | '{name[:20]}...' | {error_msg if not is_valid else 'Valid'}")
    
    print(f"\nResults: {passed} passed, {failed} failed")
    return failed == 0


def test_ip_range_validation():
    """Test IP range validation"""
    print("\n" + "="*80)
    print("TESTING IP RANGE VALIDATION")
    print("="*80)
    
    test_cases = [
        ("", True, "empty string (skip translation)"),
        ("   ", True, "whitespace only (skip translation)"),
        ("192.168.100.0/24", True, "valid /24"),
        ("10.0.0.0/8", True, "valid /8"),
        ("172.16.0.0/12", True, "valid /12"),
        ("192.168.0.0/30", False, "too small /30"),
        ("192.168.0.0/25", True, "valid /25 (minimum)"),
        ("192.168.0.0/26", False, "too small /26"),
        ("10.0.0.0/7", False, "too large /7"),
        ("invalid-ip", False, "invalid CIDR format"),
        ("192.168.1.0/33", False, "invalid prefix length"),
        ("256.256.256.0/24", False, "invalid IP octets"),
    ]
    
    validator = InputValidator()
    passed = 0
    failed = 0
    
    for ip_range, expected_valid, description in test_cases:
        is_valid, error_msg = validator.validate_ip_range(ip_range)
        status = "✓ PASS" if is_valid == expected_valid else "✗ FAIL"
        if is_valid == expected_valid:
            passed += 1
        else:
            failed += 1
        print(f"{status}: {description:35} | {ip_range:20} | {error_msg if not is_valid else 'Valid'}")
    
    print(f"\nResults: {passed} passed, {failed} failed")
    return failed == 0


def test_jitter_validation():
    """Test jitter validation"""
    print("\n" + "="*80)
    print("TESTING JITTER VALIDATION")
    print("="*80)
    
    test_cases = [
        ("", True, 0.1, "empty string (default)"),
        ("   ", True, 0.1, "whitespace only (default)"),
        ("0.1", True, 0.1, "valid default"),
        ("0", True, 0.0, "valid zero"),
        ("5.5", True, 5.5, "valid 5.5"),
        ("10", True, 10.0, "valid maximum (10)"),
        ("10.0", True, 10.0, "valid maximum float"),
        ("-1", False, 0.0, "negative value"),
        ("10.1", False, 0.0, "exceeds maximum"),
        ("15", False, 0.0, "exceeds maximum"),
        ("abc", False, 0.0, "non-numeric"),
        ("0.05", True, 0.05, "valid 50 milliseconds"),
    ]
    
    validator = InputValidator()
    passed = 0
    failed = 0
    
    for jitter_str, expected_valid, expected_value, description in test_cases:
        is_valid, jitter_value, error_msg = validator.validate_jitter(jitter_str)
        status = "✓ PASS" if (is_valid == expected_valid and (not is_valid or abs(jitter_value - expected_value) < 0.001)) else "✗ FAIL"
        if is_valid == expected_valid and (not is_valid or abs(jitter_value - expected_value) < 0.001):
            passed += 1
        else:
            failed += 1
        
        value_str = f"{jitter_value:.4f}" if is_valid else "N/A"
        print(f"{status}: {description:35} | {jitter_str:10} | {value_str:10} | {error_msg if not is_valid else 'Valid'}")
    
    print(f"\nResults: {passed} passed, {failed} failed")
    return failed == 0


def main():
    """Run all validation tests"""
    print("\n" + "="*80)
    print("INPUT VALIDATION TEST SUITE")
    print("="*80)
    
    results = {
        "Project Name": test_project_name_validation(),
        "IP Range": test_ip_range_validation(),
        "Jitter": test_jitter_validation(),
    }
    
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    
    all_passed = True
    for test_name, passed in results.items():
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"{test_name:20}: {status}")
        if not passed:
            all_passed = False
    
    print("="*80)
    
    if all_passed:
        print("\n✓ All tests passed!")
        return 0
    else:
        print("\n✗ Some tests failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
