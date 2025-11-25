"""
Example script demonstrating how to use the test suite to validate merged PCAP files.

This script shows:
1. How to run validation on existing merged files
2. How to integrate validation into your merge workflow
3. How to interpret validation results
"""

import os
import sys

# Add paths
_THIS_DIR = os.path.dirname(__file__)
_ROOT_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
_TESTS_DIR = os.path.join(_ROOT_DIR, "tests")
_SAMPLES_DIR = os.path.join(_ROOT_DIR, "samples")

if _TESTS_DIR not in sys.path:
    sys.path.insert(0, _TESTS_DIR)

from test_merged_pcap_labels import TestMergedPcapLabels


def example_validate_existing_merge():
    """
    Example: Validate an existing merged PCAP file.
    
    This demonstrates how to use the test suite to verify that a merged
    PCAP file has correct labels and IP translations.
    """
    print("="*80)
    print("EXAMPLE: Validating Existing Merged PCAP")
    print("="*80)
    print()
    
    # Point to your merged files
    # Replace these paths with actual merged files from your augmentations
    merged_pcap = os.path.join(_SAMPLES_DIR, "merged_output_v4.pcap")
    labels_csv = os.path.join(_SAMPLES_DIR, "merged_labels.csv")  # If it exists
    ip_translation_csv = os.path.join(_SAMPLES_DIR, "merged_output_v4_ip_translation_report.csv")  # If it exists
    
    # Check if files exist
    if not os.path.exists(merged_pcap):
        print(f"⚠ Merged PCAP not found: {merged_pcap}")
        print("  Please update the path to point to an actual merged PCAP file")
        return
    
    if not os.path.exists(labels_csv):
        print(f"⚠ Labels CSV not found: {labels_csv}")
        print("  Please update the path or create labels when merging")
        print("  Skipping this example...")
        return
    
    # Create test instance and run validation
    test = TestMergedPcapLabels()
    
    print(f"Validating:")
    print(f"  PCAP: {merged_pcap}")
    print(f"  Labels: {labels_csv}")
    if os.path.exists(ip_translation_csv):
        print(f"  IP Translation: {ip_translation_csv}")
    print()
    
    results = test.verify_merged_pcap_labels(
        merged_pcap_path=merged_pcap,
        labels_csv_path=labels_csv,
        ip_translation_csv_path=ip_translation_csv if os.path.exists(ip_translation_csv) else None,
        verbose=True
    )
    
    print()
    if results['valid']:
        print("✅ VALIDATION PASSED - Merged file is correctly labeled!")
    else:
        print("❌ VALIDATION FAILED - Issues found:")
        for error in results['errors']:
            print(f"   - {error}")
    
    return results


def example_validate_during_merge():
    """
    Example: Integrate validation into the merge workflow.
    
    This demonstrates how to merge PCAP files and immediately validate
    the results to ensure everything is correct.
    """
    print("\n" + "="*80)
    print("EXAMPLE: Merge and Validate Workflow")
    print("="*80)
    print()
    
    # This example shows the workflow, but doesn't execute to avoid creating files
    print("Workflow steps:")
    print("1. Create PcapMerger instance")
    print("2. Set IP translation range")
    print("3. Merge PCAPs with labels")
    print("4. Validate merged output")
    print()
    
    code_example = """
# Import required modules
from src.features.merger.pcap_merger import PcapMerger
from tests.test_merged_pcap_labels import TestMergedPcapLabels

# Setup merger
merger = PcapMerger(jitter_max=0.05)
merger.set_ip_translation_range("192.168.100.0/24")

# Merge with labels
success = merger.merge_pcaps(
    left_pcap="benign.pcap",
    right_pcap="malicious.pcap",
    output_file="merged.pcap",
    left_labels="benign_labels.csv",
    right_labels="malicious_labels.csv",
    output_labels="merged_labels.csv"
)

# Validate immediately
if success:
    test = TestMergedPcapLabels()
    results = test.verify_merged_pcap_labels(
        merged_pcap_path="merged.pcap",
        labels_csv_path="merged_labels.csv",
        ip_translation_csv_path="merged_ip_translation_report.csv",
        verbose=True
    )
    
    if results['valid']:
        print("✅ Merge successful and validated!")
    else:
        print("⚠ Merge succeeded but validation found issues")
        print("Errors:", results['errors'])
"""
    print("Code example:")
    print(code_example)


def example_run_as_unittest():
    """
    Example: Run as standard unittest.
    
    This shows how to use the test suite with Python's unittest framework.
    """
    print("\n" + "="*80)
    print("EXAMPLE: Running as unittest")
    print("="*80)
    print()
    
    print("To run the tests using unittest framework:")
    print()
    print("  # Run all tests")
    print("  python -m unittest tests.test_merged_pcap_labels")
    print()
    print("  # Run specific test")
    print("  python -m unittest tests.test_merged_pcap_labels.TestMergedPcapLabels.test_packet_count_matches_labels")
    print()
    print("  # Run with verbose output")
    print("  python -m unittest -v tests.test_merged_pcap_labels")
    print()


def example_standalone_validation():
    """
    Example: Run standalone validation script.
    
    This shows how to use the test file as a command-line tool.
    """
    print("\n" + "="*80)
    print("EXAMPLE: Standalone Validation Script")
    print("="*80)
    print()
    
    print("You can run the test file directly from command line:")
    print()
    print("  python tests/test_merged_pcap_labels.py merged.pcap merged_labels.csv")
    print()
    print("  # With IP translation report")
    print("  python tests/test_merged_pcap_labels.py merged.pcap merged_labels.csv ip_translation_report.csv")
    print()


if __name__ == "__main__":
    print("\nMERGED PCAP VALIDATION - USAGE EXAMPLES\n")
    
    # Run examples
    try:
        example_validate_existing_merge()
    except Exception as e:
        print(f"\nExample failed (this is expected if sample files don't exist): {e}\n")
    
    example_validate_during_merge()
    example_run_as_unittest()
    example_standalone_validation()
    
    print("\n" + "="*80)
    print("For more information, see tests/test_merged_pcap_labels.py")
    print("="*80 + "\n")
