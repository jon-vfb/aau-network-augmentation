"""
Example usage of the merge augmentation feature.
Demonstrates how to use the MergeAugmentation class and merge_augmentation function.
"""

import os
import sys
from pathlib import Path

# Ensure src is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from features.augmentations import MergeAugmentation, merge_augmentation


def example_1_basic_merge():
    """
    Example 1: Basic merge using convenience function
    Merges two sample pcap files with default settings.
    """
    print("\n" + "="*80)
    print("Example 1: Basic Merge Augmentation")
    print("="*80)
    
    # Paths to sample files (adjust as needed)
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    benign_pcap = os.path.join(repo_root, "samples", "pcaphandshake_1.pcapng")
    malicious_pcap = os.path.join(repo_root, "samples", "pcaphandshake_2.pcapng")
    
    # Check if files exist
    if not os.path.exists(benign_pcap) or not os.path.exists(malicious_pcap):
        print("⚠ Sample pcap files not found. Using example paths only.")
        print(f"  Expected benign: {benign_pcap}")
        print(f"  Expected malicious: {malicious_pcap}")
        return
    
    # Run the merge
    results = merge_augmentation(
        benign_pcap=benign_pcap,
        malicious_pcap=malicious_pcap,
        project_name="example_project_1"
    )
    
    print("\nResults summary:")
    print(f"  Success: {results['success']}")
    print(f"  Project dir: {results['project_dir']}")


def example_2_with_ip_translation():
    """
    Example 2: Merge with IP translation
    Translates malicious traffic to a different IP range to avoid conflicts.
    """
    print("\n" + "="*80)
    print("Example 2: Merge with IP Translation")
    print("="*80)
    
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    benign_pcap = os.path.join(repo_root, "samples", "pcaphandshake_1.pcapng")
    malicious_pcap = os.path.join(repo_root, "samples", "pcaphandshake_2.pcapng")
    
    if not os.path.exists(benign_pcap) or not os.path.exists(malicious_pcap):
        print("⚠ Sample pcap files not found. Using example paths only.")
        return
    
    # Run merge with IP translation
    results = merge_augmentation(
        benign_pcap=benign_pcap,
        malicious_pcap=malicious_pcap,
        project_name="example_project_2_with_ip_translation",
        ip_translation_range="192.168.100.0/24"  # Malicious traffic will use this range
    )
    
    print("\nResults summary:")
    print(f"  Success: {results['success']}")
    print(f"  IP translation applied to range: 192.168.100.0/24")


def example_3_with_jitter():
    """
    Example 3: Merge with custom jitter
    Adds random timing variations to malicious packets for more realistic blending.
    """
    print("\n" + "="*80)
    print("Example 3: Merge with Custom Jitter")
    print("="*80)
    
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    benign_pcap = os.path.join(repo_root, "samples", "pcaphandshake_1.pcapng")
    malicious_pcap = os.path.join(repo_root, "samples", "pcaphandshake_2.pcapng")
    
    if not os.path.exists(benign_pcap) or not os.path.exists(malicious_pcap):
        print("⚠ Sample pcap files not found. Using example paths only.")
        return
    
    # Run merge with custom jitter (0.5 seconds max)
    results = merge_augmentation(
        benign_pcap=benign_pcap,
        malicious_pcap=malicious_pcap,
        project_name="example_project_3_with_jitter",
        jitter_max=0.5  # Add up to 0.5 seconds of jitter
    )
    
    print("\nResults summary:")
    print(f"  Success: {results['success']}")
    print(f"  Jitter applied: ±0.5 seconds")


def example_4_custom_directory():
    """
    Example 4: Using custom output directory
    Demonstrates how to specify a custom base directory for project output.
    """
    print("\n" + "="*80)
    print("Example 4: Custom Output Directory")
    print("="*80)
    
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    benign_pcap = os.path.join(repo_root, "samples", "pcaphandshake_1.pcapng")
    malicious_pcap = os.path.join(repo_root, "samples", "pcaphandshake_2.pcapng")
    custom_output_dir = os.path.join(repo_root, "augmentation_results")
    
    if not os.path.exists(benign_pcap) or not os.path.exists(malicious_pcap):
        print("⚠ Sample pcap files not found. Using example paths only.")
        return
    
    # Run merge with custom output directory
    results = merge_augmentation(
        benign_pcap=benign_pcap,
        malicious_pcap=malicious_pcap,
        project_name="example_project_4_custom_dir",
        output_base_dir=custom_output_dir
    )
    
    print("\nResults summary:")
    print(f"  Success: {results['success']}")
    print(f"  Custom output dir: {custom_output_dir}")


def example_5_class_based():
    """
    Example 5: Using the class directly for more control
    Shows how to instantiate MergeAugmentation directly for advanced usage.
    """
    print("\n" + "="*80)
    print("Example 5: Class-Based Usage with Advanced Options")
    print("="*80)
    
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    benign_pcap = os.path.join(repo_root, "samples", "pcaphandshake_1.pcapng")
    malicious_pcap = os.path.join(repo_root, "samples", "pcaphandshake_2.pcapng")
    
    if not os.path.exists(benign_pcap) or not os.path.exists(malicious_pcap):
        print("⚠ Sample pcap files not found. Using example paths only.")
        return
    
    # Create augmentation object
    aug = MergeAugmentation(project_name="example_project_5_advanced")
    
    # Run with all options
    results = aug.run(
        benign_pcap=benign_pcap,
        malicious_pcap=malicious_pcap,
        ip_translation_range="10.0.0.0/8",
        jitter_max=0.2
    )
    
    # Print results using the built-in method
    aug.print_results(results)
    
    # Access individual results
    if results['success']:
        print("\nFull output paths:")
        print(f"  Benign CSV: {results['benign_csv']}")
        print(f"  Malicious CSV: {results['malicious_csv']}")
        print(f"  Merged PCAP: {results['merged_pcap']}")


def interactive_mode():
    """
    Interactive mode: prompts user for input and runs merge augmentation.
    """
    print("\n" + "="*80)
    print("Merge Augmentation - Interactive Mode")
    print("="*80)
    
    # Get user input
    benign_path = input("\nEnter path to benign PCAP file: ").strip()
    malicious_path = input("Enter path to malicious PCAP file: ").strip()
    project_name = input("Enter project name: ").strip()
    
    # Optional parameters
    print("\nOptional settings (press Enter to skip):")
    ip_range = input("IP translation range (e.g., 192.168.100.0/24): ").strip() or None
    jitter_str = input("Jitter max in seconds (default 0.1): ").strip()
    jitter_max = float(jitter_str) if jitter_str else 0.1
    
    # Run merge
    results = merge_augmentation(
        benign_pcap=benign_path,
        malicious_pcap=malicious_path,
        project_name=project_name,
        ip_translation_range=ip_range,
        jitter_max=jitter_max
    )
    
    # Print final status
    if results['success']:
        print("\n✓ Augmentation completed successfully!")
    else:
        print("\n✗ Augmentation failed!")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Merge augmentation examples and interactive mode"
    )
    parser.add_argument(
        "mode",
        nargs="?",
        choices=["example1", "example2", "example3", "example4", "example5", "interactive"],
        default="interactive",
        help="Run mode (default: interactive)"
    )
    
    args = parser.parse_args()
    
    if args.mode == "example1":
        example_1_basic_merge()
    elif args.mode == "example2":
        example_2_with_ip_translation()
    elif args.mode == "example3":
        example_3_with_jitter()
    elif args.mode == "example4":
        example_4_custom_directory()
    elif args.mode == "example5":
        example_5_class_based()
    elif args.mode == "interactive":
        interactive_mode()
    else:
        print("Running all examples...")
        example_1_basic_merge()
        example_2_with_ip_translation()
        example_3_with_jitter()
        example_4_custom_directory()
        example_5_class_based()
