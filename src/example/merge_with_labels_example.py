#!/usr/bin/env python3
"""
Example demonstrating PCAP merging with label CSV files.

This example shows how to:
1. Load two PCAP files with their corresponding label CSVs
2. Merge the PCAP files with IP translation
3. Generate a merged label CSV that tracks:
   - Original labels for each packet
   - IP address changes (for malicious traffic translation)
   - Timestamp changes (for timeline mapping)
   - Source PCAP (left or right)
"""

import os
import sys

# Add parent directories to path
_THIS_DIR = os.path.dirname(__file__)
_SRC_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from features.merger.pcap_merger import PcapMerger
from features.labeler import Labeler

def example_merge_with_labels():
    """
    Example: Merge PCAP files with label tracking.
    """
    
    # Setup paths
    samples_dir = os.path.abspath(os.path.join(_THIS_DIR, "..", "..", "samples"))
    
    # Example PCAPs
    left_pcap = os.path.join(samples_dir, "pcaphandshake_1.pcapng")
    right_pcap = os.path.join(samples_dir, "pcaphandshake_2.pcapng")
    
    # Example labels (you can create these with the Labeler class)
    left_labels = os.path.join(samples_dir, "left_labels.csv")
    right_labels = os.path.join(samples_dir, "right_labels.csv")
    
    # Output files
    output_pcap = os.path.join(samples_dir, "merged_with_labels.pcapng")
    output_labels = os.path.join(samples_dir, "merged_labels.csv")
    
    # Create label files if they don't exist
    if not os.path.exists(left_labels) or not os.path.exists(right_labels):
        print("Creating label files...")
        labeler = Labeler()
        
        if os.path.exists(left_pcap):
            labeler.label_and_export(left_pcap, left_labels, "benign")
        else:
            print(f"Warning: Left PCAP not found: {left_pcap}")
            left_labels = None
        
        if os.path.exists(right_pcap):
            labeler.label_and_export(right_pcap, right_labels, "malicious")
        else:
            print(f"Warning: Right PCAP not found: {right_pcap}")
            right_labels = None
    
    # Merge with labels
    print("\n" + "="*80)
    print("PCAP MERGE WITH LABEL TRACKING")
    print("="*80)
    
    merger = PcapMerger(jitter_max=0.05)
    
    # Set IP translation range for malicious traffic
    if not merger.set_ip_translation_range("192.168.100.0/24"):
        print("Warning: Could not set IP translation range")
    
    # Load and merge
    success = merger.merge_pcaps(
        left_pcap=left_pcap,
        right_pcap=right_pcap,
        output_file=output_pcap,
        left_labels=left_labels,
        right_labels=right_labels,
        output_labels=output_labels
    )
    
    if success:
        print(f"\n✓ Merge completed successfully!")
        print(f"  Output PCAP: {output_pcap}")
        if os.path.exists(output_labels):
            print(f"  Output Labels: {output_labels}")
            
            # Show sample of merged labels
            import pandas as pd
            df = pd.read_csv(output_labels)
            print(f"\n  Merged labels preview (first 5 rows):")
            print(df.head().to_string())
            print(f"\n  Total merged records: {len(df)}")
            print(f"  Columns: {', '.join(df.columns.tolist())}")
    else:
        print("\n✗ Merge failed!")
    
    # Print merge statistics
    print("\n" + "-"*80)
    merger.print_merge_info()


def example_merge_without_labels():
    """
    Example: Merge PCAP files without labels (original behavior).
    """
    
    samples_dir = os.path.abspath(os.path.join(_THIS_DIR, "..", "..", "samples"))
    
    left_pcap = os.path.join(samples_dir, "pcaphandshake_1.pcapng")
    right_pcap = os.path.join(samples_dir, "pcaphandshake_2.pcapng")
    output_pcap = os.path.join(samples_dir, "merged_pcaps_basic.pcapng")
    
    print("\n" + "="*80)
    print("BASIC PCAP MERGE (without labels)")
    print("="*80)
    
    merger = PcapMerger(jitter_max=0.05)
    
    # Set IP translation range
    merger.set_ip_translation_range("192.168.50.0/24")
    
    # Merge without labels
    success = merger.merge_pcaps(
        left_pcap=left_pcap,
        right_pcap=right_pcap,
        output_file=output_pcap
    )
    
    if success:
        print(f"\n✓ Basic merge completed!")
        print(f"  Output: {output_pcap}")
    else:
        print("\n✗ Basic merge failed!")
    
    print("\n" + "-"*80)
    merger.print_merge_info()


if __name__ == "__main__":
    print("PCAP Merger with Label Support - Examples\n")
    
    # Run both examples
    try:
        example_merge_with_labels()
    except Exception as e:
        print(f"Example with labels failed: {e}")
    
    print("\n\n")
    
    try:
        example_merge_without_labels()
    except Exception as e:
        print(f"Basic example failed: {e}")
