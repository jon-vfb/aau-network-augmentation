#!/usr/bin/env python3
"""
Quick test to check if merge() is being called and what IP translations happen.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from src.features.augmentations import merge_augmentation

# Run a merge and capture output
print("Running merge_augmentation with test files...")
print()

results = merge_augmentation(
    benign_pcap="samples/benign/ping_of_death_corrected.pcap",
    malicious_pcap="samples/malicious/png_final_attack.pcap",
    project_name="test_ip_translation",
    output_base_dir="augmentations",
    ip_translation_range="192.168.100.0/24",
    jitter_max=0.1
)

print("\n" + "="*80)
print("RESULTS:")
print("="*80)
for msg in results.get("messages", []):
    print(msg)

# Check if report was created
if results.get("success"):
    print("\n✓ Merge succeeded")
    report_path = results.get("ip_translation_report")
    if report_path:
        print(f"\nIP Translation Report should be at: {report_path}")
        if os.path.exists(report_path):
            print("File exists!")
            with open(report_path) as f:
                content = f.read()
                print(f"Content:\n{content}")
        else:
            print("File does NOT exist!")
else:
    print("\n✗ Merge failed")
