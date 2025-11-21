#!/usr/bin/env python3
"""
Test timestamp overlap resolution with debug output
"""

import os
import sys
sys.path.append('src')
from features.merger.pcap_merger import PcapMerger

# Create a simple test case
test_timestamps = [
    (1.0, "packet1"),
    (1.0, "packet2"),  # Duplicate
    (2.0, "packet3"),
    (2.0, "packet4"),  # Duplicate
    (3.0, "packet5"),
]

merger = PcapMerger()
print("Original timestamps:", [ts for ts, _ in test_timestamps])

resolved = merger._resolve_timestamp_overlaps(test_timestamps)
print("Resolved timestamps:", [ts for ts, _ in resolved])

# Check for duplicates
timestamps = [ts for ts, _ in resolved]
unique_count = len(set(timestamps))
print(f"Unique timestamps: {unique_count} out of {len(timestamps)}")

if unique_count == len(timestamps):
    print("✅ Test passed!")
else:
    print("❌ Test failed - still have duplicates")