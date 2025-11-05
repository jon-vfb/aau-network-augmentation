#!/usr/bin/env python3
"""
Example script demonstrating PCAP merger usage
"""

import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from features.merger.pcap_merger import PcapMerger
from classes.pcapparser import pcapparser


def main():
    # Paths to sample PCAP files
    samples_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'samples')
    left_pcap = os.path.join(samples_dir, 'pcaphandshake_1.pcapng')
    right_pcap = os.path.join(samples_dir, 'pcaphandshake_2.pcapng')
    output_file = os.path.join(samples_dir, 'merged_output.pcap')
    
    print("PCAP Merger Example")
    print("=" * 50)
    
    # Check if sample files exist
    if not os.path.exists(left_pcap):
        print(f"Left PCAP not found: {left_pcap}")
        return 1
    
    if not os.path.exists(right_pcap):
        print(f"Right PCAP not found: {right_pcap}")
        return 1
    
    # Create merger with 0.05 second jitter
    merger = PcapMerger(jitter_max=0.05)
    
    print(f"Left PCAP: {left_pcap}")
    print(f"Right PCAP: {right_pcap}")
    print(f"Output: {output_file}")
    print(f"Jitter: ±{merger.jitter_max} seconds")
    print()
    
    # Analyze original files
    print("Analyzing original files...")
    left_parser = pcapparser(left_pcap)
    left_parser.load()
    left_flows = left_parser.get_netflows()
    
    right_parser = pcapparser(right_pcap)
    right_parser.load()
    right_flows = right_parser.get_netflows()
    
    print(f"Left PCAP: {left_parser.get_packet_count()} packets, {len(left_flows)} netflows")
    print(f"Right PCAP: {right_parser.get_packet_count()} packets, {len(right_flows)} netflows")
    print()
    
    # Perform merge
    print("Starting merge process...")
    success = merger.merge_pcaps(left_pcap, right_pcap, output_file)
    
    if success:
        print("Merge completed successfully!")
        
        # Analyze merged file
        print("\nAnalyzing merged file...")
        merged_parser = pcapparser(output_file)
        merged_parser.load()
        merged_flows = merged_parser.get_netflows()
        
        print(f"Merged PCAP: {merged_parser.get_packet_count()} packets, {len(merged_flows)} netflows")
        
        # Verify netflow count
        expected_flows = len(left_flows) + len(right_flows)
        actual_flows = len(merged_flows)
        
        print(f"\nNetflow Verification:")
        print(f"Expected: {expected_flows} netflows")
        print(f"Actual: {actual_flows} netflows")
        
        if actual_flows == expected_flows:
            print("✅ Netflow count matches expected!")
        else:
            print("❌ Netflow count mismatch!")
        
        # Show some sample netflows
        print(f"\nSample merged netflows:")
        merged_parser.print_netflows(limit=5)
        
    else:
        print("❌ Merge failed!")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())