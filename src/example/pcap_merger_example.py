#!/usr/bin/env python3
"""
Example script demonstrating PCAP merger usage with IP translation
"""

import os
import sys
import argparse
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from features.merger.pcap_merger import PcapMerger
from classes.pcapparser import pcapparser


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Example of PCAP merger with IP translation')
    parser.add_argument('--left', help='Path to left (benign) PCAP file')
    parser.add_argument('--right', help='Path to right (malicious) PCAP file')
    parser.add_argument('--output', help='Path for output merged PCAP file')
    parser.add_argument('--ip-range', default='192.168.100.0/24',
                      help='CIDR notation for IP translation range (default: 192.168.100.0/24)')
    parser.add_argument('--jitter', type=float, default=0.05,
                      help='Maximum jitter to apply (default: 0.05 seconds)')
    
    args = parser.parse_args()
    
    # Paths to sample PCAP files
    samples_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'samples')
    left_pcap = args.left or os.path.join(samples_dir, 'pcaphandshake_1.pcapng')
    right_pcap = args.right or os.path.join(samples_dir, 'pcaphandshake_2.pcapng')
    output_file = args.output or os.path.join(samples_dir, 'merged_output.pcap')
    
    print("PCAP Merger Example")
    print("=" * 50)
    
    # Check if sample files exist
    if not os.path.exists(left_pcap):
        print(f"Left PCAP not found: {left_pcap}")
        return 1
    
    if not os.path.exists(right_pcap):
        print(f"Right PCAP not found: {right_pcap}")
        return 1
    
    # Create merger with specified jitter
    merger = PcapMerger(jitter_max=args.jitter)
    
    # Set IP translation range
    if not merger.set_ip_translation_range(args.ip_range):
        print("Failed to set IP translation range!")
        return 1
    
    print(f"Left (benign) PCAP: {left_pcap}")
    print(f"Right (malicious) PCAP: {right_pcap}")
    print(f"Output: {output_file}")
    print(f"Jitter: ±{merger.jitter_max} seconds")
    print(f"IP Translation Range: {args.ip_range}")
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
    if not merger.load_pcaps(left_pcap, right_pcap):
        print("Failed to load PCAP files!")
        return 1

    success = merger.merge(output_file)
    
    if success:
        print("Merge completed successfully!")
        
        # Analyze merged file
        print("\nAnalyzing merged file...")
        merged_parser = pcapparser(output_file)
        merged_parser.load()
        merged_flows = merged_parser.get_netflows()
        
        print(f"Merged PCAP: {merged_parser.get_packet_count()} packets, {len(merged_flows)} netflows")
        
        # Verify packet and netflow counts
        expected_packets = left_parser.get_packet_count() + right_parser.get_packet_count()
        actual_packets = merged_parser.get_packet_count()
        expected_flows = len(left_flows) + len(right_flows)
        actual_flows = len(merged_flows)
        
        print(f"\nPacket Verification:")
        print(f"Expected: {expected_packets} packets")
        print(f"Actual: {actual_packets} packets")
        
        if actual_packets == expected_packets:
            print("✅ Packet count matches expected!")
        else:
            print("❌ Packet count mismatch!")
        
        print(f"\nNetflow Verification:")
        print(f"Expected: {expected_flows} netflows")
        print(f"Actual: {actual_flows} netflows")
        
        if actual_flows == expected_flows:
            print("✅ Netflow count matches expected!")
        else:
            print("❌ Netflow count mismatch!")
        
        # Show IP translations that were applied
        print("\nIP Translations:")
        for original_ip, new_ip in merger.ip_mapping.items():
            print(f"{original_ip} -> {new_ip}")
        
        # Show sample netflows from merged file
        print(f"\nSample merged netflows (showing first 5):")
        merged_parser.print_netflows(limit=5)
        
        print("\nNote: IPs from the malicious PCAP have been translated to the new range")
        
    else:
        print("❌ Merge failed!")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())