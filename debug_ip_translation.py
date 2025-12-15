#!/usr/bin/env python3
"""
Debug script to test IP translation functionality.
Run this to check if IP translations are working correctly.
"""

import sys
import os
from src.classes.pcapparser import pcapparser
from src.features.merger.pcap_merger import PcapMerger

def test_ip_translation():
    """Test IP translation with two sample PCAP files."""
    
    # Using actual sample files from the project
    benign_pcap = "samples/ping_of_death_corrected.pcap"
    malicious_pcap = "samples/png_final_attack.pcap"
    
    # Check if files exist
    if not os.path.exists(benign_pcap):
        print(f"❌ Benign PCAP not found: {benign_pcap}")
        print("\nAvailable PCAP files in samples/:")
        for f in sorted(os.listdir("samples")):
            if f.endswith(".pcap") or f.endswith(".pcapng"):
                print(f"  - {f}")
        print("\nUsage: Modify the paths in this script to use actual files from above")
        return
    
    if not os.path.exists(malicious_pcap):
        print(f"❌ Malicious PCAP not found: {malicious_pcap}")
        print("\nAvailable PCAP files in samples/:")
        for f in sorted(os.listdir("samples")):
            if f.endswith(".pcap") or f.endswith(".pcapng"):
                print(f"  - {f}")
        print("\nUsage: Modify the paths in this script to use actual files from above")
        return
    
    print(f"Testing IP translation with:")
    print(f"  Benign:    {benign_pcap}")
    print(f"  Malicious: {malicious_pcap}")
    print()
    
    # Parse the malicious PCAP to see what IPs are in it
    print("Step 1: Analyzing malicious PCAP for IP addresses...")
    mal_parser = pcapparser(malicious_pcap)
    mal_parser.load()
    
    malicious_ips = set()
    for pkt in mal_parser.get_packets():
        from scapy.all import IP
        if pkt.haslayer(IP):
            malicious_ips.add(pkt[IP].src)
            malicious_ips.add(pkt[IP].dst)
    
    print(f"  Found {len(malicious_ips)} unique IPs in malicious PCAP:")
    for ip in sorted(malicious_ips):
        print(f"    - {ip}")
    print()
    
    # Now test the merger with IP translation
    print("Step 2: Testing IP translation range...")
    merger = PcapMerger()
    
    # Try to set an IP translation range
    test_range = "192.168.100.0/24"
    if merger.set_ip_translation_range(test_range):
        print(f"  ✓ Successfully set IP translation range: {test_range}")
    else:
        print(f"  ❌ Failed to set IP translation range: {test_range}")
        return
    print()
    
    # Load PCAP files
    print("Step 3: Loading PCAP files...")
    if merger.load_pcaps(benign_pcap, malicious_pcap):
        print(f"  ✓ Loaded both PCAP files")
    else:
        print(f"  ❌ Failed to load PCAP files")
        return
    print()
    
    # Try the merge (don't actually save, just test the translation tracking)
    print("Step 4: Testing merge and IP translation tracking...")
    output_pcap = "/tmp/test_merge_debug.pcap"
    
    # Temporarily override merge to just check translations
    left_packets = merger.left_parser.get_packets()
    right_packets = merger.right_parser.get_packets()
    
    print(f"  Benign packets: {len(left_packets)}")
    print(f"  Malicious packets: {len(right_packets)}")
    print()
    
    # Simulate the merge logic just to see translations
    print("Step 5: Simulating IP translation process...")
    merger._collect_used_ips()
    
    malicious_ips_found = set()
    for pkt in right_packets:
        from scapy.all import IP
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            malicious_ips_found.add(src)
            malicious_ips_found.add(dst)
            
            # Test getting translated IPs
            if merger.ip_translation_range:
                new_src = merger._get_next_available_ip(src)
                new_dst = merger._get_next_available_ip(dst)
                print(f"  {src} → {new_src}, {dst} → {new_dst}")
    
    print()
    print("Step 6: IP translation report:")
    print(f"  Total entries: {len(merger.ip_translation_report)}")
    for entry in merger.ip_translation_report:
        print(f"    {entry['original_ip']:15} → {entry['translated_ip']}")
    
    if len(merger.ip_translation_report) > 0:
        print("\n✓ IP translation tracking is WORKING!")
    else:
        print("\n❌ IP translation tracking is EMPTY!")
        print("Check:")
        print("  1. Malicious PCAP has IP packets")
        print("  2. IP translation range is valid and set")
        print("  3. The translation range has available IPs")

if __name__ == "__main__":
    test_ip_translation()
