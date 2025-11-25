"""
Test script to validate port scanning attack PCAP generation.
"""
import sys
import os
from scapy.all import rdpcap, IP, TCP

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from features.attacks.scanning_port_generator import generate_port_scan

def analyze_port_scan_pcap():
    """Generate and analyze a port scan PCAP to verify correctness."""
    
    print("=" * 80)
    print("PORT SCAN ATTACK PCAP VALIDATION")
    print("=" * 80)
    
    # Test parameters
    TARGET_IP = "192.168.1.100"
    ATTACKER_IP = "10.0.0.50"
    PORTS_TO_SCAN = [22, 80, 443, 3306, 8080]
    OPEN_PORTS = {80, 443}
    
    print(f"\nTest Configuration:")
    print(f"  Target IP: {TARGET_IP}")
    print(f"  Attacker IP: {ATTACKER_IP}")
    print(f"  Ports to scan: {PORTS_TO_SCAN}")
    print(f"  Open ports: {OPEN_PORTS}")
    print(f"  Expected closed ports: {set(PORTS_TO_SCAN) - OPEN_PORTS}")
    
    # Generate packets
    packets = generate_port_scan(
        target_ip=TARGET_IP,
        ports_to_scan=PORTS_TO_SCAN,
        attacker_ip=ATTACKER_IP,
        open_ports=OPEN_PORTS
    )
    
    print(f"\n{'='*80}")
    print(f"ANALYSIS OF GENERATED PACKETS ({len(packets)} total)")
    print(f"{'='*80}\n")
    
    # Analyze packets
    issues = []
    warnings = []
    
    # Group packets by port
    port_packets = {}
    for pkt in packets:
        if TCP in pkt:
            port = pkt[TCP].dport if pkt[IP].src == ATTACKER_IP else pkt[TCP].sport
            if port not in port_packets:
                port_packets[port] = []
            port_packets[port].append(pkt)
    
    # Analyze each port
    for port in sorted(port_packets.keys()):
        print(f"\n--- Port {port} {'(OPEN)' if port in OPEN_PORTS else '(CLOSED)'} ---")
        port_pkts = port_packets[port]
        print(f"  Packets: {len(port_pkts)}")
        
        for i, pkt in enumerate(port_pkts, 1):
            tcp_flags = pkt[TCP].flags
            flag_str = str(tcp_flags)
            
            # Convert numeric flags to readable format
            if isinstance(tcp_flags, int):
                flag_names = []
                if tcp_flags & 0x01: flag_names.append("FIN")
                if tcp_flags & 0x02: flag_names.append("SYN")
                if tcp_flags & 0x04: flag_names.append("RST")
                if tcp_flags & 0x08: flag_names.append("PSH")
                if tcp_flags & 0x10: flag_names.append("ACK")
                if tcp_flags & 0x20: flag_names.append("URG")
                flag_str = "+".join(flag_names) if flag_names else str(tcp_flags)
            
            print(f"  {i}. {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}")
            print(f"     Flags: {flag_str}, Seq: {pkt[TCP].seq}, Ack: {pkt[TCP].ack}")
            print(f"     Time: {pkt.time if hasattr(pkt, 'time') else 'N/A'}")
        
        # Validate packet sequence for this port
        if port in OPEN_PORTS:
            # Should have: SYN -> SYN-ACK -> RST
            if len(port_pkts) != 3:
                issues.append(f"Port {port} (OPEN): Expected 3 packets (SYN, SYN-ACK, RST), got {len(port_pkts)}")
            else:
                # Check first packet (SYN from attacker)
                if port_pkts[0][IP].src != ATTACKER_IP:
                    issues.append(f"Port {port}: First packet should be from attacker")
                if "S" not in str(port_pkts[0][TCP].flags):
                    issues.append(f"Port {port}: First packet should have SYN flag")
                if port_pkts[0][TCP].ack != 0:
                    warnings.append(f"Port {port}: Initial SYN has ack={port_pkts[0][TCP].ack}, typically should be 0")
                
                # Check second packet (SYN-ACK from target)
                if port_pkts[1][IP].src != TARGET_IP:
                    issues.append(f"Port {port}: Second packet should be from target")
                if "SA" not in str(port_pkts[1][TCP].flags) and port_pkts[1][TCP].flags != 18:
                    issues.append(f"Port {port}: Second packet should have SYN-ACK flags")
                if port_pkts[1][TCP].ack != port_pkts[0][TCP].seq + 1:
                    issues.append(f"Port {port}: SYN-ACK ack should be SYN seq + 1")
                
                # Check third packet (RST from attacker)
                if port_pkts[2][IP].src != ATTACKER_IP:
                    issues.append(f"Port {port}: Third packet should be from attacker")
                if "R" not in str(port_pkts[2][TCP].flags):
                    issues.append(f"Port {port}: Third packet should have RST flag")
                if port_pkts[2][TCP].seq != port_pkts[0][TCP].seq + 1:
                    issues.append(f"Port {port}: RST seq should be original SYN seq + 1")
        else:
            # Closed port: Should have SYN -> RST-ACK
            if len(port_pkts) != 2:
                issues.append(f"Port {port} (CLOSED): Expected 2 packets (SYN, RST-ACK), got {len(port_pkts)}")
            else:
                # Check first packet (SYN from attacker)
                if port_pkts[0][IP].src != ATTACKER_IP:
                    issues.append(f"Port {port}: First packet should be from attacker")
                if "S" not in str(port_pkts[0][TCP].flags):
                    issues.append(f"Port {port}: First packet should have SYN flag")
                
                # Check second packet (RST-ACK from target)
                if port_pkts[1][IP].src != TARGET_IP:
                    issues.append(f"Port {port}: Second packet should be from target")
                if "RA" not in str(port_pkts[1][TCP].flags) and port_pkts[1][TCP].flags != 20:
                    issues.append(f"Port {port}: Second packet should have RST-ACK flags")
                if port_pkts[1][TCP].ack != port_pkts[0][TCP].seq + 1:
                    issues.append(f"Port {port}: RST-ACK ack should be SYN seq + 1")
    
    # Timing analysis
    print(f"\n{'='*80}")
    print("TIMING ANALYSIS")
    print(f"{'='*80}")
    
    times = [pkt.time for pkt in packets if hasattr(pkt, 'time')]
    if times:
        print(f"  First packet time: {times[0]}")
        print(f"  Last packet time: {times[-1]}")
        print(f"  Total duration: {times[-1] - times[0]:.6f} seconds")
        
        # Check time spacing
        syn_times = []
        for pkt in packets:
            if pkt[IP].src == ATTACKER_IP and "S" in str(pkt[TCP].flags) and "A" not in str(pkt[TCP].flags):
                if hasattr(pkt, 'time'):
                    syn_times.append(pkt.time)
        
        if len(syn_times) > 1:
            intervals = [syn_times[i+1] - syn_times[i] for i in range(len(syn_times)-1)]
            print(f"  SYN packet intervals: {[f'{x:.6f}s' for x in intervals]}")
            avg_interval = sum(intervals) / len(intervals)
            print(f"  Average interval: {avg_interval:.6f} seconds")
            
            # Check if intervals are reasonably consistent (around 1ms)
            if not all(0.0005 < interval < 0.002 for interval in intervals):
                warnings.append(f"SYN intervals vary significantly from expected ~1ms")
    else:
        warnings.append("No timestamps found on packets")
    
    # Check for duplicate sequence numbers (within same flow)
    print(f"\n{'='*80}")
    print("SEQUENCE NUMBER ANALYSIS")
    print(f"{'='*80}")
    
    attacker_seqs = set()
    target_seqs = set()
    
    for pkt in packets:
        if pkt[IP].src == ATTACKER_IP:
            if pkt[TCP].seq in attacker_seqs and "S" in str(pkt[TCP].flags):
                warnings.append(f"Duplicate sequence number from attacker: {pkt[TCP].seq}")
            attacker_seqs.add(pkt[TCP].seq)
        else:
            if pkt[TCP].seq in target_seqs and "S" in str(pkt[TCP].flags):
                warnings.append(f"Duplicate sequence number from target: {pkt[TCP].seq}")
            target_seqs.add(pkt[TCP].seq)
    
    print(f"  Unique attacker sequence numbers: {len(attacker_seqs)}")
    print(f"  Unique target sequence numbers: {len(target_seqs)}")
    
    # Summary
    print(f"\n{'='*80}")
    print("VALIDATION SUMMARY")
    print(f"{'='*80}\n")
    
    if not issues and not warnings:
        print("✓ ALL CHECKS PASSED - PCAP appears to be correctly generated!")
    else:
        if issues:
            print(f"✗ ISSUES FOUND ({len(issues)}):")
            for issue in issues:
                print(f"  - {issue}")
        
        if warnings:
            print(f"\n⚠ WARNINGS ({len(warnings)}):")
            for warning in warnings:
                print(f"  - {warning}")
    
    print(f"\n{'='*80}\n")
    
    return len(issues) == 0


if __name__ == "__main__":
    success = analyze_port_scan_pcap()
    sys.exit(0 if success else 1)
