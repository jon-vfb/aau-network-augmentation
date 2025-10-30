from scapy.all import IP, TCP, wrpcap, RandShort
from typing import List
import os

def generate_port_scan(target_ip: str, ports_to_scan: List[int], attacker_ip: str) -> List:
    
    attack_packets = []
    
    for port in ports_to_scan:
        random_source_port = RandShort()
        
        packet = IP(src=attacker_ip, dst=target_ip) / TCP(sport=random_source_port, dport=port, flags="S")
        
        attack_packets.append(packet)
        
    print("Packet generation completed.")
    return attack_packets

def save_packets_to_pcap(packets: List, filename: str):
    print(f"Saving {len(packets)} packets to '{filename}'...")
    
    wrpcap(filename, packets)
    
    print(f"PCAP file '{filename}' created successfully.")

if __name__ == "__main__":
    
    TARGET_IP = "10.0.0.42"
    ATTACKER_IP = "192.168.1.137"
    PORTS_TO_SCAN = [21, 22, 25, 80, 110, 143, 443, 3306, 3389, 8080]
    
    OUTPUT_FILENAME = "port_scan_attack.pcap"

    packets = generate_port_scan(
        target_ip=TARGET_IP,
        ports_to_scan=PORTS_TO_SCAN,
        attacker_ip=ATTACKER_IP
    )
    
    save_packets_to_pcap(packets, OUTPUT_FILENAME)