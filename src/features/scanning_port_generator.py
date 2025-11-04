from scapy.all import IP, TCP, wrpcap, RandShort
from typing import List, Set
import os

def generate_port_scan(target_ip: str, ports_to_scan: List[int], attacker_ip: str, open_ports: Set[int]) -> List:
    
    attack_packets = []
    
    for port in ports_to_scan:
        random_source_port = RandShort()
        #generation of the packet
        syn_packet = IP(src=attacker_ip, dst=target_ip) / TCP(sport=random_source_port, dport=port, flags="S")
        
        attack_packets.append(syn_packet)
        
        response_time= syn_packet.time + 0.001  # Simulated response time

        if port in open_ports:
            
            syn_ack_packet = IP(src=target_ip, dst=attacker_ip) / TCP(
                sport=port,
                dport=random_source_port,
                flags="SA",
                ack=syn_packet.seq + 1,
                seq=RandShort()
            )
            syn_ack_packet.time = response_time
            attack_packets.append(syn_ack_packet)

            #RST packet in order to be stealthy (not completing the handshake)
            rst_packet = IP(src=attacker_ip, dst=target_ip) / TCP(
                sport=random_source_port,
                dport=port,
                flags="R", # Flag Reset
                ack=syn_ack_packet.seq + 1,
                seq=syn_packet.seq + 1
            )
            
            rst_packet.time = response_time + 0.00005 
            attack_packets.append(rst_packet)

    return attack_packets

def save_packets_to_pcap(packets: List, filename: str):
    print(f"Saving {len(packets)} packets to '{filename}'...")
    
    wrpcap(filename, packets)
    
    print(f"PCAP file '{filename}' created successfully.")

# ONLY FOR TESTING PURPOSES
if __name__ == "__main__":
    
    TARGET_IP_INPUT = input("Insert victim IP address (default 10.0.0.42): ")
    
    if not TARGET_IP_INPUT:
        TARGET_IP = "10.0.0.42"
    else:
        TARGET_IP = TARGET_IP_INPUT

    ATTACKER_IP = "192.168.1.137" 
    PORTS_TO_SCAN = [21, 22, 25, 80, 110, 143, 443, 3306, 3389, 8080]
    
    OPEN_PORTS = {80, 443, 8080}
    
    OUTPUT_FILENAME = "port_scan_attack.pcap"

    packets = generate_port_scan(
        target_ip=TARGET_IP,
        ports_to_scan=PORTS_TO_SCAN,
        attacker_ip=ATTACKER_IP,
        open_ports=OPEN_PORTS
    )

    save_packets_to_pcap(packets, OUTPUT_FILENAME)