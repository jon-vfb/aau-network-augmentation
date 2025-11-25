import random
from scapy.all import IP, TCP, wrpcap, RandShort
from typing import List, Set
import os
import time

def generate_port_scan(target_ip: str, ports_to_scan: List[int], attacker_ip: str, open_ports: Set[int]) -> List:
    
    attack_packets = []
    base_time = time.time() # Current time as the base for packet timestamps
    
    for i, port in enumerate(ports_to_scan): 
        random_source_port = RandShort()
        client_seq = random.randint(0, 4294967295) # Random initial sequence number
        
        # Create SYN packet
        syn_packet = IP(src=attacker_ip, dst=target_ip) / TCP(
            sport=random_source_port, 
            dport=port, 
            flags="S",
            seq=client_seq
        )
        # Remove automatic fields to force recalculation
        del syn_packet[IP].len
        del syn_packet[IP].chksum
        del syn_packet[TCP].chksum
        
        # Rebuild packet to recalculate fields
        syn_packet = syn_packet.__class__(bytes(syn_packet))
        
        syn_packet.time = base_time + (i * 0.001)
        attack_packets.append(syn_packet)

        # Simulate response time
        simulated_rtt = random.uniform(0.0001, 0.0005)
        response_time = syn_packet.time + simulated_rtt 

        # Create response packets based on port status
        if port in open_ports:
            server_seq = random.randint(0, 4294967295)
            syn_ack_packet = IP(src=target_ip, dst=attacker_ip) / TCP(
                sport=port,
                dport=random_source_port,
                flags="SA",
                ack=client_seq + 1,
                seq=server_seq
            )
            
            # Remove automatic fields to force recalculation
            del syn_ack_packet[IP].len
            del syn_ack_packet[IP].chksum
            del syn_ack_packet[TCP].chksum
            # Rebuild packet to recalculate fields
            syn_ack_packet = syn_ack_packet.__class__(bytes(syn_ack_packet))
            
            # Set timestamp and add to packet list
            syn_ack_packet.time = response_time
            attack_packets.append(syn_ack_packet)
            rst_packet = IP(src=attacker_ip, dst=target_ip) / TCP(
                sport=random_source_port,
                dport=port,
                flags="R",
                ack=syn_ack_packet.seq + 1,
                seq=client_seq + 1
            )
            
            # Remove automatic fields to force recalculation
            del rst_packet[IP].len
            del rst_packet[IP].chksum
            del rst_packet[TCP].chksum
            # Rebuild packet to recalculate fields
            rst_packet = rst_packet.__class__(bytes(rst_packet))
            
            # Set timestamp and add to packet list
            rst_packet.time = response_time + 0.00005 
            attack_packets.append(rst_packet)

        # Port is closed
        else:
            rst_ack_packet = IP(src=target_ip, dst=attacker_ip) / TCP(
                sport=port,
                dport=random_source_port,
                flags="RA",
                ack=client_seq + 1,
                seq=0
            )

            # Remove automatic fields to force recalculation
            del rst_ack_packet[IP].len
            del rst_ack_packet[IP].chksum
            del rst_ack_packet[TCP].chksum

            # Rebuild packet to recalculate fields
            rst_ack_packet = rst_ack_packet.__class__(bytes(rst_ack_packet))
            
            rst_ack_packet.time = response_time
            attack_packets.append(rst_ack_packet)

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