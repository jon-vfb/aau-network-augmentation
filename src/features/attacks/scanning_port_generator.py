import random
from scapy.all import IP, TCP, wrpcap, RandShort
from typing import List, Set, Dict, Any
import os
import sys

# Import the attack base class
from .attack_base import AttackBase, AttackParameter

def generate_port_scan(target_ip: str, ports_to_scan: List[int], attacker_ip: str, open_ports: Set[int]) -> List:
    
    attack_packets = []
    
    for port in ports_to_scan:
        random_source_port = RandShort()
        #generation of the packet
        syn_packet = IP(src=attacker_ip, dst=target_ip) / TCP(sport=random_source_port, dport=port, flags="S")
        
        attack_packets.append(syn_packet)

        simulated_rtt = random.uniform(0.0001, 0.0005) # Simulated round-trip time between 0.1ms and 0.5ms
        response_time = syn_packet.time + simulated_rtt 

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

        else:
            # Closed port response
            rst_ack_packet = IP(src=target_ip, dst=attacker_ip) / TCP(
                sport=port,
                dport=random_source_port,
                flags="RA", # Flag Reset-Ack
                ack=syn_packet.seq + 1,
                seq=0 # No sequence number for RST-ACK
            )
            rst_ack_packet.time = response_time
            attack_packets.append(rst_ack_packet)

    return attack_packets

def save_packets_to_pcap(packets: List, filename: str):
    print(f"Saving {len(packets)} packets to '{filename}'...")
    
    wrpcap(filename, packets)
    
    print(f"PCAP file '{filename}' created successfully.")


class PortScanAttack(AttackBase):
    """
    Port Scanning Attack generator implementing the AttackBase interface.
    Performs a port scan on a target IP address.
    """
    
    ATTACK_NAME = "Port Scan"
    ATTACK_DESCRIPTION = "Port scanning attack to discover open ports on a target"
    ATTACK_PARAMETERS = [
        AttackParameter(
            name="target_ip",
            param_type="ip",
            description="IP address of the target",
            required=True,
            validation_hint="e.g., 192.168.1.100"
        ),
        AttackParameter(
            name="attacker_ip",
            param_type="ip",
            description="IP address of the attacker",
            required=True,
            validation_hint="e.g., 192.168.1.50"
        ),
        AttackParameter(
            name="ports",
            param_type="ports",
            description="Ports to scan (comma-separated or ranges)",
            required=True,
            validation_hint="e.g., 80,443,8080 or 80-100"
        ),
        AttackParameter(
            name="open_ports",
            param_type="ports",
            description="Which ports should appear as open (comma-separated)",
            required=False,
            default="80,443",
            validation_hint="Subset of ports to scan, default: 80,443"
        ),
    ]
    
    def generate(self, parameters: Dict[str, Any], output_path: str) -> bool:
        """
        Generate port scan attack PCAP.
        
        Args:
            parameters: Dict with 'target_ip', 'attacker_ip', 'ports', 'open_ports'
            output_path: Path to save the generated PCAP
            
        Returns:
            bool: True if successful
        """
        try:
            # Validate parameters
            is_valid, error_msg = self.validate_parameters(parameters)
            if not is_valid:
                raise ValueError(f"Invalid parameters: {error_msg}")
            
            target_ip = str(parameters.get('target_ip')).strip()
            attacker_ip = str(parameters.get('attacker_ip')).strip()
            ports_str = str(parameters.get('ports')).strip()
            open_ports_str = str(parameters.get('open_ports', '80,443')).strip()
            
            # Parse port strings
            ports_to_scan = self.parse_ports(ports_str)
            open_ports_set = set(self.parse_ports(open_ports_str))
            
            # Generate attack packets
            packets = generate_port_scan(
                target_ip=target_ip,
                ports_to_scan=ports_to_scan,
                attacker_ip=attacker_ip,
                open_ports=open_ports_set
            )
            
            # Save to PCAP file
            wrpcap(output_path, packets)
            return True
            
        except Exception as e:
            print(f"Error generating port scan attack: {e}")
            return False


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