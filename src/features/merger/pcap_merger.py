from scapy.all import *
from scapy.utils import rdpcap, wrpcap
# Explicit imports to ensure layer classes are available
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
from scapy.packet import Raw
import os
import random
import time
import ipaddress
from typing import List, Dict, Optional, Tuple, Set
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from classes.pcapparser import pcapparser

# Import the centralized protocol-ports configuration
from configs.protocol_ports import (
    get_ports_for_protocol, get_protocols_for_port, get_primary_port,
    uses_tcp, uses_udp, get_protocol_transport, get_protocol_info,
    is_well_known_port, get_port_category, validate_port
)


class PcapMerger:
    def __init__(self, jitter_max: float = 0.1):
        """
        Initialize PCAP merger with jitter parameter.
        
        Args:
            jitter_max (float): Maximum jitter to add to timestamps (in seconds)
        """
        self.jitter_max = jitter_max
        self.left_parser = None
        self.right_parser = None
        self.ip_translation_range = None
        self.ip_mapping = {}  # Store IP translations
        self.used_ips = set()  # Track all used IPs
        
    def set_ip_translation_range(self, ip_range: str) -> bool:
        """
        Set the IP range for translating malicious traffic IPs.
        
        Args:
            ip_range (str): CIDR notation for IP range (e.g., '192.168.100.0/24')
            
        Returns:
            bool: Success status
        """
        try:
            self.ip_translation_range = ipaddress.ip_network(ip_range)
            return True
        except ValueError as e:
            print(f"Error setting IP translation range: {e}")
            return False
            
    def load_pcaps(self, left_pcap: str, right_pcap: str) -> bool:
        """
        Load both PCAP files.
        
        Args:
            left_pcap (str): Path to left PCAP file
            right_pcap (str): Path to right PCAP file
            
        Returns:
            bool: Success status
        """
        try:
            self.left_parser = pcapparser(left_pcap)
            self.right_parser = pcapparser(right_pcap)
            
            # Load packets
            left_packets = self.left_parser.load()
            right_packets = self.right_parser.load()
            
            if not left_packets:
                print(f"Error: No packets found in left PCAP: {left_pcap}")
                return False
            if not right_packets:
                print(f"Error: No packets found in right PCAP: {right_pcap}")
                return False
                
            # Initialize used IPs set with IPs from both PCAPs
            self._collect_used_ips()
                
            print(f"Loaded {len(left_packets)} packets from left PCAP")
            print(f"Loaded {len(right_packets)} packets from right PCAP")
            return True
            
        except Exception as e:
            print(f"Error loading PCAP files: {e}")
            return False
            
    def merge(self, output_path: str) -> bool:
        """
        Merge the loaded PCAP files with IP translation for malicious traffic.
        
        Args:
            output_path (str): Path for the merged output file
            
        Returns:
            bool: Success status
        """
        if not self.left_parser or not self.right_parser:
            print("Error: PCAP files not loaded")
            return False
            
        try:
            # Extract netflows and timing information (IP packets only)
            left_flows = self._extract_netflows_with_timing(self.left_parser)
            right_flows = self._extract_netflows_with_timing(self.right_parser)
            
            # Get all packets including non-IP packets
            left_packets = self.left_parser.get_packets()
            right_packets = self.right_parser.get_packets()
            
            # Calculate base timestamp from all packets
            left_base = min(float(pkt.time) for pkt in left_packets)
            right_base = min(float(pkt.time) for pkt in right_packets)
            
            merged_packets = []
            
            # Process left (benign) packets - include ALL packets
            for pkt in left_packets:
                merged_packets.append((float(pkt.time), pkt))
                    
            # Process right (malicious) packets with IP translation
            for pkt in right_packets:
                # Create a copy of the packet for modification
                new_pkt = pkt.copy()
                
                # Apply IP translation if packet has IP layer and range is set
                if self.ip_translation_range and new_pkt.haslayer(IP):
                    original_src = new_pkt[IP].src
                    original_dst = new_pkt[IP].dst
                    
                    # Get translated IPs
                    new_src_ip = self._get_next_available_ip(original_src)
                    new_dst_ip = self._get_next_available_ip(original_dst)
                    
                    # Only translate if we successfully got new IPs
                    if new_src_ip and new_dst_ip:
                        new_pkt[IP].src = new_src_ip
                        new_pkt[IP].dst = new_dst_ip
                        # Delete checksums to force recalculation
                        del new_pkt[IP].chksum
                        if new_pkt.haslayer(TCP):
                            del new_pkt[TCP].chksum
                        elif new_pkt.haslayer(UDP):
                            del new_pkt[UDP].chksum
                    else:
                        print(f"Warning: Could not allocate new IPs for {original_src}->{original_dst}, keeping original IPs")
                        
                # Calculate relative timestamp with jitter
                relative_ts = float(pkt.time) - right_base
                new_ts = left_base + self._apply_jitter(relative_ts)
                merged_packets.append((new_ts, new_pkt))
                    
            # Sort packets by timestamp
            merged_packets.sort(key=lambda x: x[0])
            
            # Write merged PCAP
            wrpcap(output_path, [pkt for _, pkt in merged_packets])
            print(f"Successfully merged {len(merged_packets)} packets")
            return True
            
        except Exception as e:
            print(f"Error during merge: {e}")
            return False
            
    def _collect_used_ips(self):
        """Collect all used IP addresses from both PCAP files."""
        self.used_ips.clear()
        
        # Collect IPs from left PCAP
        for pkt in self.left_parser.get_packets():
            if pkt.haslayer(IP):
                self.used_ips.add(pkt[IP].src)
                self.used_ips.add(pkt[IP].dst)
                
        # Collect original IPs from right PCAP (before translation)
        for pkt in self.right_parser.get_packets():
            if pkt.haslayer(IP):
                self.used_ips.add(pkt[IP].src)
                self.used_ips.add(pkt[IP].dst)
                
    def _get_next_available_ip(self, original_ip: str) -> Optional[str]:
        """
        Get the next available IP from the translation range.
        
        Args:
            original_ip (str): Original IP to translate
            
        Returns:
            Optional[str]: New IP address or None if no IPs available
        """
        if original_ip in self.ip_mapping:
            return self.ip_mapping[original_ip]
            
        if not self.ip_translation_range:
            return None
            
        # Try to find an available IP in the translation range
        for ip in self.ip_translation_range.hosts():
            ip_str = str(ip)
            if ip_str not in self.used_ips:
                self.ip_mapping[original_ip] = ip_str
                self.used_ips.add(ip_str)
                return ip_str
                
        return None
        
    def _apply_jitter(self, delta: float) -> float:
        """
        Apply random jitter to a time delta.
        
        Args:
            delta (float): Original time delta
            
        Returns:
            float: Delta with jitter applied
        """
        if self.jitter_max <= 0:
            return delta
            
        # Apply jitter as a percentage of the original delta, capped by jitter_max
        jitter_range = min(abs(delta * 0.1), self.jitter_max)
        jitter = random.uniform(-jitter_range, jitter_range)
        return max(0, delta + jitter)  # Ensure positive delta
        
    def _extract_netflows_with_timing(self, parser: pcapparser) -> Dict[str, Dict]:
        """
        Extract netflows with detailed timing information.
        
        Args:
            parser (pcapparser): Parser containing loaded packets
            
        Returns:
            Dict[str, Dict]: Dictionary of netflows with timing data
        """
        flows = {}
        packets = parser.get_packets()
        
        for pkt in packets:
            if not pkt.haslayer(IP):
                continue
                
            ip_layer = pkt[IP]
            flow_key = None
            protocol = None
            src_port = dst_port = 0
            
            # Extract transport protocol and ports
            if pkt.haslayer(TCP):
                protocol = 'TCP'
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                protocol = 'UDP'
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
            elif pkt.haslayer(ICMP):
                protocol = 'ICMP'
                src_port = dst_port = 0
            else:
                protocol = str(ip_layer.proto)
                src_port = dst_port = 0
                
            # Create unidirectional flow key
            flow_key = f"{ip_layer.src}:{src_port}->{ip_layer.dst}:{dst_port}-{protocol}"
            
            if flow_key not in flows:
                flows[flow_key] = {
                    'packets': [],
                    'timestamps': [],
                    'src_ip': ip_layer.src,
                    'src_port': src_port,
                    'dst_ip': ip_layer.dst,
                    'dst_port': dst_port,
                    'protocol': protocol
                }
                
            flows[flow_key]['packets'].append(pkt)
            flows[flow_key]['timestamps'].append(float(pkt.time))
            
        return flows
        
    def merge_pcaps(self, left_pcap: str, right_pcap: str, output_file: str) -> bool:
        """
        Convenience method to load and merge PCAP files in one call.
        
        Args:
            left_pcap (str): Path to left PCAP file
            right_pcap (str): Path to right PCAP file
            output_file (str): Path for output merged PCAP file
            
        Returns:
            bool: Success status
        """
        if not self.load_pcaps(left_pcap, right_pcap):
            return False
        
        return self.merge(output_file)

    def get_merge_statistics(self) -> Dict:
        """
        Get statistics about the last merge operation.
        
        Returns:
            Dict: Statistics dictionary
        """
        if not self.left_parser or not self.right_parser:
            return {}
            
        left_flows = self._extract_netflows_with_timing(self.left_parser)
        right_flows = self._extract_netflows_with_timing(self.right_parser)
        
        stats = {
            'left_packets': len(self.left_parser.get_packets()),
            'right_packets': len(self.right_parser.get_packets()),
            'total_expected_packets': len(self.left_parser.get_packets()) + len(self.right_parser.get_packets()),
            'left_netflows': len(left_flows),
            'right_netflows': len(right_flows),
            'total_expected_netflows': len(left_flows) + len(right_flows),
            'jitter_max': self.jitter_max
        }
        
        return stats
    
    def print_merge_info(self):
        """Print detailed information about the merge process."""
        stats = self.get_merge_statistics()
        if not stats:
            print("No merge statistics available")
            return
        
        print(f"\n{'='*80}")
        print(f"PCAP Merge Information")
        print(f"{'='*80}")
        print(f"Left PCAP:")
        print(f"  Packets: {stats['left_packets']}")
        print(f"  Netflows: {stats['left_netflows']}")
        
        print(f"Right PCAP:")
        print(f"  Packets: {stats['right_packets']}")
        print(f"  Netflows: {stats['right_netflows']}")
        
        print(f"Merge Settings:")
        print(f"  Jitter: ±{stats['jitter_max']} seconds")
        if self.ip_translation_range:
            print(f"  IP Translation Range: {self.ip_translation_range}")
        print(f"Expected Output:")
        print(f"  Total Packets: {stats['total_expected_packets']}")
        print(f"  Total Netflows: {stats['total_expected_netflows']}")
        
        print(f"{'='*80}\n")