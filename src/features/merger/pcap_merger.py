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
import pandas as pd
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
        self.left_labels = None  # DataFrame for left labels
        self.right_labels = None  # DataFrame for right labels
        self.left_time_offset = None  # Track time mapping for left PCAP
        self.right_time_offset = None  # Track time mapping for right PCAP
        self.packet_source_map = {}  # Map packet index to source ('left' or 'right')
        self.ip_translation_report = []  # Track all IP translations for reporting
        
    def _adjust_labels_for_merged_packets(self, merged_packets: List[Tuple[float, any]], output_labels_path: Optional[str] = None) -> Optional[pd.DataFrame]:
        """
        Create output labels DataFrame by transforming input labels according to IP and timestamp changes.
        
        Args:
            merged_packets: List of (timestamp, packet) tuples in chronological order
            output_labels_path: Optional path to save the output labels CSV
            
        Returns:
            Optional[pd.DataFrame]: Merged labels DataFrame, or None if no labels were provided
        """
        if self.left_labels is None and self.right_labels is None:
            return None
        
        merged_labels = []
        left_packets = self.left_parser.get_packets()
        right_packets = self.right_parser.get_packets()
        
        # Get time ranges for mapping
        left_timestamps = [float(pkt.time) for pkt in left_packets]
        right_timestamps = [float(pkt.time) for pkt in right_packets]
        
        left_start = min(left_timestamps) if left_timestamps else 0
        left_end = max(left_timestamps) if left_timestamps else 0
        left_duration = left_end - left_start if left_start != left_end else 1
        
        right_start = min(right_timestamps) if right_timestamps else 0
        right_end = max(right_timestamps) if right_timestamps else 0
        right_duration = right_end - right_start if right_start != right_end else 1
        
        merged_output_start = min(ts for ts, _ in merged_packets)
        
        # Process each merged packet
        for output_idx, (new_timestamp, pkt) in enumerate(merged_packets):
            # Find corresponding label and source
            label_row = None
            source = None
            
            # Try to find matching packet in original sequences
            for orig_idx, orig_pkt in enumerate(left_packets):
                if orig_pkt is pkt:
                    source = 'left'
                    if self.left_labels is not None and orig_idx < len(self.left_labels):
                        label_row = self.left_labels.iloc[orig_idx].copy()
                    break
            
            if source is None:
                for orig_idx, orig_pkt in enumerate(right_packets):
                    # Need to check if packet matches (compare content, not identity)
                    if self._packets_match(orig_pkt, pkt):
                        source = 'right'
                        if self.right_labels is not None and orig_idx < len(self.right_labels):
                            label_row = self.right_labels.iloc[orig_idx].copy()
                        break
            
            # Create output label entry
            if label_row is not None:
                label_row = dict(label_row)
            else:
                label_row = {}
            
            # Update timestamp
            label_row['timestamp'] = new_timestamp
            label_row['index'] = output_idx
            label_row['source'] = source
            
            # Update IP addresses if packet has IP layer and was translated
            if pkt.haslayer(IP):
                label_row['source_ip'] = pkt[IP].src
                label_row['destination_ip'] = pkt[IP].dst
            
            merged_labels.append(label_row)
        
        # Create DataFrame and save if output path provided
        output_df = pd.DataFrame(merged_labels)
        
        if output_labels_path:
            output_df.to_csv(output_labels_path, index=False)
            print(f"Merged labels exported to {output_labels_path}")
        
        return output_df
    
    def _packets_match(self, pkt1, pkt2) -> bool:
        """
        Check if two packets match based on content (after transformations).
        Simplified matching based on layer presence and basic fields.
        
        Args:
            pkt1: First packet
            pkt2: Second packet
            
        Returns:
            bool: Whether packets match
        """
        # Simple heuristic: compare packet length and layer types
        try:
            if len(pkt1) != len(pkt2):
                return False
            
            # Compare layer types
            if pkt1.layers() != pkt2.layers():
                return False
            
            return True
        except:
            return False

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
            
    def load_pcaps(self, left_pcap: str, right_pcap: str, left_labels: Optional[str] = None, right_labels: Optional[str] = None) -> bool:
        """
        Load both PCAP files and optional label CSV files.
        
        Args:
            left_pcap (str): Path to left PCAP file
            right_pcap (str): Path to right PCAP file
            left_labels (str, optional): Path to left labels CSV file
            right_labels (str, optional): Path to right labels CSV file
            
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
            
            # Load labels if provided
            if left_labels and os.path.exists(left_labels):
                try:
                    self.left_labels = pd.read_csv(left_labels)
                    print(f"Loaded {len(self.left_labels)} labels from left CSV: {left_labels}")
                except Exception as e:
                    print(f"Warning: Could not load left labels: {e}")
                    self.left_labels = None
            
            if right_labels and os.path.exists(right_labels):
                try:
                    self.right_labels = pd.read_csv(right_labels)
                    print(f"Loaded {len(self.right_labels)} labels from right CSV: {right_labels}")
                except Exception as e:
                    print(f"Warning: Could not load right labels: {e}")
                    self.right_labels = None
                
            # Initialize used IPs set with IPs from both PCAPs
            self._collect_used_ips()
                
            print(f"Loaded {len(left_packets)} packets from left PCAP")
            print(f"Loaded {len(right_packets)} packets from right PCAP")
            return True
            
        except Exception as e:
            print(f"Error loading PCAP files: {e}")
            return False
            
    def merge(self, output_path: str, output_labels_path: Optional[str] = None) -> bool:
        """
        Merge the loaded PCAP files with IP translation for malicious traffic.
        Optionally generates merged labels CSV if input labels were provided.
        
        Args:
            output_path (str): Path for the merged output file
            output_labels_path (str, optional): Path for merged output labels CSV
            
        Returns:
            bool: Success status
        """
        if not self.left_parser or not self.right_parser:
            print("Error: PCAP files not loaded")
            return False
            
        try:
            # Get all packets including non-IP packets
            left_packets = self.left_parser.get_packets()
            right_packets = self.right_parser.get_packets()
            
            if not left_packets or not right_packets:
                print("Error: No packets found in one or both PCAP files")
                return False
            
            # Calculate time ranges for both captures
            left_timestamps = [float(pkt.time) for pkt in left_packets]
            right_timestamps = [float(pkt.time) for pkt in right_packets]
            
            left_start = min(left_timestamps)
            left_end = max(left_timestamps)
            left_duration = left_end - left_start
            
            right_start = min(right_timestamps)
            right_end = max(right_timestamps)
            right_duration = right_end - right_start
            
            merged_packets = []
            packet_mapping = []  # Track (output_idx, source_idx, source_type)
            
            # Add all left (benign) packets with their original timestamps - keep intact
            print(f"Adding {len(left_packets)} benign packets with original timestamps")
            for idx, pkt in enumerate(left_packets):
                merged_packets.append((float(pkt.time), pkt))
                packet_mapping.append((len(merged_packets) - 1, idx, 'left'))
            
            # Process right (malicious) packets - map them into the benign timeline
            print(f"Mapping {len(right_packets)} malicious packets into benign timeline")
            
            for idx, pkt in enumerate(right_packets):
                # Create a copy of the packet for modification
                new_pkt = pkt.copy()
                
                # Apply IP translation if packet has IP layer and range is set
                if new_pkt.haslayer(IP):
                    original_src = new_pkt[IP].src
                    original_dst = new_pkt[IP].dst
                    
                    if self.ip_translation_range:
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
                            # Still track that IPs stayed the same
                            self._track_ip_translation(original_src, original_src)
                            self._track_ip_translation(original_dst, original_dst)
                    else:
                        # No translation range - track IPs as same
                        self._track_ip_translation(original_src, original_src)
                        self._track_ip_translation(original_dst, original_dst)
                
                # Map the malicious packet timestamp into the benign timeline
                # Calculate the relative position of this packet in the original malicious capture
                if right_duration > 0:
                    relative_position = (float(pkt.time) - right_start) / right_duration
                else:
                    relative_position = 0.5  # If single packet, place it in the middle
                
                # Map this position into the benign timeline (constrain to benign bounds)
                new_timestamp = left_start + (relative_position * left_duration)
                
                # Apply jitter if enabled (only to malicious packets)
                if self.jitter_max > 0:
                    jitter_range = min(self.jitter_max, left_duration * 0.01)  # Max 1% of total duration
                    jitter = random.uniform(-jitter_range, jitter_range)
                    new_timestamp += jitter
                
                # Ensure timestamp stays strictly within benign timeline bounds
                new_timestamp = max(left_start, min(left_end, new_timestamp))
                
                # Update the packet's timestamp
                new_pkt.time = new_timestamp
                merged_packets.append((new_timestamp, new_pkt))
                packet_mapping.append((len(merged_packets) - 1, idx, 'right'))
            
            # Sort all packets by timestamp to ensure proper chronological order
            merged_packets.sort(key=lambda x: x[0])
            
            # Update mapping indices after sorting
            sorted_mapping = [None] * len(merged_packets)
            for output_idx, (_, pkt) in enumerate(merged_packets):
                for map_idx, (orig_output_idx, src_idx, src_type) in enumerate(packet_mapping):
                    if orig_output_idx == map_idx:
                        sorted_mapping[output_idx] = (src_idx, src_type)
                        break
            
            # Resolve timestamp overlaps to ensure realistic timing
            print("Resolving timestamp overlaps...")
            resolved_packets = self._resolve_timestamp_overlaps(merged_packets)
            
            # Write merged PCAP with packets in chronological order
            # Update packet timestamps to ensure they're properly set
            final_packets = []
            for timestamp, pkt in resolved_packets:
                pkt.time = timestamp
                final_packets.append(pkt)
            
            wrpcap(output_path, final_packets)
            print(f"Successfully merged {len(final_packets)} packets in chronological order")
            
            # Generate merged labels if input labels were provided
            if self.left_labels is not None or self.right_labels is not None:
                output_labels = self._adjust_labels_for_merged_packets(resolved_packets, output_labels_path)
                if output_labels is not None:
                    print(f"Generated merged labels with {len(output_labels)} records")
            
            # Generate IP translation report (always done, even if no translations occurred)
            output_dir = os.path.dirname(output_path)
            output_base_name = os.path.splitext(os.path.basename(output_path))[0]
            report_path = self._generate_ip_translation_report(output_dir, output_base_name)
            if report_path:
                print(f"IP translation report saved: {report_path}")
            elif self.ip_translation_range:
                print(f"Note: No IP translations were needed (all IPs already in use or no conflicts)")
            else:
                print(f"Note: IP translation disabled (no translation range specified)")
            
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
    
    def _track_ip_translation(self, original_ip: str, translated_ip: str):
        """
        Track an IP translation in the report. Avoids duplicates.
        
        Args:
            original_ip (str): Original IP from malicious traffic
            translated_ip (str): IP it was translated to (or same IP if no translation)
        """
        if not any(entry['original_ip'] == original_ip for entry in self.ip_translation_report):
            self.ip_translation_report.append({
                'original_ip': original_ip,
                'translated_ip': translated_ip
            })
                
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
                # Track this translation for the report
                self._track_ip_translation(original_ip, ip_str)
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
        
    def _resolve_timestamp_overlaps(self, packets_with_timestamps: List[Tuple[float, any]]) -> List[Tuple[float, any]]:
        """
        Resolve timestamp overlaps by adding microsecond-level offsets to ensure unique timestamps.
        This handles both duplicates in original files and those created during merging.
        
        Args:
            packets_with_timestamps: List of (timestamp, packet) tuples (should be pre-sorted)
            
        Returns:
            List of (timestamp, packet) tuples with unique timestamps
        """
        if not packets_with_timestamps:
            return packets_with_timestamps
            
        resolved_packets = []
        overlap_count = 0
        
        # Minimum increment in seconds (10 microseconds for better separation)
        min_increment = 0.00001
        
        # Process packets sequentially, ensuring each timestamp is unique and strictly increasing
        for i, (timestamp, packet) in enumerate(packets_with_timestamps):
            if i == 0:
                # First packet keeps its timestamp
                resolved_packets.append((timestamp, packet))
            else:
                prev_timestamp = resolved_packets[-1][0]
                
                # Ensure this timestamp is strictly greater than the previous one
                # If there's any collision or if timestamps are too close, move it forward
                if timestamp <= prev_timestamp:
                    # Move to just after the previous timestamp
                    adjusted_timestamp = prev_timestamp + min_increment
                    overlap_count += 1
                else:
                    adjusted_timestamp = timestamp
                
                resolved_packets.append((adjusted_timestamp, packet))
        
        if overlap_count > 0:
            print(f"Resolved {overlap_count} timestamp overlaps with microsecond offsets")
            
        return resolved_packets
        
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
        
    def _generate_ip_translation_report(self, output_dir: str, base_name: str) -> Optional[str]:
        """
        Generate a CSV report of all IP translations from malicious traffic.
        Report is always created with proper headers, even if no translations occurred.
        
        Args:
            output_dir (str): Directory where the report will be saved
            base_name (str): Base name for the report file
            
        Returns:
            Optional[str]: Path to the generated report file, or None if there's an error
        """
        try:
            # Create report with structured format - always include headers
            report_data = self.ip_translation_report if self.ip_translation_report else []
            report_df = pd.DataFrame(report_data, columns=['original_ip', 'translated_ip'])
            report_path = os.path.join(output_dir, f"{base_name}_ip_translation_report.csv")
            report_df.to_csv(report_path, index=False)
            print(f"IP Translation Report generated: {report_path} ({len(report_data)} translations)")
            return report_path
        except Exception as e:
            print(f"Error generating IP translation report: {e}")
            return None

    def merge_pcaps(self, left_pcap: str, right_pcap: str, output_file: str, 
                    left_labels: Optional[str] = None, right_labels: Optional[str] = None,
                    output_labels: Optional[str] = None) -> bool:
        """
        Convenience method to load and merge PCAP files in one call.
        
        Args:
            left_pcap (str): Path to left PCAP file
            right_pcap (str): Path to right PCAP file
            output_file (str): Path for output merged PCAP file
            left_labels (str, optional): Path to left labels CSV file
            right_labels (str, optional): Path to right labels CSV file
            output_labels (str, optional): Path for output merged labels CSV file
            
        Returns:
            bool: Success status
        """
        if not self.load_pcaps(left_pcap, right_pcap, left_labels, right_labels):
            return False
        
        return self.merge(output_file, output_labels)

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
        if stats['jitter_max'] > 0:
            print(f"  Jitter: ±{stats['jitter_max']} seconds (applied to malicious traffic only)")
        else:
            print(f"  Jitter: Disabled")
        if self.ip_translation_range:
            print(f"  IP Translation Range: {self.ip_translation_range}")
        print(f"Expected Output:")
        print(f"  Total Packets: {stats['total_expected_packets']}")
        print(f"  Total Netflows: {stats['total_expected_netflows']}")
        
        print(f"{'='*80}\n")