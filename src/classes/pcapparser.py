

from scapy.all import *
from scapy.utils import rdpcap, wrpcap
# Explicit imports to ensure layer classes are available
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
from scapy.packet import Raw
import os
import sys
from typing import List, Optional, Union, Callable

# Import the centralized protocol-ports configuration
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from configs.protocol_ports import (
    get_ports_for_protocol, get_protocols_for_port, get_primary_port,
    uses_tcp, uses_udp, get_protocol_transport, get_protocol_info,
    is_well_known_port, get_port_category, validate_port
)


class pcapparser:
    def __init__(self, filename: str):
        """
        Initialize the PCAP parser with a filename.
        
        Args:
            filename (str): Path to the PCAP file
        """
        self.filename = filename
        self.packets = []
        self._loaded = False
    
    def load(self) -> List:
        """
        Load packets from the PCAP file.
        
        Returns:
            List: List of loaded packets
        """
        try:
            self.packets = rdpcap(self.filename)
            self._loaded = True
            return self.packets
        except Exception as e:
            print(f"Error loading PCAP file: {e}")
            return []
    
    def parse(self) -> List:
        """
        Parse the PCAP file and return packets.
        
        Returns:
            List: List of parsed packets
        """
        if not self._loaded:
            return self.load()
        return self.packets
    
    def get_packets(self) -> List:
        """
        Get all packets from the PCAP file.
        
        Returns:
            List: List of packets
        """
        if not self._loaded:
            self.load()
        return self.packets
    
    def get_packet_count(self) -> int:
        """
        Get the total number of packets.
        
        Returns:
            int: Number of packets
        """
        if not self._loaded:
            self.load()
        return len(self.packets)
    
    def get_packet(self, index: int):
        """
        Get a specific packet by index.
        
        Args:
            index (int): Index of the packet
            
        Returns:
            Packet or None: The packet at the specified index
        """
        if not self._loaded:
            self.load()
        
        if 0 <= index < len(self.packets):
            return self.packets[index]
        return None
    
    def filter_packets(self, filter_func: Callable) -> List:
        """
        Filter packets based on a custom function.
        
        Args:
            filter_func (Callable): Function that takes a packet and returns bool
            
        Returns:
            List: Filtered packets
        """
        if not self._loaded:
            self.load()
        
        return [pkt for pkt in self.packets if filter_func(pkt)]
    
    def filter_by_protocol(self, protocol: str) -> List:
        """
        Filter packets by protocol using centralized configuration.
        
        Args:
            protocol (str): Protocol name (e.g., 'TCP', 'UDP', 'ICMP', 'HTTP', 'SSH', 'MYSQL')
            
        Returns:
            List: Packets matching the protocol
        """
        if not self._loaded:
            self.load()
        
        protocol = protocol.upper()
        filtered = []
        
        # Handle transport layer protocols directly
        if protocol in ['TCP', 'UDP', 'ICMP', 'ARP']:
            for pkt in self.packets:
                if protocol == 'TCP' and pkt.haslayer(TCP):
                    filtered.append(pkt)
                elif protocol == 'UDP' and pkt.haslayer(UDP):
                    filtered.append(pkt)
                elif protocol == 'ICMP' and pkt.haslayer(ICMP):
                    filtered.append(pkt)
                elif protocol == 'ARP' and pkt.haslayer(ARP):
                    filtered.append(pkt)
        else:
            # Use configuration-based protocol detection
            expected_ports = get_ports_for_protocol(protocol)
            transport_protocols = get_protocol_transport(protocol)
            
            if not expected_ports:
                # Fallback to legacy detection for unknown protocols
                return self._legacy_protocol_filter(protocol)
            
            for pkt in self.packets:
                packet_matches = False
                
                # Check TCP packets
                if 'TCP' in transport_protocols and pkt.haslayer(TCP):
                    tcp_layer = pkt[TCP]
                    if tcp_layer.sport in expected_ports or tcp_layer.dport in expected_ports:
                        packet_matches = True
                
                # Check UDP packets  
                if 'UDP' in transport_protocols and pkt.haslayer(UDP):
                    udp_layer = pkt[UDP]
                    if udp_layer.sport in expected_ports or udp_layer.dport in expected_ports:
                        packet_matches = True
                
                # Special payload-based detection for certain protocols
                if protocol in ['HTTP', 'HTTPS'] and pkt.haslayer(Raw) and pkt.haslayer(TCP):
                    try:
                        payload = str(pkt[Raw].load, 'utf-8', errors='ignore')
                        if any(method in payload for method in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HTTP/']):
                            packet_matches = True
                    except:
                        pass
                
                elif protocol == 'DNS' and pkt.haslayer(DNS):
                    packet_matches = True
                
                if packet_matches:
                    filtered.append(pkt)
        
        return filtered
    
    def _legacy_protocol_filter(self, protocol: str) -> List:
        """
        Legacy protocol filtering for protocols not in configuration.
        
        Args:
            protocol (str): Protocol name
            
        Returns:
            List: Filtered packets
        """
        filtered = []
        for pkt in self.packets:
            if protocol == 'HTTP' and pkt.haslayer(Raw) and pkt.haslayer(TCP):
                try:
                    payload = str(pkt[Raw].load, 'utf-8', errors='ignore')
                    if 'HTTP' in payload or 'GET ' in payload or 'POST ' in payload:
                        filtered.append(pkt)
                except:
                    pass
            elif protocol == 'DNS' and pkt.haslayer(DNS):
                filtered.append(pkt)
        
        return filtered
    
    def filter_by_ip(self, ip_address: str, direction: str = 'both') -> List:
        """
        Filter packets by IP address.
        
        Args:
            ip_address (str): IP address to filter by
            direction (str): 'src', 'dst', or 'both'
            
        Returns:
            List: Packets matching the IP filter
        """
        if not self._loaded:
            self.load()
        
        filtered = []
        for pkt in self.packets:
            if pkt.haslayer(IP):
                ip_layer = pkt[IP]
                if direction == 'src' and ip_layer.src == ip_address:
                    filtered.append(pkt)
                elif direction == 'dst' and ip_layer.dst == ip_address:
                    filtered.append(pkt)
                elif direction == 'both' and (ip_layer.src == ip_address or ip_layer.dst == ip_address):
                    filtered.append(pkt)
        
        return filtered
    
    def filter_by_port(self, port: int, direction: str = 'both') -> List:
        """
        Filter packets by port number.
        
        Args:
            port (int): Port number to filter by
            direction (str): 'src', 'dst', or 'both'
            
        Returns:
            List: Packets matching the port filter
        """
        if not self._loaded:
            self.load()
        
        filtered = []
        for pkt in self.packets:
            if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                transport_layer = pkt[TCP] if pkt.haslayer(TCP) else pkt[UDP]
                if direction == 'src' and transport_layer.sport == port:
                    filtered.append(pkt)
                elif direction == 'dst' and transport_layer.dport == port:
                    filtered.append(pkt)
                elif direction == 'both' and (transport_layer.sport == port or transport_layer.dport == port):
                    filtered.append(pkt)
        
        return filtered
    
    def inject_packet(self, packet, index: Optional[int] = None) -> bool:
        """
        Inject a packet into the packet list.
        
        Args:
            packet: Scapy packet to inject
            index (Optional[int]): Index to insert at (None for append)
            
        Returns:
            bool: Success status
        """
        if not self._loaded:
            self.load()
        
        try:
            if index is None:
                self.packets.append(packet)
            else:
                self.packets.insert(index, packet)
            return True
        except Exception as e:
            print(f"Error injecting packet: {e}")
            return False
    
    def remove_packet(self, index: int) -> bool:
        """
        Remove a packet by index.
        
        Args:
            index (int): Index of packet to remove
            
        Returns:
            bool: Success status
        """
        if not self._loaded:
            self.load()
        
        try:
            if 0 <= index < len(self.packets):
                del self.packets[index]
                return True
            return False
        except Exception as e:
            print(f"Error removing packet: {e}")
            return False
    
    def remove_packets(self, indices: List[int]) -> int:
        """
        Remove multiple packets by indices.
        
        Args:
            indices (List[int]): List of indices to remove
            
        Returns:
            int: Number of packets successfully removed
        """
        if not self._loaded:
            self.load()
        
        # Sort indices in descending order to avoid index shifting issues
        indices = sorted(set(indices), reverse=True)
        removed_count = 0
        
        for index in indices:
            if self.remove_packet(index):
                removed_count += 1
        
        return removed_count
    
    def modify_packet(self, index: int, modifier_func: Callable) -> bool:
        """
        Modify a packet using a custom function.
        
        Args:
            index (int): Index of packet to modify
            modifier_func (Callable): Function that takes a packet and returns modified packet
            
        Returns:
            bool: Success status
        """
        if not self._loaded:
            self.load()
        
        try:
            if 0 <= index < len(self.packets):
                self.packets[index] = modifier_func(self.packets[index])
                return True
            return False
        except Exception as e:
            print(f"Error modifying packet: {e}")
            return False
    
    def save(self, filename: Optional[str] = None) -> bool:
        """
        Save packets to a PCAP file.
        
        Args:
            filename (Optional[str]): Output filename (defaults to original filename)
            
        Returns:
            bool: Success status
        """
        if not self._loaded:
            self.load()
        
        output_file = filename or self.filename
        
        try:
            wrpcap(output_file, self.packets)
            return True
        except Exception as e:
            print(f"Error saving PCAP file: {e}")
            return False
    
    def save_filtered(self, packets: List, filename: str) -> bool:
        """
        Save filtered packets to a new PCAP file.
        
        Args:
            packets (List): List of packets to save
            filename (str): Output filename
            
        Returns:
            bool: Success status
        """
        try:
            wrpcap(filename, packets)
            return True
        except Exception as e:
            print(f"Error saving filtered PCAP file: {e}")
            return False
    
    def get_summary(self) -> dict:
        """
        Get a summary of the PCAP file.
        
        Returns:
            dict: Summary information
        """
        if not self._loaded:
            self.load()
        
        summary = {
            'total_packets': len(self.packets),
            'protocols': {},
            'unique_ips': set(),
            'unique_ports': set(),
            'file_size': os.path.getsize(self.filename) if os.path.exists(self.filename) else 0
        }
        
        for pkt in self.packets:
            # Protocol analysis
            if pkt.haslayer(TCP):
                summary['protocols']['TCP'] = summary['protocols'].get('TCP', 0) + 1
                summary['unique_ports'].add(pkt[TCP].sport)
                summary['unique_ports'].add(pkt[TCP].dport)
            if pkt.haslayer(UDP):
                summary['protocols']['UDP'] = summary['protocols'].get('UDP', 0) + 1
                summary['unique_ports'].add(pkt[UDP].sport)
                summary['unique_ports'].add(pkt[UDP].dport)
            if pkt.haslayer(ICMP):
                summary['protocols']['ICMP'] = summary['protocols'].get('ICMP', 0) + 1
            if pkt.haslayer(ARP):
                summary['protocols']['ARP'] = summary['protocols'].get('ARP', 0) + 1
            if pkt.haslayer(DNS):
                summary['protocols']['DNS'] = summary['protocols'].get('DNS', 0) + 1
            
            # IP analysis
            if pkt.haslayer(IP):
                summary['unique_ips'].add(pkt[IP].src)
                summary['unique_ips'].add(pkt[IP].dst)
        
        # Convert sets to counts
        summary['unique_ips'] = len(summary['unique_ips'])
        summary['unique_ports'] = len(summary['unique_ports'])
        
        return summary
    
    def print_summary(self):
        """Print a formatted summary of the PCAP file."""
        summary = self.get_summary()
        
        print(f"\n{'='*50}")
        print(f"PCAP File Summary: {os.path.basename(self.filename)}")
        print(f"{'='*50}")
        print(f"Total Packets: {summary['total_packets']}")
        print(f"File Size: {summary['file_size']} bytes")
        print(f"Unique IPs: {summary['unique_ips']}")
        print(f"Unique Ports: {summary['unique_ports']}")
        print(f"\nProtocol Distribution:")
        for protocol, count in summary['protocols'].items():
            percentage = (count / summary['total_packets']) * 100
            print(f"  {protocol}: {count} ({percentage:.1f}%)")
        print(f"{'='*50}\n")
    
    def inspect_packet(self, index: int, detailed: bool = False):
        """
        Inspect a specific packet.
        
        Args:
            index (int): Index of packet to inspect
            detailed (bool): Show detailed packet information
        """
        packet = self.get_packet(index)
        if packet:
            if detailed:
                packet.show()
            else:
                print(f"Packet {index}: {packet.summary()}")
        else:
            print(f"Packet at index {index} not found")
    
    def search_packets(self, search_term: str, case_sensitive: bool = False) -> List[int]:
        """
        Search for packets containing a specific string in their payload.
        
        Args:
            search_term (str): String to search for
            case_sensitive (bool): Whether search should be case sensitive
            
        Returns:
            List[int]: Indices of matching packets
        """
        if not self._loaded:
            self.load()
        
        matching_indices = []
        
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(Raw):
                payload = str(pkt[Raw].load)
                if not case_sensitive:
                    payload = payload.lower()
                    search_term = search_term.lower()
                
                if search_term in payload:
                    matching_indices.append(i)
        
        return matching_indices
    
    def get_netflows(self) -> List[dict]:
        """
        Identify and return unique network flows from the packets.
        A netflow is defined by: src_ip, dst_ip, src_port, dst_port, protocol
        
        Returns:
            List[dict]: List of unique netflows with their characteristics and packet count
        """
        if not self._loaded:
            self.load()
        
        flows = {}
        
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(IP):
                ip_layer = pkt[IP]
                flow_key = None
                protocol = None
                src_port = dst_port = None
                
                # Extract protocol and ports
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
                    src_port = dst_port = 0  # ICMP doesn't have ports
                else:
                    protocol = str(ip_layer.proto)
                    src_port = dst_port = 0
                
                # Create flow key (unidirectional - matches Cisco NetFlow standard)
                # A flow from A->B is different from B->A
                flow_key = (ip_layer.src, src_port, ip_layer.dst, dst_port, protocol)
                
                if flow_key not in flows:
                    flows[flow_key] = {
                        'src_ip': ip_layer.src,
                        'src_port': src_port,
                        'dst_ip': ip_layer.dst,
                        'dst_port': dst_port,
                        'protocol': protocol,
                        'packet_count': 0,
                        'packet_indices': [],
                        'first_seen': i,
                        'last_seen': i,
                        'bytes_total': 0
                    }
                
                # Update flow statistics
                flows[flow_key]['packet_count'] += 1
                flows[flow_key]['packet_indices'].append(i)
                flows[flow_key]['last_seen'] = i
                flows[flow_key]['bytes_total'] += len(pkt)
        
        return list(flows.values())
    
    def get_packets_by_netflow(self, netflow: dict) -> List:
        """
        Get all packets belonging to a specific netflow.
        
        Args:
            netflow (dict): Netflow dictionary (from get_netflows())
            
        Returns:
            List: Packets belonging to the specified netflow
        """
        if not self._loaded:
            self.load()
        
        if 'packet_indices' not in netflow:
            return []
        
        packets = []
        for index in netflow['packet_indices']:
            if 0 <= index < len(self.packets):
                packets.append(self.packets[index])
        
        return packets
    
    def filter_netflows(self, min_packets: int = 1, protocol: Optional[str] = None, 
                       src_ip: Optional[str] = None, dst_ip: Optional[str] = None) -> List[dict]:
        """
        Filter netflows based on various criteria.
        
        Args:
            min_packets (int): Minimum number of packets in flow
            protocol (Optional[str]): Filter by protocol (TCP, UDP, ICMP, etc.)
            src_ip (Optional[str]): Filter by source IP
            dst_ip (Optional[str]): Filter by destination IP
            
        Returns:
            List[dict]: Filtered netflows
        """
        flows = self.get_netflows()
        filtered = []
        
        for flow in flows:
            # Apply filters
            if flow['packet_count'] < min_packets:
                continue
            if protocol and flow['protocol'].upper() != protocol.upper():
                continue
            if src_ip and flow['src_ip'] != src_ip and flow['dst_ip'] != src_ip:
                continue
            if dst_ip and flow['src_ip'] != dst_ip and flow['dst_ip'] != dst_ip:
                continue
            
            filtered.append(flow)
        
        return filtered
    
    def print_netflows(self, flows: Optional[List[dict]] = None, limit: int = 20):
        """
        Print a formatted list of netflows.
        
        Args:
            flows (Optional[List[dict]]): Flows to print (defaults to all flows)
            limit (int): Maximum number of flows to display
        """
        if flows is None:
            flows = self.get_netflows()
        
        # Sort by packet count (descending)
        flows = sorted(flows, key=lambda x: x['packet_count'], reverse=True)
        
        print(f"\n{'='*100}")
        print(f"Network Flows Summary ({len(flows)} total flows)")
        print(f"{'='*100}")
        print(f"{'#':<3} {'Src IP':<15} {'Src Port':<8} {'Dst IP':<15} {'Dst Port':<8} {'Protocol':<8} {'Packets':<8} {'Bytes':<10}")
        print(f"{'-'*100}")
        
        for i, flow in enumerate(flows[:limit]):
            print(f"{i+1:<3} {flow['src_ip']:<15} {flow['src_port']:<8} {flow['dst_ip']:<15} "
                  f"{flow['dst_port']:<8} {flow['protocol']:<8} {flow['packet_count']:<8} {flow['bytes_total']:<10}")
        
        if len(flows) > limit:
            print(f"\n... and {len(flows) - limit} more flows")
        print(f"{'='*100}\n")
    
    def detect_protocols_in_traffic(self) -> dict:
        """
        Detect all protocols present in the traffic using the centralized configuration.
        
        Returns:
            Dict: Protocol detection results with counts and details
        """
        if not self._loaded:
            self.load()
        
        protocol_stats = {}
        
        # Check for common application protocols using port-based detection
        from configs.protocol_ports import get_all_protocols
        
        for protocol in get_all_protocols():
            matching_packets = self.filter_by_protocol(protocol)
            if matching_packets:
                protocol_stats[protocol] = {
                    'packet_count': len(matching_packets),
                    'expected_ports': get_ports_for_protocol(protocol),
                    'transport_protocols': get_protocol_transport(protocol),
                    'uses_tcp': uses_tcp(protocol),
                    'uses_udp': uses_udp(protocol)
                }
        
        return protocol_stats
    
    def get_enhanced_summary(self) -> dict:
        """
        Get an enhanced summary using the protocol configuration.
        
        Returns:
            dict: Enhanced summary information
        """
        if not self._loaded:
            self.load()
        
        summary = {
            'total_packets': len(self.packets),
            'protocols': {},
            'application_protocols': {},
            'unique_ips': set(),
            'unique_ports': set(),
            'port_analysis': {},
            'file_size': os.path.getsize(self.filename) if os.path.exists(self.filename) else 0
        }
        
        for pkt in self.packets:
            # Transport layer analysis
            if pkt.haslayer(TCP):
                summary['protocols']['TCP'] = summary['protocols'].get('TCP', 0) + 1
                summary['unique_ports'].add(pkt[TCP].sport)
                summary['unique_ports'].add(pkt[TCP].dport)
                self._analyze_port(pkt[TCP].sport, summary['port_analysis'])
                self._analyze_port(pkt[TCP].dport, summary['port_analysis'])
            if pkt.haslayer(UDP):
                summary['protocols']['UDP'] = summary['protocols'].get('UDP', 0) + 1
                summary['unique_ports'].add(pkt[UDP].sport)
                summary['unique_ports'].add(pkt[UDP].dport)
                self._analyze_port(pkt[UDP].sport, summary['port_analysis'])
                self._analyze_port(pkt[UDP].dport, summary['port_analysis'])
            if pkt.haslayer(ICMP):
                summary['protocols']['ICMP'] = summary['protocols'].get('ICMP', 0) + 1
            if pkt.haslayer(ARP):
                summary['protocols']['ARP'] = summary['protocols'].get('ARP', 0) + 1
            if pkt.haslayer(DNS):
                summary['protocols']['DNS'] = summary['protocols'].get('DNS', 0) + 1
            
            # IP analysis
            if pkt.haslayer(IP):
                summary['unique_ips'].add(pkt[IP].src)
                summary['unique_ips'].add(pkt[IP].dst)
        
        # Detect application protocols
        summary['application_protocols'] = self.detect_protocols_in_traffic()
        
        # Convert sets to counts
        summary['unique_ips'] = len(summary['unique_ips'])
        summary['unique_ports'] = len(summary['unique_ports'])
        
        return summary
    
    def _analyze_port(self, port: int, port_analysis: dict):
        """
        Analyze a port using the configuration.
        
        Args:
            port (int): Port number to analyze
            port_analysis (dict): Dictionary to store analysis results
        """
        if port not in port_analysis:
            port_analysis[port] = {
                'count': 0,
                'protocols': get_protocols_for_port(port),
                'category': get_port_category(port),
                'well_known': is_well_known_port(port)
            }
        port_analysis[port]['count'] += 1
    
    def filter_by_service_type(self, service_type: str) -> List:
        """
        Filter packets by service type using the configuration.
        
        Args:
            service_type (str): Type of service ('web', 'database', 'email', etc.)
            
        Returns:
            List: Packets matching the service type
        """
        service_mappings = {
            'web': ['HTTP', 'HTTPS', 'APACHE', 'NGINX'],
            'database': ['MYSQL', 'POSTGRESQL', 'MSSQL', 'ORACLE', 'MONGODB', 'REDIS'],
            'email': ['SMTP', 'POP3', 'IMAP'],
            'file_transfer': ['FTP', 'FTPS', 'SFTP', 'TFTP'],
            'remote_access': ['SSH', 'TELNET', 'RDP', 'VNC'],
            'dns': ['DNS'],
            'voip': ['SIP', 'RTP'],
            'messaging': ['RABBITMQ', 'KAFKA', 'MQTT'],
            'monitoring': ['SNMP', 'SYSLOG', 'GRAFANA', 'PROMETHEUS'],
            'development': ['DJANGO', 'FLASK', 'NODE', 'RAILS'],
            'container': ['DOCKER', 'KUBERNETES']
        }
        
        protocols = service_mappings.get(service_type.lower(), [])
        all_packets = []
        
        for protocol in protocols:
            packets = self.filter_by_protocol(protocol)
            all_packets.extend(packets)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_packets = []
        for pkt in all_packets:
            pkt_id = id(pkt)
            if pkt_id not in seen:
                seen.add(pkt_id)
                unique_packets.append(pkt)
        
        return unique_packets
    
    def get_security_analysis(self) -> dict:
        """
        Perform security analysis using the protocol configuration.
        
        Returns:
            Dict: Security analysis results
        """
        if not self._loaded:
            self.load()
        
        analysis = {
            'unencrypted_protocols': {},
            'administrative_protocols': {},
            'database_protocols': {},
            'high_risk_ports': {},
            'security_recommendations': []
        }
        
        # Define security-sensitive protocol groups
        unencrypted = ['HTTP', 'FTP', 'TELNET', 'SMTP', 'POP3', 'IMAP']
        administrative = ['SSH', 'RDP', 'TELNET', 'SNMP']
        database = ['MYSQL', 'POSTGRESQL', 'MSSQL', 'ORACLE', 'MONGODB']
        
        # Analyze each group
        for protocol in unencrypted:
            packets = self.filter_by_protocol(protocol)
            if packets:
                analysis['unencrypted_protocols'][protocol] = len(packets)
        
        for protocol in administrative:
            packets = self.filter_by_protocol(protocol)
            if packets:
                analysis['administrative_protocols'][protocol] = len(packets)
        
        for protocol in database:
            packets = self.filter_by_protocol(protocol)
            if packets:
                analysis['database_protocols'][protocol] = len(packets)
        
        # Generate security recommendations
        if analysis['unencrypted_protocols']:
            analysis['security_recommendations'].append(
                "Unencrypted protocols detected. Consider using encrypted alternatives (HTTPS, FTPS, SSH, etc.)"
            )
        
        if 'TELNET' in analysis['administrative_protocols']:
            analysis['security_recommendations'].append(
                "TELNET detected. Replace with SSH for secure remote access."
            )
        
        if analysis['database_protocols']:
            analysis['security_recommendations'].append(
                "Database traffic detected. Ensure proper access controls and encryption."
            )
        
        # Check for non-standard ports
        enhanced_summary = self.get_enhanced_summary()
        for port, info in enhanced_summary.get('port_analysis', {}).items():
            if not info['protocols'] and info['count'] > 10:  # High traffic on unknown ports
                analysis['high_risk_ports'][port] = {
                    'count': info['count'],
                    'category': info['category'],
                    'reason': 'High traffic on unassigned port'
                }
        
        return analysis
    
    def get_ip_range(self) -> Optional[str]:
        """
        Extract the most common IP range from the PCAP file.
        Returns a CIDR notation string representing the primary network range.
        
        Returns:
            Optional[str]: IP range in CIDR notation (e.g., '192.168.1.0/24') or None if no IPs found
        """
        if not self._loaded:
            self.load()
        
        from ipaddress import ip_address, ip_network, IPv4Address
        
        ip_list = []
        
        # Collect all unique IPs (both source and destination)
        for pkt in self.packets:
            if pkt.haslayer(IP):
                try:
                    src = str(pkt[IP].src)
                    dst = str(pkt[IP].dst)
                    src_ip = ip_address(src)
                    dst_ip = ip_address(dst)
                    
                    # Only consider IPv4 addresses that are not loopback
                    if isinstance(src_ip, IPv4Address) and not src_ip.is_loopback:
                        ip_list.append(src)
                    if isinstance(dst_ip, IPv4Address) and not dst_ip.is_loopback:
                        ip_list.append(dst)
                except:
                    continue
        
        if not ip_list:
            return None
        
        # Remove duplicates and sort for processing
        ip_set = sorted(set(ip_list))
        
        # Try to find the best network that covers the most IPs
        # Start with smaller subnets and work our way up
        best_network = None
        best_coverage = 0
        
        for prefix_len in range(24, 15, -1):  # /24 down to /16
            for ip_str in ip_set:
                try:
                    # Create network from this IP with the prefix length
                    test_network = ip_network(f"{ip_str}/{prefix_len}", strict=False)
                    
                    # Count how many IPs from our set fall in this network
                    coverage = sum(1 for ip in ip_set if ip_address(ip) in test_network)
                    
                    # Keep track of the network with best coverage
                    if coverage > best_coverage:
                        best_network = test_network
                        best_coverage = coverage
                except:
                    continue
        
        # If we found a network covering at least one IP, return it
        # Otherwise fallback to just creating a /24 from the first IP
        if best_network:
            return str(best_network)
        
        # Fallback: if no good network found, create /24 from first IP
        try:
            fallback_network = ip_network(f"{ip_set[0]}/24", strict=False)
            return str(fallback_network)
        except:
            return None