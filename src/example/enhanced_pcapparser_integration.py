"""
Enhanced protocol detection methods for pcapparser using the centralized configuration.

This shows how to integrate the protocol_ports configuration with the existing
pcapparser class to provide more comprehensive protocol detection.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from configs.protocol_ports import *

# Import Scapy layers for packet analysis
try:
    from scapy.all import TCP, UDP, ICMP, DNS, ARP, Raw
except ImportError:
    # For demonstration purposes, create mock classes if scapy is not available
    class MockLayer:
        def __init__(self, name):
            self.name = name
    
    TCP = MockLayer("TCP")
    UDP = MockLayer("UDP")
    ICMP = MockLayer("ICMP")
    DNS = MockLayer("DNS")
    ARP = MockLayer("ARP")
    Raw = MockLayer("Raw")


def enhance_pcapparser_with_config(pcapparser_class):
    """
    Enhance the pcapparser class with centralized protocol configuration.
    This can be applied as a mixin or used to extend the existing class.
    """
    
    def filter_by_protocol_enhanced(self, protocol: str) -> list:
        """
        Enhanced protocol filtering using the centralized configuration.
        
        Args:
            protocol (str): Protocol name (e.g., 'HTTP', 'MYSQL', 'SSH')
            
        Returns:
            List: Packets matching the protocol
        """
        if not self._loaded:
            self.load()
        
        protocol = protocol.upper()
        filtered = []
        
        # Get expected ports for this protocol
        expected_ports = get_ports_for_protocol(protocol)
        transport_protocols = get_protocol_transport(protocol)
        
        for pkt in self.packets:
            packet_matches = False
            
            # Check by transport layer and ports
            if 'TCP' in transport_protocols and pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                if (tcp_layer.sport in expected_ports or 
                    tcp_layer.dport in expected_ports):
                    packet_matches = True
            
            if 'UDP' in transport_protocols and pkt.haslayer(UDP):
                udp_layer = pkt[UDP]
                if (udp_layer.sport in expected_ports or 
                    udp_layer.dport in expected_ports):
                    packet_matches = True
            
            # Special cases for protocols that need payload inspection
            if protocol == 'HTTP' and pkt.haslayer(Raw) and pkt.haslayer(TCP):
                try:
                    payload = str(pkt[Raw].load, 'utf-8', errors='ignore')
                    if any(method in payload for method in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HTTP/']):
                        packet_matches = True
                except:
                    pass
            
            elif protocol == 'DNS' and pkt.haslayer(DNS):
                packet_matches = True
            
            elif protocol == 'ARP' and pkt.haslayer(ARP):
                packet_matches = True
            
            elif protocol == 'ICMP' and pkt.haslayer(ICMP):
                packet_matches = True
            
            if packet_matches:
                filtered.append(pkt)
        
        return filtered
    
    def detect_protocols_in_traffic(self) -> dict:
        """
        Detect all protocols present in the traffic using the configuration.
        
        Returns:
            Dict: Protocol detection results with counts and details
        """
        if not self._loaded:
            self.load()
        
        protocol_stats = {}
        all_protocols = get_all_protocols()
        
        for protocol in all_protocols:
            matching_packets = self.filter_by_protocol_enhanced(protocol)
            if matching_packets:
                protocol_stats[protocol] = {
                    'packet_count': len(matching_packets),
                    'expected_ports': get_ports_for_protocol(protocol),
                    'transport_protocols': get_protocol_transport(protocol),
                    'uses_tcp': uses_tcp(protocol),
                    'uses_udp': uses_udp(protocol)
                }
        
        return protocol_stats
    
    def get_protocol_breakdown(self) -> dict:
        """
        Get a comprehensive breakdown of protocols in the PCAP.
        
        Returns:
            Dict: Detailed protocol analysis
        """
        if not self._loaded:
            self.load()
        
        breakdown = {
            'total_packets': len(self.packets),
            'protocols_detected': {},
            'transport_layer_stats': {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0},
            'port_usage': {},
            'protocol_summary': {}
        }
        
        # Analyze each packet
        for pkt in self.packets:
            # Transport layer statistics
            if pkt.haslayer(TCP):
                breakdown['transport_layer_stats']['TCP'] += 1
                self._analyze_ports(pkt[TCP], breakdown['port_usage'])
            elif pkt.haslayer(UDP):
                breakdown['transport_layer_stats']['UDP'] += 1
                self._analyze_ports(pkt[UDP], breakdown['port_usage'])
            elif pkt.haslayer(ICMP):
                breakdown['transport_layer_stats']['ICMP'] += 1
            else:
                breakdown['transport_layer_stats']['Other'] += 1
        
        # Detect protocols using configuration
        detected_protocols = self.detect_protocols_in_traffic()
        breakdown['protocols_detected'] = detected_protocols
        
        # Create summary
        breakdown['protocol_summary'] = {
            'total_protocols_detected': len(detected_protocols),
            'tcp_protocols': len([p for p in detected_protocols.keys() if uses_tcp(p)]),
            'udp_protocols': len([p for p in detected_protocols.keys() if uses_udp(p)]),
            'most_active_protocol': max(detected_protocols.keys(), 
                                      key=lambda x: detected_protocols[x]['packet_count']) 
                                    if detected_protocols else None
        }
        
        return breakdown
    
    def _analyze_ports(self, transport_layer, port_usage):
        """Helper method to analyze port usage."""
        sport = transport_layer.sport
        dport = transport_layer.dport
        
        for port in [sport, dport]:
            if port not in port_usage:
                port_usage[port] = {
                    'count': 0,
                    'protocols': get_protocols_for_port(port),
                    'category': get_port_category(port)
                }
            port_usage[port]['count'] += 1
    
    def filter_by_service_type(self, service_type: str) -> list:
        """
        Filter packets by service type (e.g., 'web', 'database', 'email').
        
        Args:
            service_type (str): Type of service to filter for
            
        Returns:
            List: Packets matching the service type
        """
        service_mappings = {
            'web': ['HTTP', 'HTTPS'],
            'database': ['MYSQL', 'POSTGRESQL', 'MSSQL', 'ORACLE', 'MONGODB', 'REDIS'],
            'email': ['SMTP', 'POP3', 'IMAP'],
            'file_transfer': ['FTP', 'FTPS', 'SFTP', 'TFTP'],
            'remote_access': ['SSH', 'TELNET', 'RDP', 'VNC'],
            'dns': ['DNS'],
            'voip': ['SIP', 'RTP'],
            'messaging': ['RABBITMQ', 'KAFKA', 'MQTT']
        }
        
        protocols = service_mappings.get(service_type.lower(), [])
        all_packets = []
        
        for protocol in protocols:
            packets = self.filter_by_protocol_enhanced(protocol)
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
        Perform security-focused analysis using protocol configuration.
        
        Returns:
            Dict: Security analysis results
        """
        if not self._loaded:
            self.load()
        
        analysis = {
            'unencrypted_protocols': {},
            'administrative_protocols': {},
            'database_protocols': {},
            'suspicious_ports': {},
            'security_recommendations': []
        }
        
        # Define security-sensitive protocol groups
        unencrypted = ['HTTP', 'FTP', 'TELNET', 'SMTP', 'POP3', 'IMAP']
        administrative = ['SSH', 'RDP', 'TELNET', 'SNMP']
        database = ['MYSQL', 'POSTGRESQL', 'MSSQL', 'ORACLE', 'MONGODB']
        
        # Analyze each group
        for protocol in unencrypted:
            packets = self.filter_by_protocol_enhanced(protocol)
            if packets:
                analysis['unencrypted_protocols'][protocol] = len(packets)
        
        for protocol in administrative:
            packets = self.filter_by_protocol_enhanced(protocol)
            if packets:
                analysis['administrative_protocols'][protocol] = len(packets)
        
        for protocol in database:
            packets = self.filter_by_protocol_enhanced(protocol)
            if packets:
                analysis['database_protocols'][protocol] = len(packets)
        
        # Generate recommendations
        if analysis['unencrypted_protocols']:
            analysis['security_recommendations'].append(
                "Unencrypted protocols detected. Consider using encrypted alternatives."
            )
        
        if 'TELNET' in analysis['administrative_protocols']:
            analysis['security_recommendations'].append(
                "TELNET detected. Replace with SSH for secure remote access."
            )
        
        if analysis['database_protocols']:
            analysis['security_recommendations'].append(
                "Database traffic detected. Ensure proper access controls and encryption."
            )
        
        return analysis
    
    # Add methods to the class
    pcapparser_class.filter_by_protocol_enhanced = filter_by_protocol_enhanced
    pcapparser_class.detect_protocols_in_traffic = detect_protocols_in_traffic
    pcapparser_class.get_protocol_breakdown = get_protocol_breakdown
    pcapparser_class._analyze_ports = _analyze_ports
    pcapparser_class.filter_by_service_type = filter_by_service_type
    pcapparser_class.get_security_analysis = get_security_analysis
    
    return pcapparser_class


def example_usage():
    """Example of how to use the enhanced functionality."""
    print("Enhanced PCAP Parser with Protocol Configuration")
    print("=" * 60)
    
    # This would be used with an actual pcapparser instance:
    # from classes.pcapparser import pcapparser
    # enhance_pcapparser_with_config(pcapparser)
    # 
    # parser = pcapparser("sample.pcap")
    # parser.load()
    # 
    # # Use enhanced methods
    # http_packets = parser.filter_by_protocol_enhanced('HTTP')
    # web_packets = parser.filter_by_service_type('web')
    # protocol_stats = parser.detect_protocols_in_traffic()
    # breakdown = parser.get_protocol_breakdown()
    # security_analysis = parser.get_security_analysis()
    
    print("Example usage patterns:")
    print("1. Enhanced protocol filtering:")
    print("   packets = parser.filter_by_protocol_enhanced('HTTP')")
    
    print("\n2. Service type filtering:")
    print("   web_packets = parser.filter_by_service_type('web')")
    print("   db_packets = parser.filter_by_service_type('database')")
    
    print("\n3. Protocol detection:")
    print("   protocols = parser.detect_protocols_in_traffic()")
    
    print("\n4. Comprehensive analysis:")
    print("   breakdown = parser.get_protocol_breakdown()")
    
    print("\n5. Security analysis:")
    print("   security_info = parser.get_security_analysis()")


if __name__ == "__main__":
    example_usage()