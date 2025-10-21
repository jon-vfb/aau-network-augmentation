

from scapy.all import *
from scapy.utils import rdpcap, wrpcap
import os
from typing import List, Optional, Union, Callable


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
        Filter packets by protocol.
        
        Args:
            protocol (str): Protocol name (e.g., 'TCP', 'UDP', 'ICMP', 'HTTP')
            
        Returns:
            List: Packets matching the protocol
        """
        if not self._loaded:
            self.load()
        
        protocol = protocol.upper()
        filtered = []
        
        for pkt in self.packets:
            if protocol == 'TCP' and pkt.haslayer(TCP):
                filtered.append(pkt)
            elif protocol == 'UDP' and pkt.haslayer(UDP):
                filtered.append(pkt)
            elif protocol == 'ICMP' and pkt.haslayer(ICMP):
                filtered.append(pkt)
            elif protocol == 'HTTP' and pkt.haslayer(Raw) and pkt.haslayer(TCP):
                # Simple HTTP detection
                payload = str(pkt[Raw].load)
                if 'HTTP' in payload or 'GET ' in payload or 'POST ' in payload:
                    filtered.append(pkt)
            elif protocol == 'DNS' and pkt.haslayer(DNS):
                filtered.append(pkt)
            elif protocol == 'ARP' and pkt.haslayer(ARP):
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