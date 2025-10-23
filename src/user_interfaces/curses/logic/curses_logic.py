import os
import sys
from typing import List, Optional, Dict, Any

# Add the src directory to the path to import pcapparser
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'src'))
from classes.pcapparser import pcapparser


class CursesLogic:
    """Handles all the business logic for the curses UI"""
    
    def __init__(self):
        self.parser: Optional[pcapparser] = None
        self.available_pcaps: List[str] = []
        self.current_pcap_path: Optional[str] = None
        self.current_pcap_info: Dict[str, Any] = {}
        self.netflows: List[Dict[str, Any]] = []
        self.selected_netflow: Optional[Dict[str, Any]] = None
        self.netflow_packets: List[Any] = []
        self.last_error: Optional[str] = None
        
    def scan_for_pcaps(self, samples_dir: str = None) -> List[str]:
        """Scan for available PCAP files"""
        if samples_dir is None:
            samples_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'samples')
        
        pcap_files = []
        if os.path.exists(samples_dir):
            for file in os.listdir(samples_dir):
                if file.endswith(('.pcap', '.pcapng')):
                    pcap_files.append(os.path.join(samples_dir, file))
        
        self.available_pcaps = pcap_files
        return pcap_files
    
    def load_pcap(self, pcap_path: str) -> bool:
        """Load a PCAP file and extract basic information"""
        try:
            self.parser = pcapparser(pcap_path)
            packets = self.parser.load()
            self.current_pcap_path = pcap_path
            
            # Extract basic info
            self.current_pcap_info = {
                'filename': os.path.basename(pcap_path),
                'total_packets': len(packets),
                'file_size': os.path.getsize(pcap_path),
                'protocols': self._get_protocols_summary(packets),
                'duration': self._get_duration(packets),
                'ip_addresses': self._get_ip_addresses(packets)
            }
            
            # Generate netflows
            self._generate_netflows()
            
            return True
        except Exception as e:
            # Store error message for UI to display
            self.last_error = f"Error loading PCAP: {e}"
            return False
    
    def _get_protocols_summary(self, packets) -> Dict[str, int]:
        """Get a summary of protocols in the PCAP"""
        protocols = {}
        for packet in packets:
            try:
                # Basic protocol detection
                if hasattr(packet, 'proto'):
                    proto = packet.proto
                elif hasattr(packet, 'protocol'):
                    proto = packet.protocol
                else:
                    proto = 'Unknown'
                
                protocols[proto] = protocols.get(proto, 0) + 1
            except:
                protocols['Unknown'] = protocols.get('Unknown', 0) + 1
        
        return protocols
    
    def _get_duration(self, packets) -> float:
        """Calculate the duration of the capture"""
        if len(packets) < 2:
            return 0.0
        
        try:
            first_time = packets[0].time if hasattr(packets[0], 'time') else 0
            last_time = packets[-1].time if hasattr(packets[-1], 'time') else 0
            return float(last_time - first_time)
        except:
            return 0.0
    
    def _get_ip_addresses(self, packets) -> Dict[str, int]:
        """Get unique IP addresses and their packet counts"""
        ip_addresses = {}
        for packet in packets:
            try:
                # Try to extract source and destination IPs
                src_ip = getattr(packet, 'src', None)
                dst_ip = getattr(packet, 'dst', None)
                
                if src_ip:
                    ip_addresses[src_ip] = ip_addresses.get(src_ip, 0) + 1
                if dst_ip:
                    ip_addresses[dst_ip] = ip_addresses.get(dst_ip, 0) + 1
            except:
                continue
                
        return ip_addresses
    
    def _generate_netflows(self):
        """Generate netflows from the loaded PCAP"""
        if not self.parser:
            return
        
        packets = self.parser.get_packets()
        flows = {}
        
        for i, packet in enumerate(packets):
            try:
                # Extract flow key (src_ip, dst_ip, src_port, dst_port, protocol)
                src_ip = getattr(packet, 'src', 'Unknown')
                dst_ip = getattr(packet, 'dst', 'Unknown')
                src_port = getattr(packet, 'sport', 0)
                dst_port = getattr(packet, 'dport', 0)
                protocol = getattr(packet, 'proto', 'Unknown')
                
                # Create bidirectional flow key
                flow_key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]) + [protocol])
                
                if flow_key not in flows:
                    flows[flow_key] = {
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'protocol': protocol,
                        'packet_count': 0,
                        'packet_indices': [],
                        'first_seen': getattr(packet, 'time', 0),
                        'last_seen': getattr(packet, 'time', 0),
                        'bytes_transferred': 0
                    }
                
                flow = flows[flow_key]
                flow['packet_count'] += 1
                flow['packet_indices'].append(i)
                flow['last_seen'] = getattr(packet, 'time', flow['last_seen'])
                flow['bytes_transferred'] += len(getattr(packet, 'load', b''))
                
            except Exception as e:
                continue
        
        # Convert to list and sort by packet count
        self.netflows = sorted(flows.values(), key=lambda x: x['packet_count'], reverse=True)
    
    def get_pcap_info(self) -> Dict[str, Any]:
        """Get information about the currently loaded PCAP"""
        return self.current_pcap_info
    
    def get_netflows(self) -> List[Dict[str, Any]]:
        """Get the list of netflows"""
        return self.netflows
    
    def select_netflow(self, index: int) -> bool:
        """Select a netflow and load its packets"""
        if 0 <= index < len(self.netflows):
            self.selected_netflow = self.netflows[index]
            self._load_netflow_packets()
            return True
        return False
    
    def _load_netflow_packets(self):
        """Load packets for the selected netflow"""
        if not self.selected_netflow or not self.parser:
            return
        
        all_packets = self.parser.get_packets()
        self.netflow_packets = [
            all_packets[i] for i in self.selected_netflow['packet_indices']
            if i < len(all_packets)
        ]
    
    def get_netflow_packets(self) -> List[Any]:
        """Get packets for the selected netflow"""
        return self.netflow_packets
    
    def get_selected_netflow_info(self) -> Optional[Dict[str, Any]]:
        """Get information about the selected netflow"""
        return self.selected_netflow
    
    def format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def format_duration(self, duration: float) -> str:
        """Format duration in human readable format"""
        if duration < 60:
            return f"{duration:.2f}s"
        elif duration < 3600:
            return f"{int(duration // 60)}m {duration % 60:.1f}s"
        else:
            hours = int(duration // 3600)
            minutes = int((duration % 3600) // 60)
            seconds = duration % 60
            return f"{hours}h {minutes}m {seconds:.1f}s"
    
    def get_last_error(self) -> Optional[str]:
        """Get the last error message"""
        return self.last_error
