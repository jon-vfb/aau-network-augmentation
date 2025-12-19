import os
import sys
from typing import List, Optional, Dict, Any
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Add the src directory to the path to import pcapparser
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'src'))
from classes.pcapparser import pcapparser
from features.augmentations import merge_augmentation, attack_and_merge_augmentation, InputValidator
from features.attacks import get_available_attacks, get_attack_instance


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
        
        # Augmentation state
        self.augmentation_state: Dict[str, Any] = {}
        self.augmentation_results: Optional[Dict[str, Any]] = None
        
        # Attack augmentation state
        self.attack_config_state: Dict[str, Any] = {}
        
    def scan_for_pcaps(self, samples_dir: str = None, folder_type: str = None) -> List[str]:
        """
        Scan for available PCAP files in samples/malicious and samples/benign
        
        Args:
            samples_dir: Optional custom samples directory path
            folder_type: Optional filter - 'malicious', 'benign', or None (both)
        """
        if samples_dir is None:
            samples_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'samples')
        
        pcap_files = []
        
        # Scan malicious folder (unless filtered to benign only)
        if folder_type != 'benign':
            malicious_dir = os.path.join(samples_dir, 'malicious')
            if os.path.exists(malicious_dir):
                for file in os.listdir(malicious_dir):
                    if file.endswith(('.pcap', '.pcapng')):
                        pcap_files.append(os.path.join(malicious_dir, file))
        
        # Scan benign folder (unless filtered to malicious only)
        if folder_type != 'malicious':
            benign_dir = os.path.join(samples_dir, 'benign')
            if os.path.exists(benign_dir):
                for file in os.listdir(benign_dir):
                    if file.endswith(('.pcap', '.pcapng')):
                        pcap_files.append(os.path.join(benign_dir, file))
        
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
                from scapy.all import IP, TCP, UDP, ICMP, ARP
                
                # Extract flow key (src_ip, dst_ip, src_port, dst_port, protocol)
                src_ip = 'Unknown'
                dst_ip = 'Unknown'
                src_port = 0
                dst_port = 0
                protocol = 'Unknown'
                
                # Extract IP layer information
                if packet.haslayer(IP):
                    ip_layer = packet[IP]
                    src_ip = str(ip_layer.src)
                    dst_ip = str(ip_layer.dst)
                    
                    if packet.haslayer(TCP):
                        tcp_layer = packet[TCP]
                        src_port = tcp_layer.sport
                        dst_port = tcp_layer.dport
                        protocol = 'TCP'
                    elif packet.haslayer(UDP):
                        udp_layer = packet[UDP]
                        src_port = udp_layer.sport
                        dst_port = udp_layer.dport
                        protocol = 'UDP'
                    elif packet.haslayer(ICMP):
                        protocol = 'ICMP'
                        src_port = dst_port = 0
                    else:
                        protocol = str(ip_layer.proto)
                        src_port = dst_port = 0
                        
                elif packet.haslayer(ARP):
                    arp_layer = packet[ARP]
                    src_ip = str(arp_layer.psrc)
                    dst_ip = str(arp_layer.pdst)
                    protocol = 'ARP'
                    src_port = dst_port = 0
                else:
                    # Fallback to getattr for older packets or unknown format
                    src_ip = str(getattr(packet, 'src', 'Unknown'))
                    dst_ip = str(getattr(packet, 'dst', 'Unknown'))
                    src_port = getattr(packet, 'sport', 0)
                    dst_port = getattr(packet, 'dport', 0)
                    protocol = str(getattr(packet, 'proto', 'Unknown'))
                
                # Create unidirectional flow key (matches Cisco NetFlow standard)
                # A flow from A->B is different from B->A
                flow_key = (src_ip, src_port, dst_ip, dst_port, protocol)
                
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
                        'bytes_total': 0
                    }
                
                flow = flows[flow_key]
                flow['packet_count'] += 1
                flow['packet_indices'].append(i)
                flow['last_seen'] = getattr(packet, 'time', flow['last_seen'])
                flow['bytes_total'] += len(packet)
                
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
    
    # ==================== AUGMENTATION METHODS ====================
    
    def reset_augmentation_state(self, augmentation_type: str = 'merge') -> Dict[str, Any]:
        """Reset and initialize augmentation state for a new workflow"""
        if augmentation_type == 'merge':
            return self.start_augmentation_merge()
        elif augmentation_type == 'attack':
            return self.start_augmentation_attack()
        elif augmentation_type == 'attack_only':
            return self.start_augmentation_attack()
        else:
            self.last_error = f"Unknown augmentation type: {augmentation_type}"
            return {}
    
    def start_augmentation_merge(self) -> Dict[str, Any]:
        """Initialize merge augmentation workflow"""
        self.augmentation_state = {
            'augmentation_type': 'merge',
            'step': 1,  # Step tracking: 1=benign selection, 2=malicious, 3=config, 4=confirm, 5=running
            'benign_pcap': None,
            'malicious_pcap': None,
            'benign_ip_range': None,
            'malicious_ip_range': None,
            'project_name': None,
            'ip_translation_range': None,
            'jitter_max': 0.1,
        }
        return self.augmentation_state
    
    def set_benign_pcap(self, pcap_path: str) -> bool:
        """Set the benign PCAP file for augmentation"""
        if not self.augmentation_state:
            self.last_error = "Augmentation not initialized"
            return False
        if not os.path.exists(pcap_path):
            self.last_error = f"File not found: {pcap_path}"
            return False
        
        # Extract IP range from benign PCAP
        try:
            parser = pcapparser(pcap_path)
            parser.load()
            benign_ip_range = parser.get_ip_range()
            self.augmentation_state['benign_ip_range'] = benign_ip_range
        except Exception as e:
            self.last_error = f"Error extracting IP range: {e}"
            self.augmentation_state['benign_ip_range'] = None
        
        self.augmentation_state['benign_pcap'] = pcap_path
        self.augmentation_state['step'] = 2
        return True
    
    def set_malicious_pcap(self, pcap_path: str) -> bool:
        """Set the malicious PCAP file for augmentation"""
        if not self.augmentation_state:
            self.last_error = "Augmentation not initialized"
            return False
        if not os.path.exists(pcap_path):
            self.last_error = f"File not found: {pcap_path}"
            return False
        
        # Extract IP range from malicious PCAP
        try:
            parser = pcapparser(pcap_path)
            parser.load()
            malicious_ip_range = parser.get_ip_range()
            self.augmentation_state['malicious_ip_range'] = malicious_ip_range
        except Exception as e:
            self.last_error = f"Error extracting IP range: {e}"
            self.augmentation_state['malicious_ip_range'] = None
        
        self.augmentation_state['malicious_pcap'] = pcap_path
        self.augmentation_state['step'] = 3
        return True
    
    def get_default_ip_translation_range(self) -> Optional[str]:
        """
        Get the default IP translation range based on AUTO_IP_TRANSLATION env variable.
        Returns the benign file's IP range if auto translation is enabled.
        
        Returns:
            Optional[str]: Default IP range in CIDR notation or None
        """
        # Check if AUTO_IP_TRANSLATION is enabled
        auto_translate = os.getenv('AUTO_IP_TRANSLATION', '').lower() in ('true', '1', 'yes', 'on')
        
        if auto_translate and self.augmentation_state.get('benign_ip_range'):
            return self.augmentation_state['benign_ip_range']
        
        return None
    
    def set_augmentation_config(self, project_name: str, 
                                ip_translation_range: Optional[str] = None, 
                                jitter_max: float = 0.1) -> bool:
        """Configure augmentation options with validation"""
        if not self.augmentation_state:
            self.last_error = "Augmentation not initialized"
            return False
        
        # Validate inputs
        validator = InputValidator()
        
        # Validate project name
        is_valid, error_msg = validator.validate_project_name(project_name)
        if not is_valid:
            self.last_error = f"Invalid project name: {error_msg}"
            return False
        
        # Validate IP range
        if ip_translation_range and ip_translation_range.strip():
            is_valid, error_msg = validator.validate_ip_range(ip_translation_range)
            if not is_valid:
                self.last_error = f"Invalid IP range: {error_msg}"
                return False
        
        # Validate jitter
        is_valid, jitter_value, error_msg = validator.validate_jitter(str(jitter_max))
        if not is_valid:
            self.last_error = f"Invalid jitter value: {error_msg}"
            return False
        
        # All validations passed
        self.augmentation_state['project_name'] = project_name.strip()
        self.augmentation_state['ip_translation_range'] = ip_translation_range.strip() if ip_translation_range else None
        self.augmentation_state['jitter_max'] = jitter_value
        self.augmentation_state['step'] = 4
        return True
    
    def run_augmentation_merge(self) -> Optional[Dict[str, Any]]:
        """Execute the merge augmentation workflow"""
        state = self.augmentation_state
        
        if not state or not state.get('benign_pcap') or not state.get('malicious_pcap'):
            self.last_error = "Benign and malicious PCAP files must be selected"
            return None
        
        if not state.get('project_name'):
            self.last_error = "Project name must be set"
            return None
        
        try:
            state['step'] = 5  # Running
            
            # Set augmentations output to root level (same as samples)
            augmentations_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'augmentations')
            
            # Run the augmentation
            results = merge_augmentation(
                benign_pcap=state['benign_pcap'],
                malicious_pcap=state['malicious_pcap'],
                project_name=state['project_name'],
                output_base_dir=augmentations_dir,
                ip_translation_range=state.get('ip_translation_range'),
                jitter_max=state.get('jitter_max', 0.1)
            )
            
            self.augmentation_results = results
            return results
            
        except Exception as e:
            self.last_error = f"Augmentation error: {str(e)}"
            return None
    
    def get_augmentation_state(self) -> Dict[str, Any]:
        """Get current augmentation state"""
        return self.augmentation_state
    
    def get_augmentation_results(self) -> Optional[Dict[str, Any]]:
        """Get results from last augmentation run"""
        return self.augmentation_results
    
    # ==================== ATTACK AUGMENTATION METHODS ====================
    
    def start_augmentation_attack(self) -> Dict[str, Any]:
        """Initialize attack generation workflow (no merging)"""
        self.augmentation_state = {
            'augmentation_type': 'attack',
            'step': 1,  # Step tracking: 1=attack selection, 2=config, 3=confirm, 4=running
            'project_name': None,
            'benign_ip_range': None,
        }
        self.attack_config_state = {}
        return self.augmentation_state
    
    def get_available_attacks(self) -> List[Dict]:
        """Get list of available attacks"""
        try:
            return get_available_attacks()
        except Exception as e:
            self.last_error = f"Error loading attacks: {e}"
            return []
    
    def set_attack(self, attack_key: str) -> bool:
        """Set the attack type for augmentation"""
        try:
            attack_instance = get_attack_instance(attack_key)
            metadata = attack_instance.get_metadata()
            
            # Convert AttackParameter dataclass objects to dictionaries
            parameters_list = []
            for param in metadata['parameters']:
                if hasattr(param, '__dict__'):
                    # It's a dataclass, convert to dict
                    param_dict = {
                        'name': param.name,
                        'param_type': param.param_type,
                        'description': param.description,
                        'required': param.required,
                        'default': param.default,
                        'validation_hint': param.validation_hint,
                    }
                else:
                    # Already a dict
                    param_dict = param
                parameters_list.append(param_dict)
            
            self.attack_config_state = {
                'attack_key': attack_key,
                'attack_name': metadata['name'],
                'attack_description': metadata['description'],
                'parameters': parameters_list,
                'input_values': {},
                'current_parameter_index': 0,
            }
            
            # Initialize input values with defaults
            for param in parameters_list:
                default_val = param.get('default')
                self.attack_config_state['input_values'][param['name']] = default_val if default_val is not None else ''
            
            self.augmentation_state['step'] = 3
            return True
        except Exception as e:
            self.last_error = f"Error setting attack: {e}"
            return False
    
    def set_attack_parameter_index(self, index: int) -> bool:
        """Set the current parameter index for attack configuration"""
        if not self.attack_config_state:
            return False
        
        params_count = len(self.attack_config_state.get('parameters', []))
        if 0 <= index < params_count:
            self.attack_config_state['current_parameter_index'] = index
            return True
        return False
    
    def set_attack_parameter_value(self, param_name: str, value: str) -> bool:
        """Set a specific attack parameter value"""
        if not self.attack_config_state:
            self.last_error = "Attack not configured"
            return False
        
        # Find the parameter definition
        parameters = self.attack_config_state.get('parameters', [])
        param_def = next((p for p in parameters if p['name'] == param_name), None)
        
        if not param_def:
            self.last_error = f"Unknown parameter: {param_name}"
            return False
        
        # Validate the parameter if validation method exists
        if param_def:
            try:
                attack_instance = get_attack_instance(self.attack_config_state['attack_key'])
                # TEMPORARILY SKIP VALIDATION FOR DEBUGGING
                # if not attack_instance._validate_single_parameter(param_def, value):
                #     self.last_error = f"Invalid value for {param_name}"
                #     return False
            except Exception as e:
                self.last_error = f"Validation error: {e}"
                return False
        
        # Store the value - create entry if it doesn't exist
        self.attack_config_state['input_values'][param_name] = value
        return True
    
    def get_attack_config_state(self) -> Dict[str, Any]:
        """Get the current attack configuration state"""
        return self.attack_config_state
    
    def run_attack_generation(self) -> bool:
        """Execute standalone attack generation (no merging)"""
        state = self.augmentation_state
        attack_config = self.attack_config_state
        
        if not attack_config or not attack_config.get('attack_key'):
            self.last_error = "Attack must be selected"
            return False
        
        if not state.get('project_name'):
            self.last_error = "Project name must be set"
            return False
        
        try:
            state['step'] = 4  # Running
            
            # Prepare attack parameters from input values
            attack_params = {}
            for param in attack_config.get('parameters', []):
                param_name = param['name']
                param_value = attack_config['input_values'].get(param_name, param.get('default', ''))
                
                # Convert value to appropriate type
                if param.get('param_type') == 'int':
                    attack_params[param_name] = int(param_value)
                elif param.get('param_type') == 'float':
                    attack_params[param_name] = float(param_value)
                else:
                    attack_params[param_name] = str(param_value)
            
            # Setup output directory - save to samples/malicious folder
            output_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'samples', 'malicious')
            os.makedirs(output_dir, exist_ok=True)
            
            # Generate output filename
            output_filename = f"{state['project_name']}_attack.pcap"
            output_path = os.path.join(output_dir, output_filename)
            
            # Get attack instance and generate
            attack_instance = get_attack_instance(attack_config['attack_key'])
            success = attack_instance.generate(attack_params, output_path)
            
            if success:
                self.augmentation_results = {
                    'success': True,
                    'output_file': output_path,
                    'attack_type': attack_config['attack_name'],
                    'message': f"Attack PCAP generated successfully: {output_filename}"
                }
                return True
            else:
                self.last_error = "Attack generation failed"
                self.augmentation_results = {
                    'success': False,
                    'error': 'Attack generation failed'
                }
                return False
                
        except Exception as e:
            self.last_error = f"Error generating attack: {str(e)}"
            self.augmentation_results = {
                'success': False,
                'error': str(e)
            }
            return False
    
    def run_augmentation_attack_and_merge(self) -> bool:
        """Execute the attack generation and merge workflow"""
        state = self.augmentation_state
        attack_config = self.attack_config_state
        
        if not state or not state.get('benign_pcap'):
            self.last_error = "Benign PCAP file must be selected"
            return False
        
        if not attack_config or not attack_config.get('attack_key'):
            self.last_error = "Attack must be selected"
            return False
        
        if not state.get('project_name'):
            self.last_error = "Project name must be set"
            return False
        
        try:
            state['step'] = 5  # Running
            
            # Prepare attack parameters from input values
            attack_params = {}
            for param in attack_config.get('parameters', []):
                param_name = param['name']
                param_value = attack_config['input_values'].get(param_name, param.get('default', ''))
                
                # Convert value to appropriate type
                if param.get('param_type') == 'int':
                    attack_params[param_name] = int(param_value)
                elif param.get('param_type') == 'float':
                    attack_params[param_name] = float(param_value)
                else:
                    attack_params[param_name] = str(param_value)
            
            # Set augmentations output to root level (same as samples)
            augmentations_dir = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'augmentations')
            
            # Run the attack and merge augmentation
            results = attack_and_merge_augmentation(
                benign_pcap=state['benign_pcap'],
                attack_key=attack_config['attack_key'],
                attack_parameters=attack_params,
                project_name=state['project_name'],
                output_base_dir=augmentations_dir,
                ip_translation_range=state.get('ip_translation_range'),
                jitter_max=state.get('jitter_max', 0.1)
            )
            
            self.augmentation_results = results
            return results.get('success', False)
            
        except Exception as e:
            self.last_error = f"Augmentation error: {str(e)}"
            return False