"""
Base class for attack generators.
All attack generators must inherit from this class and implement the required methods.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class AttackParameter:
    """Represents a single parameter required for an attack."""
    name: str
    param_type: str  # 'str', 'int', 'float', 'ip', 'ports', etc.
    description: str
    required: bool = True
    default: Optional[Any] = None
    validation_hint: str = ""  # User-friendly hint for input format


class AttackBase(ABC):
    """Base class for all attack generators."""
    
    # These must be defined in subclasses
    ATTACK_NAME: str = ""
    ATTACK_DESCRIPTION: str = ""
    ATTACK_PARAMETERS: List[AttackParameter] = []
    
    def __init__(self):
        """Initialize the attack generator."""
        pass
    
    @classmethod
    def get_metadata(cls) -> Dict[str, Any]:
        """
        Return metadata about this attack.
        
        Returns:
            Dict with 'name', 'description', and 'parameters'
        """
        return {
            'name': cls.ATTACK_NAME,
            'description': cls.ATTACK_DESCRIPTION,
            'parameters': cls.ATTACK_PARAMETERS
        }
    
    @abstractmethod
    def generate(self, parameters: Dict[str, Any], output_path: str) -> bool:
        """
        Generate the attack PCAP file.
        
        Args:
            parameters: Dict of parameter_name -> value
            output_path: Path where to save the generated PCAP
            
        Returns:
            bool: True if successful, False otherwise
        """
        pass
    
    def validate_parameters(self, parameters: Dict[str, Any]) -> tuple:
        """
        Validate the provided parameters.
        
        Args:
            parameters: Dict of parameter_name -> value
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check required parameters
        for param in self.ATTACK_PARAMETERS:
            if param.required and param.name not in parameters:
                return False, f"Missing required parameter: {param.name}"
            
            if param.name in parameters and parameters[param.name] is not None:
                if not self._validate_single_parameter(param, parameters[param.name]):
                    return False, f"Invalid value for {param.name}: {parameters[param.name]}"
        
        return True, ""
    
    def _validate_single_parameter(self, param: AttackParameter, value: Any) -> bool:
        """Validate a single parameter based on its type."""
        if value is None and not param.required:
            return True
        
        if param.param_type == 'int':
            return isinstance(value, int) or (isinstance(value, str) and value.isdigit())
        elif param.param_type == 'float':
            try:
                float(value)
                return True
            except (ValueError, TypeError):
                return False
        elif param.param_type == 'str':
            return isinstance(value, str) and len(str(value).strip()) > 0
        elif param.param_type == 'ip':
            return self._is_valid_ip(str(value))
        elif param.param_type == 'ports':
            return self._is_valid_ports(str(value))
        
        return True
    
    @staticmethod
    def _is_valid_ip(ip_str: str) -> bool:
        """Check if a string is a valid IP address."""
        parts = ip_str.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    @staticmethod
    def _is_valid_ports(ports_str: str) -> bool:
        """Check if a string is valid port notation (comma-separated or ranges)."""
        try:
            for part in ports_str.split(','):
                part = part.strip()
                if '-' in part:
                    # Port range like 80-443
                    start, end = part.split('-')
                    start, end = int(start.strip()), int(end.strip())
                    if not (0 <= start <= 65535 and 0 <= end <= 65535):
                        return False
                else:
                    # Single port
                    port = int(part)
                    if not (0 <= port <= 65535):
                        return False
            return True
        except ValueError:
            return False
    
    @staticmethod
    def parse_ports(ports_str: str) -> List[int]:
        """
        Parse port string into list of ports.
        Supports: "80", "80,443,8080", "80-443" (range)
        
        Returns:
            List of port numbers
        """
        ports = []
        for part in ports_str.split(','):
            part = part.strip()
            if '-' in part:
                # Port range
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                # Single port
                ports.append(int(part))
        return sorted(list(set(ports)))
