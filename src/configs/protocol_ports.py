"""
Protocol Ports Configuration

This module provides comprehensive mappings between network ports and protocols.
These mappings are used throughout the network augmentation system for packet
analysis, filtering, and generation.
"""

from typing import Dict, List, Set, Optional


# Main protocol-to-ports mapping
PROTOCOL_PORTS: Dict[str, List[int]] = {
    # Web protocols
    'HTTP': [80, 8080, 8000, 3000, 8888],
    'HTTPS': [443, 8443, 9443],
    
    # Email protocols
    'SMTP': [25, 587, 465],
    'POP3': [110, 995],
    'IMAP': [143, 993],
    
    # File transfer protocols
    'FTP': [20, 21],
    'FTPS': [989, 990],
    'SFTP': [22],  # SSH-based
    'TFTP': [69],
    
    # Remote access protocols
    'SSH': [22],
    'TELNET': [23],
    'RDP': [3389],
    'VNC': [5900, 5901, 5902, 5903, 5904],
    
    # DNS
    'DNS': [53],
    
    # DHCP
    'DHCP': [67, 68],
    
    # Network management
    'SNMP': [161, 162],
    'NTP': [123],
    'LDAP': [389, 636],  # 636 is LDAPS
    
    # Database protocols
    'MYSQL': [3306],
    'POSTGRESQL': [5432],
    'MSSQL': [1433, 1434],
    'ORACLE': [1521, 1522],
    'MONGODB': [27017, 27018, 27019],
    'REDIS': [6379],
    
    # Message queues
    'RABBITMQ': [5672, 15672],
    'KAFKA': [9092, 9093],
    
    # Monitoring and logging
    'SYSLOG': [514],
    'GRAFANA': [3000],
    'PROMETHEUS': [9090],
    'ELASTICSEARCH': [9200, 9300],
    
    # Development servers
    'DJANGO': [8000],
    'FLASK': [5000],
    'NODE': [3000, 8000],
    'RAILS': [3000],
    'TOMCAT': [8080, 8443],
    'APACHE': [80, 443, 8080, 8443],
    'NGINX': [80, 443, 8080, 8443],
    
    # Gaming protocols
    'MINECRAFT': [25565],
    'STEAM': [27015, 27016],
    
    # VoIP and video
    'SIP': [5060, 5061],
    'RTP': [5004],  # Range typically 5004-65535
    'RTSP': [554],
    
    # Proxy protocols
    'PROXY': [3128, 8080, 1080],
    'SOCKS': [1080, 1085],
    
    # Container and orchestration
    'DOCKER': [2375, 2376],
    'KUBERNETES': [6443, 8080, 10250],
    
    # Version control
    'GIT': [9418],
    
    # Backup protocols
    'RSYNC': [873],
    
    # P2P protocols
    'BITTORRENT': [6881, 6882, 6883, 6884, 6885],
    
    # Network services
    'KERBEROS': [88],
    'RADIUS': [1812, 1813],
    'TACACS': [49],
    
    # IoT protocols
    'MQTT': [1883, 8883],  # 8883 is MQTT over SSL
    'COAP': [5683, 5684],  # 5684 is COAP over DTLS
    
    # Other common services
    'NETBIOS': [137, 138, 139],
    'SMB': [445],
    'NFS': [2049],
    'CUPS': [631],
    'UPNP': [1900],
}

# Reverse mapping: port to protocols
PORT_PROTOCOLS: Dict[int, List[str]] = {}

# Well-known port ranges
WELL_KNOWN_PORTS = range(0, 1024)
REGISTERED_PORTS = range(1024, 49152)
DYNAMIC_PORTS = range(49152, 65536)

# Transport protocol mappings
TCP_PROTOCOLS: Set[str] = {
    'HTTP', 'HTTPS', 'SMTP', 'POP3', 'IMAP', 'FTP', 'FTPS', 'SFTP',
    'SSH', 'TELNET', 'RDP', 'LDAP', 'MYSQL', 'POSTGRESQL', 'MSSQL',
    'ORACLE', 'MONGODB', 'REDIS', 'RABBITMQ', 'KAFKA', 'GRAFANA',
    'PROMETHEUS', 'ELASTICSEARCH', 'DJANGO', 'FLASK', 'NODE', 'RAILS',
    'TOMCAT', 'APACHE', 'NGINX', 'MINECRAFT', 'SIP', 'RTSP', 'PROXY',
    'SOCKS', 'DOCKER', 'KUBERNETES', 'GIT', 'RSYNC', 'BITTORRENT',
    'RADIUS', 'TACACS', 'MQTT', 'SMB', 'NFS', 'CUPS'
}

UDP_PROTOCOLS: Set[str] = {
    'DNS', 'DHCP', 'SNMP', 'NTP', 'TFTP', 'SYSLOG', 'SIP', 'RTP',
    'RADIUS', 'TACACS', 'COAP', 'NETBIOS', 'UPNP', 'KERBEROS'
}

# Both TCP and UDP protocols
MIXED_PROTOCOLS: Set[str] = {
    'DNS', 'SIP', 'RADIUS', 'TACACS', 'KERBEROS'
}


def _build_port_protocols_mapping():
    """Build the reverse mapping from ports to protocols."""
    global PORT_PROTOCOLS
    PORT_PROTOCOLS.clear()
    
    for protocol, ports in PROTOCOL_PORTS.items():
        for port in ports:
            if port not in PORT_PROTOCOLS:
                PORT_PROTOCOLS[port] = []
            PORT_PROTOCOLS[port].append(protocol)


def get_protocols_for_port(port: int) -> List[str]:
    """
    Get all protocols that commonly use a specific port.
    
    Args:
        port (int): Port number
        
    Returns:
        List[str]: List of protocols using this port
    """
    return PORT_PROTOCOLS.get(port, [])


def get_ports_for_protocol(protocol: str) -> List[int]:
    """
    Get all ports commonly used by a specific protocol.
    
    Args:
        protocol (str): Protocol name (case insensitive)
        
    Returns:
        List[int]: List of ports used by this protocol
    """
    return PROTOCOL_PORTS.get(protocol.upper(), [])


def get_primary_port(protocol: str) -> Optional[int]:
    """
    Get the primary (most common) port for a protocol.
    
    Args:
        protocol (str): Protocol name (case insensitive)
        
    Returns:
        Optional[int]: Primary port number, or None if protocol not found
    """
    ports = get_ports_for_protocol(protocol)
    return ports[0] if ports else None


def is_well_known_port(port: int) -> bool:
    """
    Check if a port is in the well-known range (0-1023).
    
    Args:
        port (int): Port number
        
    Returns:
        bool: True if port is well-known
    """
    return port in WELL_KNOWN_PORTS


def is_registered_port(port: int) -> bool:
    """
    Check if a port is in the registered range (1024-49151).
    
    Args:
        port (int): Port number
        
    Returns:
        bool: True if port is registered
    """
    return port in REGISTERED_PORTS


def is_dynamic_port(port: int) -> bool:
    """
    Check if a port is in the dynamic range (49152-65535).
    
    Args:
        port (int): Port number
        
    Returns:
        bool: True if port is dynamic
    """
    return port in DYNAMIC_PORTS


def get_port_category(port: int) -> str:
    """
    Get the category of a port (well-known, registered, or dynamic).
    
    Args:
        port (int): Port number
        
    Returns:
        str: Port category
    """
    if is_well_known_port(port):
        return "well-known"
    elif is_registered_port(port):
        return "registered"
    elif is_dynamic_port(port):
        return "dynamic"
    else:
        return "invalid"


def uses_tcp(protocol: str) -> bool:
    """
    Check if a protocol typically uses TCP.
    
    Args:
        protocol (str): Protocol name (case insensitive)
        
    Returns:
        bool: True if protocol uses TCP
    """
    return protocol.upper() in TCP_PROTOCOLS


def uses_udp(protocol: str) -> bool:
    """
    Check if a protocol typically uses UDP.
    
    Args:
        protocol (str): Protocol name (case insensitive)
        
    Returns:
        bool: True if protocol uses UDP
    """
    return protocol.upper() in UDP_PROTOCOLS


def uses_both_transports(protocol: str) -> bool:
    """
    Check if a protocol uses both TCP and UDP.
    
    Args:
        protocol (str): Protocol name (case insensitive)
        
    Returns:
        bool: True if protocol uses both TCP and UDP
    """
    return protocol.upper() in MIXED_PROTOCOLS


def get_protocol_transport(protocol: str) -> List[str]:
    """
    Get the transport protocol(s) used by a specific protocol.
    
    Args:
        protocol (str): Protocol name (case insensitive)
        
    Returns:
        List[str]: List of transport protocols ('TCP', 'UDP', or both)
    """
    protocol = protocol.upper()
    transports = []
    
    if uses_tcp(protocol):
        transports.append('TCP')
    if uses_udp(protocol):
        transports.append('UDP')
    
    return transports


def get_all_protocols() -> List[str]:
    """
    Get a list of all configured protocols.
    
    Returns:
        List[str]: List of all protocol names
    """
    return list(PROTOCOL_PORTS.keys())


def get_all_ports() -> List[int]:
    """
    Get a list of all configured ports.
    
    Returns:
        List[int]: List of all port numbers
    """
    return list(PORT_PROTOCOLS.keys())


def search_protocols(query: str) -> List[str]:
    """
    Search for protocols by name (case insensitive, partial match).
    
    Args:
        query (str): Search query
        
    Returns:
        List[str]: List of matching protocol names
    """
    query = query.upper()
    return [proto for proto in PROTOCOL_PORTS.keys() if query in proto]


def get_protocol_info(protocol: str) -> Dict:
    """
    Get comprehensive information about a protocol.
    
    Args:
        protocol (str): Protocol name (case insensitive)
        
    Returns:
        Dict: Protocol information including ports, transport, etc.
    """
    protocol = protocol.upper()
    
    if protocol not in PROTOCOL_PORTS:
        return {}
    
    return {
        'name': protocol,
        'ports': get_ports_for_protocol(protocol),
        'primary_port': get_primary_port(protocol),
        'transport_protocols': get_protocol_transport(protocol),
        'uses_tcp': uses_tcp(protocol),
        'uses_udp': uses_udp(protocol),
        'uses_both': uses_both_transports(protocol)
    }


def validate_port(port: int) -> bool:
    """
    Validate if a port number is valid (0-65535).
    
    Args:
        port (int): Port number to validate
        
    Returns:
        bool: True if port is valid
    """
    return 0 <= port <= 65535


# Build the reverse mapping when module is imported
_build_port_protocols_mapping()


# Export commonly used items
__all__ = [
    'PROTOCOL_PORTS',
    'PORT_PROTOCOLS', 
    'TCP_PROTOCOLS',
    'UDP_PROTOCOLS',
    'MIXED_PROTOCOLS',
    'get_protocols_for_port',
    'get_ports_for_protocol',
    'get_primary_port',
    'is_well_known_port',
    'is_registered_port',
    'is_dynamic_port',
    'get_port_category',
    'uses_tcp',
    'uses_udp',
    'uses_both_transports',
    'get_protocol_transport',
    'get_all_protocols',
    'get_all_ports',
    'search_protocols',
    'get_protocol_info',
    'validate_port'
]


if __name__ == "__main__":
    # Example usage and testing
    print("Protocol Ports Configuration")
    print("="*50)
    
    # Test some lookups
    print(f"HTTP ports: {get_ports_for_protocol('HTTP')}")
    print(f"Port 80 protocols: {get_protocols_for_port(80)}")
    print(f"SSH primary port: {get_primary_port('SSH')}")
    print(f"DNS transport: {get_protocol_transport('DNS')}")
    print(f"Port 443 category: {get_port_category(443)}")
    
    # Show some statistics
    print(f"\nTotal protocols configured: {len(get_all_protocols())}")
    print(f"Total ports configured: {len(get_all_ports())}")
    print(f"TCP-only protocols: {len([p for p in get_all_protocols() if uses_tcp(p) and not uses_udp(p)])}")
    print(f"UDP-only protocols: {len([p for p in get_all_protocols() if uses_udp(p) and not uses_tcp(p)])}")
    print(f"Mixed protocols: {len([p for p in get_all_protocols() if uses_both_transports(p)])}")
