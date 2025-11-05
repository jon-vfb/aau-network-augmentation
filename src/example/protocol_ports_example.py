#!/usr/bin/env python3
"""
Example usage of the protocol_ports configuration module.

This demonstrates how to use the protocol ports configuration
in various network analysis scenarios.
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from configs.protocol_ports import *


def demonstrate_basic_usage():
    """Demonstrate basic protocol-port lookups."""
    print("=== Basic Protocol-Port Lookups ===")
    
    # Get ports for a protocol
    http_ports = get_ports_for_protocol('HTTP')
    print(f"HTTP uses ports: {http_ports}")
    
    # Get protocols for a port
    port_80_protocols = get_protocols_for_port(80)
    print(f"Port 80 is used by: {port_80_protocols}")
    
    # Get primary port for a protocol
    ssh_port = get_primary_port('SSH')
    print(f"SSH primary port: {ssh_port}")
    
    print()


def demonstrate_transport_detection():
    """Demonstrate transport protocol detection."""
    print("=== Transport Protocol Detection ===")
    
    protocols_to_check = ['HTTP', 'DNS', 'TFTP', 'SMTP']
    
    for protocol in protocols_to_check:
        transports = get_protocol_transport(protocol)
        tcp_status = uses_tcp(protocol)
        udp_status = uses_udp(protocol)
        both_status = uses_both_transports(protocol)
        
        print(f"{protocol}:")
        print(f"  Transport protocols: {transports}")
        print(f"  Uses TCP: {tcp_status}, Uses UDP: {udp_status}, Uses Both: {both_status}")
    
    print()


def demonstrate_port_classification():
    """Demonstrate port range classification."""
    print("=== Port Classification ===")
    
    test_ports = [22, 80, 443, 1433, 3000, 8080, 50000, 65000]
    
    for port in test_ports:
        category = get_port_category(port)
        well_known = is_well_known_port(port)
        registered = is_registered_port(port)
        dynamic = is_dynamic_port(port)
        protocols = get_protocols_for_port(port)
        
        print(f"Port {port}:")
        print(f"  Category: {category}")
        print(f"  Well-known: {well_known}, Registered: {registered}, Dynamic: {dynamic}")
        print(f"  Known protocols: {protocols if protocols else 'None'}")
    
    print()


def demonstrate_protocol_search():
    """Demonstrate protocol searching and filtering."""
    print("=== Protocol Search and Filtering ===")
    
    # Search for protocols
    web_protocols = search_protocols('HTTP')
    print(f"Protocols containing 'HTTP': {web_protocols}")
    
    db_protocols = search_protocols('SQL')
    print(f"Protocols containing 'SQL': {db_protocols}")
    
    # Get all TCP-only protocols
    tcp_only = [p for p in get_all_protocols() if uses_tcp(p) and not uses_udp(p)]
    print(f"TCP-only protocols ({len(tcp_only)}): {tcp_only[:10]}...")  # Show first 10
    
    # Get all UDP-only protocols  
    udp_only = [p for p in get_all_protocols() if uses_udp(p) and not uses_tcp(p)]
    print(f"UDP-only protocols ({len(udp_only)}): {udp_only}")
    
    # Get protocols that use both
    both_transports = [p for p in get_all_protocols() if uses_both_transports(p)]
    print(f"Protocols using both TCP and UDP: {both_transports}")
    
    print()


def demonstrate_comprehensive_info():
    """Demonstrate getting comprehensive protocol information."""
    print("=== Comprehensive Protocol Information ===")
    
    interesting_protocols = ['HTTP', 'HTTPS', 'SSH', 'DNS', 'FTP']
    
    for protocol in interesting_protocols:
        info = get_protocol_info(protocol)
        if info:
            print(f"{protocol}:")
            for key, value in info.items():
                print(f"  {key}: {value}")
            print()


def demonstrate_validation():
    """Demonstrate port validation."""
    print("=== Port Validation ===")
    
    test_ports = [-1, 0, 22, 65535, 65536, 100000]
    
    for port in test_ports:
        valid = validate_port(port)
        print(f"Port {port}: {'Valid' if valid else 'Invalid'}")
    
    print()


def show_statistics():
    """Show configuration statistics."""
    print("=== Configuration Statistics ===")
    
    all_protocols = get_all_protocols()
    all_ports = get_all_ports()
    
    tcp_protocols = [p for p in all_protocols if uses_tcp(p)]
    udp_protocols = [p for p in all_protocols if uses_udp(p)]
    mixed_protocols = [p for p in all_protocols if uses_both_transports(p)]
    
    well_known_ports = [p for p in all_ports if is_well_known_port(p)]
    registered_ports = [p for p in all_ports if is_registered_port(p)]
    dynamic_ports = [p for p in all_ports if is_dynamic_port(p)]
    
    print(f"Total protocols configured: {len(all_protocols)}")
    print(f"Total ports configured: {len(all_ports)}")
    print(f"TCP protocols: {len(tcp_protocols)}")
    print(f"UDP protocols: {len(udp_protocols)}")
    print(f"Mixed transport protocols: {len(mixed_protocols)}")
    print(f"Well-known ports (0-1023): {len(well_known_ports)}")
    print(f"Registered ports (1024-49151): {len(registered_ports)}")
    print(f"Dynamic ports (49152-65535): {len(dynamic_ports)}")
    
    print()


def demonstrate_practical_usage():
    """Demonstrate practical usage scenarios."""
    print("=== Practical Usage Scenarios ===")
    
    # Scenario 1: Identifying web traffic
    print("Scenario 1: Identifying web traffic")
    web_ports = []
    web_ports.extend(get_ports_for_protocol('HTTP'))
    web_ports.extend(get_ports_for_protocol('HTTPS'))
    print(f"Web traffic ports to monitor: {sorted(set(web_ports))}")
    
    # Scenario 2: Database service detection
    print("\nScenario 2: Database service detection")
    db_protocols = ['MYSQL', 'POSTGRESQL', 'MSSQL', 'ORACLE', 'MONGODB', 'REDIS']
    db_ports = []
    for proto in db_protocols:
        db_ports.extend(get_ports_for_protocol(proto))
    print(f"Database ports to monitor: {sorted(set(db_ports))}")
    
    # Scenario 3: Security-sensitive protocols
    print("\nScenario 3: Security-sensitive protocols")
    security_protocols = ['SSH', 'RDP', 'TELNET', 'FTP', 'SNMP']
    for proto in security_protocols:
        ports = get_ports_for_protocol(proto)
        transports = get_protocol_transport(proto)
        print(f"{proto}: ports {ports}, transport {transports}")
    
    print()


if __name__ == "__main__":
    print("Protocol Ports Configuration - Example Usage")
    print("=" * 60)
    print()
    
    demonstrate_basic_usage()
    demonstrate_transport_detection()
    demonstrate_port_classification()
    demonstrate_protocol_search()
    demonstrate_comprehensive_info()
    demonstrate_validation()
    show_statistics()
    demonstrate_practical_usage()
    
    print("Example completed successfully!")