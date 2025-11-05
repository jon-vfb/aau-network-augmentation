# Protocol Ports Configuration Integration Guide

This guide shows how to integrate and use the new centralized protocol-ports configuration throughout the AAU Network Augmentation project.

## Overview

The `src/configs/protocol_ports.py` file provides a comprehensive mapping between network protocols and their associated ports. This centralized configuration eliminates hardcoded port numbers and protocol assumptions scattered throughout the codebase.

## Features

### 1. Protocol-to-Ports Mapping
```python
from configs.protocol_ports import get_ports_for_protocol

# Get all ports used by HTTP
http_ports = get_ports_for_protocol('HTTP')
# Returns: [80, 8080, 8000, 3000, 8888]

# Get primary port for SSH
ssh_port = get_primary_port('SSH')
# Returns: 22
```

### 2. Port-to-Protocols Mapping
```python
from configs.protocol_ports import get_protocols_for_port

# Get all protocols that use port 80
port_80_protocols = get_protocols_for_port(80)
# Returns: ['HTTP', 'APACHE', 'NGINX']
```

### 3. Transport Protocol Detection
```python
from configs.protocol_ports import uses_tcp, uses_udp, get_protocol_transport

# Check transport protocols
uses_tcp('HTTP')  # True
uses_udp('DNS')   # True
get_protocol_transport('DNS')  # ['UDP'] (note: DNS actually uses both)
```

### 4. Port Classification
```python
from configs.protocol_ports import get_port_category, is_well_known_port

# Classify ports
get_port_category(80)    # 'well-known'
get_port_category(8080)  # 'registered'
is_well_known_port(22)   # True
```

## Integration Examples

### 1. Enhanced PCAP Parser

Update the `pcapparser.py` to use the configuration:

```python
# In src/classes/pcapparser.py
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from configs.protocol_ports import get_ports_for_protocol, get_protocol_transport

def filter_by_protocol_enhanced(self, protocol: str) -> List:
    """Enhanced protocol filtering using centralized configuration."""
    protocol = protocol.upper()
    expected_ports = get_ports_for_protocol(protocol)
    transport_protocols = get_protocol_transport(protocol)
    
    filtered = []
    for pkt in self.packets:
        # Check TCP packets
        if 'TCP' in transport_protocols and pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            if tcp_layer.sport in expected_ports or tcp_layer.dport in expected_ports:
                filtered.append(pkt)
        
        # Check UDP packets  
        if 'UDP' in transport_protocols and pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            if udp_layer.sport in expected_ports or udp_layer.dport in expected_ports:
                filtered.append(pkt)
    
    return filtered
```

### 2. Traffic Generation

Use the configuration for generating realistic traffic:

```python
# In src/features/traffic_generator.py (example)
from configs.protocol_ports import get_primary_port, get_ports_for_protocol

def generate_web_traffic():
    """Generate realistic web traffic using configured ports."""
    http_ports = get_ports_for_protocol('HTTP')
    https_ports = get_ports_for_protocol('HTTPS')
    
    # Generate packets for various web ports
    for port in http_ports[:3]:  # Use top 3 HTTP ports
        packet = create_http_packet(port)
        # ...
```

### 3. Security Analysis

Implement security analysis using protocol classifications:

```python
# In src/features/security_analyzer.py (example)
from configs.protocol_ports import *

def analyze_security_risks(packets):
    """Analyze security risks based on protocol usage."""
    unencrypted_protocols = ['HTTP', 'FTP', 'TELNET']
    admin_protocols = ['SSH', 'RDP', 'TELNET']
    
    risks = {}
    
    for protocol in unencrypted_protocols:
        protocol_packets = filter_packets_by_protocol(packets, protocol)
        if protocol_packets:
            risks[f'unencrypted_{protocol.lower()}'] = len(protocol_packets)
    
    return risks
```

### 4. Network Flow Analysis

Enhance netflow detection:

```python
# Enhanced netflow analysis
def classify_netflow(flow):
    """Classify a netflow based on its ports and protocols."""
    src_port = flow['src_port']
    dst_port = flow['dst_port']
    
    # Check what protocols these ports typically serve
    src_protocols = get_protocols_for_port(src_port)
    dst_protocols = get_protocols_for_port(dst_port)
    
    # Determine most likely protocol
    if dst_protocols:
        flow['likely_protocol'] = dst_protocols[0]
        flow['service_type'] = classify_service_type(dst_protocols[0])
    elif src_protocols:
        flow['likely_protocol'] = src_protocols[0] 
        flow['service_type'] = classify_service_type(src_protocols[0])
    
    return flow

def classify_service_type(protocol):
    """Classify protocol into service categories."""
    web_protocols = ['HTTP', 'HTTPS']
    db_protocols = ['MYSQL', 'POSTGRESQL', 'MSSQL', 'ORACLE']
    
    if protocol in web_protocols:
        return 'web'
    elif protocol in db_protocols:
        return 'database'
    # ... more classifications
```

## Usage Patterns

### 1. Service Discovery
```python
# Discover database services in traffic
db_protocols = ['MYSQL', 'POSTGRESQL', 'MSSQL', 'ORACLE', 'MONGODB']
db_ports = []
for proto in db_protocols:
    db_ports.extend(get_ports_for_protocol(proto))

# Now filter traffic for database ports
database_traffic = filter_traffic_by_ports(packets, db_ports)
```

### 2. Protocol Validation
```python
def validate_protocol_port_combination(protocol, port):
    """Validate if a port is typically used by a protocol."""
    expected_ports = get_ports_for_protocol(protocol)
    return port in expected_ports

# Usage
is_valid = validate_protocol_port_combination('HTTP', 80)  # True
is_valid = validate_protocol_port_combination('HTTP', 22)  # False
```

### 3. Configuration-Driven Features
```python
# Generate monitoring rules based on configuration
def generate_monitoring_rules():
    """Generate monitoring rules for security-sensitive protocols."""
    sensitive_protocols = ['SSH', 'RDP', 'TELNET', 'SNMP']
    rules = []
    
    for protocol in sensitive_protocols:
        ports = get_ports_for_protocol(protocol)
        transport = get_protocol_transport(protocol)
        
        for port in ports:
            for trans in transport:
                rules.append({
                    'protocol': protocol,
                    'port': port,
                    'transport': trans,
                    'action': 'monitor',
                    'priority': 'high' if protocol in ['TELNET', 'SNMP'] else 'medium'
                })
    
    return rules
```

## Best Practices

1. **Always use the configuration** instead of hardcoding ports:
   ```python
   # Bad
   if packet[TCP].dport == 80:  # HTTP
   
   # Good
   http_ports = get_ports_for_protocol('HTTP')
   if packet[TCP].dport in http_ports:
   ```

2. **Handle protocol variations**:
   ```python
   # Check for both HTTP and HTTPS
   web_ports = []
   web_ports.extend(get_ports_for_protocol('HTTP'))
   web_ports.extend(get_ports_for_protocol('HTTPS'))
   ```

3. **Use transport protocol information**:
   ```python
   # Check appropriate transport layer
   if uses_tcp(protocol) and packet.haslayer(TCP):
       # Process TCP packet
   if uses_udp(protocol) and packet.haslayer(UDP):
       # Process UDP packet
   ```

4. **Leverage port categories**:
   ```python
   # Focus on well-known ports for service detection
   if is_well_known_port(port):
       # More reliable service identification
   ```

## Extending the Configuration

To add new protocols or ports:

1. Update `PROTOCOL_PORTS` dictionary in `protocol_ports.py`
2. Update transport protocol sets (`TCP_PROTOCOLS`, `UDP_PROTOCOLS`, `MIXED_PROTOCOLS`)
3. The reverse mapping (`PORT_PROTOCOLS`) is automatically updated

Example:
```python
# Add a new protocol
PROTOCOL_PORTS['MYPROTOCOL'] = [9999, 9998]
TCP_PROTOCOLS.add('MYPROTOCOL')
```

## Testing

Use the included example and test files:
```bash
python src/configs/protocol_ports.py  # Run built-in tests
python src/example/protocol_ports_example.py  # Extended examples
```

This centralized approach ensures consistency across all components and makes the system easier to maintain and extend.