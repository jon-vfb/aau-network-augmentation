# Attack Development Guide

This guide provides comprehensive instructions for creating, structuring, and adding new attack generators to the network augmentation system.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Creating a New Attack](#creating-a-new-attack)
4. [Step-by-Step Tutorial](#step-by-step-tutorial)
5. [Attack Base Class Reference](#attack-base-class-reference)
6. [Best Practices](#best-practices)
7. [Testing Your Attack](#testing-your-attack)
8. [Troubleshooting](#troubleshooting)
9. [Examples](#examples)

---

## Overview

The attack generation system is designed to be **modular** and **self-registering**. Each attack is implemented as a separate Python module that inherits from `AttackBase`. The system automatically discovers and registers all attacks at runtime.

### Key Features

- **Automatic Discovery**: Attacks are automatically discovered and registered
- **Parameter Validation**: Built-in validation for attack parameters
- **UI Integration**: Attacks automatically appear in the curses UI
- **PCAP Generation**: Generate realistic network traffic in PCAP format
- **Extensible**: Easy to add new attack types

---

## Architecture

### Directory Structure

```
src/features/attacks/
├── __init__.py                    # Attack registry and auto-discovery
├── attack_base.py                 # Base class for all attacks
├── arp_spoofing_generator.py      # Example: ARP Spoofing attack
├── scanning_port_generator.py     # Example: Port Scan attack
├── ping_of_death_generator.py     # Example: Ping of Death attack
└── your_attack_generator.py       # Your new attack
```

### Core Components

1. **`AttackBase`**: Abstract base class that all attacks must inherit from
2. **`AttackParameter`**: Data class for defining attack parameters
3. **`AttackRegistry`**: Auto-discovery and registration system
4. **Attack Generator**: Your specific attack implementation

---

## Creating a New Attack

### Requirements

Every attack must:

1. Inherit from `AttackBase`
2. Define `ATTACK_NAME`, `ATTACK_DESCRIPTION`, and `ATTACK_PARAMETERS`
3. Implement the `generate()` method
4. Be saved in the `src/features/attacks/` directory
5. Have a filename ending in `_generator.py` or `.py`

### File Template

```python
"""
[Attack Name] Attack Generator

Brief description of what this attack does and how it works.
"""

from typing import List, Dict, Any
from scapy.all import IP, TCP, wrpcap  # Import necessary Scapy layers
import time
import random

# Import the attack base class
from .attack_base import AttackBase, AttackParameter


def generate_attack_packets(param1: str, param2: int) -> List:
    """
    Core function that generates the attack packets.
    
    Args:
        param1: Description of parameter 1
        param2: Description of parameter 2
        
    Returns:
        List of Scapy packets
    """
    packets = []
    base_time = time.time()
    
    # Your packet generation logic here
    # Example:
    # pkt = IP(src=source_ip, dst=target_ip) / TCP(dport=80)
    # pkt.time = base_time
    # packets.append(pkt)
    
    return packets


class YourAttackName(AttackBase):
    """
    [Attack Name] implementing the AttackBase interface.
    Detailed description of the attack.
    """
    
    ATTACK_NAME = "Your Attack Name"
    ATTACK_DESCRIPTION = "Brief description shown in the UI"
    ATTACK_PARAMETERS = [
        AttackParameter(
            name="target_ip",
            param_type="ip",
            description="IP address of the target",
            required=True,
            validation_hint="e.g., 192.168.1.100"
        ),
        AttackParameter(
            name="num_packets",
            param_type="int",
            description="Number of packets to generate",
            required=False,
            default=10,
            validation_hint="Default: 10"
        ),
        # Add more parameters as needed
    ]
    
    def generate(self, parameters: Dict[str, Any], output_path: str) -> bool:
        """
        Generate attack PCAP file.
        
        Args:
            parameters: Dict of parameter_name -> value
            output_path: Path where to save the generated PCAP
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # 1. Validate parameters
            is_valid, error_msg = self.validate_parameters(parameters)
            if not is_valid:
                raise ValueError(f"Invalid parameters: {error_msg}")
            
            # 2. Extract parameters
            target_ip = str(parameters.get('target_ip')).strip()
            num_packets = int(parameters.get('num_packets', 10))
            
            # 3. Generate attack packets
            packets = generate_attack_packets(
                param1=target_ip,
                param2=num_packets
            )
            
            if not packets:
                raise ValueError("No packets generated")
            
            # 4. Save to PCAP file
            wrpcap(output_path, packets)
            print(f"Generated {len(packets)} packets to {output_path}")
            return True
            
        except Exception as e:
            print(f"Error generating attack: {e}")
            import traceback
            traceback.print_exc()
            return False


# Optional: Standalone testing
if __name__ == "__main__":
    print("=== Testing Your Attack ===")
    # Add interactive testing code here
```

---

## Step-by-Step Tutorial

### Step 1: Create the File

Create a new file in `src/features/attacks/` with a descriptive name:

```bash
touch src/features/attacks/your_attack_generator.py
```

**Naming Convention**: Use lowercase with underscores, ending in `_generator.py`

Examples:
- `ping_of_death_generator.py`
- `syn_flood_generator.py`
- `dns_amplification_generator.py`

### Step 2: Import Required Modules

```python
from typing import List, Dict, Any
from scapy.all import IP, TCP, UDP, ICMP, Ether, wrpcap
import time
import random

from .attack_base import AttackBase, AttackParameter
```

### Step 3: Define Attack Metadata

```python
class YourAttack(AttackBase):
    ATTACK_NAME = "Your Attack Name"
    ATTACK_DESCRIPTION = "What the attack does (shown in UI)"
    ATTACK_PARAMETERS = [
        # Define parameters here
    ]
```

### Step 4: Define Parameters

Parameters use the `AttackParameter` data class:

```python
AttackParameter(
    name="parameter_name",           # Internal name (used in code)
    param_type="ip",                 # Type: ip, int, float, str, ports
    description="User-friendly description",
    required=True,                   # Is this parameter required?
    default=None,                    # Default value (if optional)
    validation_hint="e.g., 192.168.1.1"  # Example for users
)
```

**Available Parameter Types**:
- `"ip"`: IP address (validated with regex)
- `"int"`: Integer value
- `"float"`: Floating-point value
- `"str"`: String value
- `"ports"`: Port list (e.g., "80,443" or "80-100")

### Step 5: Implement the `generate()` Method

```python
def generate(self, parameters: Dict[str, Any], output_path: str) -> bool:
    try:
        # Validate
        is_valid, error_msg = self.validate_parameters(parameters)
        if not is_valid:
            raise ValueError(f"Invalid parameters: {error_msg}")
        
        # Extract parameters
        target_ip = str(parameters.get('target_ip')).strip()
        
        # Generate packets
        packets = self._generate_packets(target_ip)
        
        # Save PCAP
        wrpcap(output_path, packets)
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False
```

### Step 6: Implement Packet Generation

Create a separate function for packet generation logic:

```python
def _generate_packets(self, target_ip: str) -> List:
    packets = []
    base_time = time.time()
    
    # Create packets using Scapy
    for i in range(10):
        pkt = IP(dst=target_ip) / ICMP()
        pkt.time = base_time + i * 0.1
        packets.append(pkt)
    
    return packets
```

### Step 7: Test Standalone (Optional but Recommended)

Add a `__main__` block for testing:

```python
if __name__ == "__main__":
    attack = YourAttack()
    params = {
        'target_ip': '192.168.1.100',
        'num_packets': 5
    }
    success = attack.generate(params, 'test_output.pcap')
    print(f"Success: {success}")
```

---

## Attack Base Class Reference

### `AttackBase` Methods

#### `get_metadata() -> Dict[str, Any]`
Returns metadata about the attack (name, description, parameters).

```python
metadata = attack.get_metadata()
# Returns: {'name': '...', 'description': '...', 'parameters': [...]}
```

#### `validate_parameters(parameters: Dict[str, Any]) -> tuple`
Validates provided parameters against the attack's schema.

```python
is_valid, error_msg = attack.validate_parameters(params)
if not is_valid:
    print(f"Validation error: {error_msg}")
```

#### `generate(parameters: Dict[str, Any], output_path: str) -> bool`
**Abstract method** - Must be implemented by your attack class.

Generates the attack PCAP file.

```python
success = attack.generate(
    parameters={'target_ip': '10.0.0.1'},
    output_path='output.pcap'
)
```

### `AttackParameter` Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | `str` | Parameter name (used in code) |
| `param_type` | `str` | Type of parameter (ip, int, float, str, ports) |
| `description` | `str` | User-friendly description |
| `required` | `bool` | Whether parameter is required |
| `default` | `Any` | Default value (for optional parameters) |
| `validation_hint` | `str` | Example/hint shown to users |

---

## Best Practices

### 1. **Realistic Traffic Generation**

Generate realistic network traffic that resembles actual attacks:

```python
# Good: Realistic timing
for i in range(num_packets):
    pkt.time = base_time + i * random.uniform(0.001, 0.1)
    
# Bad: All packets at same time
for i in range(num_packets):
    pkt.time = base_time
```

### 2. **Proper Checksums**

Always recalculate checksums for packets:

```python
# Delete old checksums
del packet[IP].chksum
del packet[TCP].chksum

# Rebuild packet (Scapy recalculates checksums)
packet = IP(bytes(packet))
```

### 3. **Include Response Traffic**

Generate both attack and response packets for realism:

```python
# Attack packet
syn = IP(src=attacker, dst=victim) / TCP(flags="S")
packets.append(syn)

# Response packet
syn_ack = IP(src=victim, dst=attacker) / TCP(flags="SA")
packets.append(syn_ack)
```

### 4. **Sequence Numbers and TCP State**

For TCP attacks, maintain proper sequence numbers:

```python
client_seq = random.randint(1000000, 4294967295)
server_seq = random.randint(0, 4294967295)

# SYN
syn = TCP(seq=client_seq, ack=0, flags="S")

# SYN-ACK
syn_ack = TCP(seq=server_seq, ack=client_seq + 1, flags="SA")

# ACK
ack = TCP(seq=client_seq + 1, ack=server_seq + 1, flags="A")
```

### 5. **Validate Input Parameters**

Use the built-in validation:

```python
is_valid, error_msg = self.validate_parameters(parameters)
if not is_valid:
    raise ValueError(f"Invalid parameters: {error_msg}")
```

### 6. **Informative Error Messages**

Provide clear error messages:

```python
try:
    # ... generation logic
except ValueError as e:
    print(f"Parameter error: {e}")
    return False
except Exception as e:
    print(f"Unexpected error generating attack: {e}")
    import traceback
    traceback.print_exc()
    return False
```

### 7. **Documentation**

Document your attack thoroughly:

```python
"""
SYN Flood Attack Generator

This attack floods the target with TCP SYN packets without completing
the handshake, exhausting the target's connection queue.

The attack simulates multiple source IPs to make filtering difficult.
"""
```

### 8. **Parameter Defaults**

Provide sensible defaults for optional parameters:

```python
AttackParameter(
    name="rate",
    param_type="int",
    description="Packets per second",
    required=False,
    default=100,  # Reasonable default
    validation_hint="Default: 100 pps"
)
```

---

## Testing Your Attack

### 1. **Standalone Testing**

Run your attack file directly:

```bash
python src/features/attacks/your_attack_generator.py
```

### 2. **Integration Testing**

Create a test script:

```python
from features.attacks import get_available_attacks, get_attack_instance

# Check if attack is registered
attacks = get_available_attacks()
for attack in attacks:
    if 'your_attack' in attack['key']:
        print(f"✓ Found: {attack['name']}")
        
        # Create instance
        instance = get_attack_instance(attack['key'])
        
        # Test generation
        params = {
            'target_ip': '192.168.1.100',
            # ... other parameters
        }
        success = instance.generate(params, 'test_output.pcap')
        print(f"Generation: {'✓' if success else '✗'}")
```

### 3. **Validate PCAP Output**

Use Wireshark or `tshark` to inspect generated PCAPs:

```bash
# View packet summary
tshark -r output.pcap

# Filter for specific protocols
tshark -r output.pcap -Y "tcp.flags.syn==1"

# Check packet count
tshark -r output.pcap -T fields -e frame.number | wc -l
```

### 4. **Verify in UI**

1. Start the application: `python main.py`
2. Navigate to: **Augmentation** → **Create Attack**
3. Verify your attack appears in the list
4. Test parameter input and generation

---

## Troubleshooting

### Attack Not Appearing in Registry

**Problem**: Your attack doesn't show up in the UI.

**Solutions**:
1. Ensure filename ends with `_generator.py` or `.py`
2. Check that class inherits from `AttackBase`
3. Verify `ATTACK_NAME` is defined
4. Look for import errors in console output

```python
# Correct
class MyAttack(AttackBase):
    ATTACK_NAME = "My Attack"
    # ...
```

### Import Errors

**Problem**: `ModuleNotFoundError` or import failures.

**Solutions**:
1. Use relative imports: `from .attack_base import AttackBase`
2. Ensure all dependencies are installed: `pip install -r requirements.txt`
3. Check Python path is correct

### Validation Failures

**Problem**: Parameters fail validation.

**Solutions**:
1. Check `param_type` matches the data type
2. Ensure IP addresses are valid format
3. Use `validation_hint` to guide users
4. Test with the `validate_parameters()` method

```python
# Test validation
attack = MyAttack()
is_valid, msg = attack.validate_parameters({'target_ip': 'invalid'})
print(f"Valid: {is_valid}, Message: {msg}")
```

### Empty PCAP Files

**Problem**: Generated PCAP has no packets.

**Solutions**:
1. Check packet generation logic returns packets
2. Verify `wrpcap()` is called with correct path
3. Ensure packets list is not empty before writing

```python
if not packets:
    raise ValueError("No packets generated")
wrpcap(output_path, packets)
```

### Incorrect Checksums

**Problem**: Wireshark shows checksum errors.

**Solutions**:
1. Delete old checksums before rebuilding:
   ```python
   del packet[IP].chksum
   del packet[TCP].chksum
   packet = IP(bytes(packet))
   ```
2. Let Scapy recalculate automatically

---

## Examples

### Example 1: Simple ICMP Flood

```python
from typing import List, Dict, Any
from scapy.all import IP, ICMP, wrpcap
import time
import random

from .attack_base import AttackBase, AttackParameter


class ICMPFloodAttack(AttackBase):
    ATTACK_NAME = "ICMP Flood"
    ATTACK_DESCRIPTION = "Floods target with ICMP echo requests"
    ATTACK_PARAMETERS = [
        AttackParameter(
            name="attacker_ip",
            param_type="ip",
            description="Source IP address",
            required=True,
            validation_hint="e.g., 192.168.1.50"
        ),
        AttackParameter(
            name="target_ip",
            param_type="ip",
            description="Target IP address",
            required=True,
            validation_hint="e.g., 192.168.1.100"
        ),
        AttackParameter(
            name="num_packets",
            param_type="int",
            description="Number of ICMP packets",
            required=False,
            default=1000,
            validation_hint="Default: 1000"
        ),
    ]
    
    def generate(self, parameters: Dict[str, Any], output_path: str) -> bool:
        try:
            is_valid, error_msg = self.validate_parameters(parameters)
            if not is_valid:
                raise ValueError(f"Invalid parameters: {error_msg}")
            
            attacker_ip = str(parameters.get('attacker_ip')).strip()
            target_ip = str(parameters.get('target_ip')).strip()
            num_packets = int(parameters.get('num_packets', 1000))
            
            packets = []
            base_time = time.time()
            
            for i in range(num_packets):
                pkt = IP(src=attacker_ip, dst=target_ip) / ICMP()
                pkt.time = base_time + i * 0.001  # 1ms intervals
                packets.append(pkt)
            
            wrpcap(output_path, packets)
            print(f"Generated {len(packets)} ICMP packets")
            return True
            
        except Exception as e:
            print(f"Error: {e}")
            return False
```

### Example 2: TCP SYN Flood

```python
from typing import List, Dict, Any
from scapy.all import IP, TCP, wrpcap
import time
import random

from .attack_base import AttackBase, AttackParameter


class SYNFloodAttack(AttackBase):
    ATTACK_NAME = "SYN Flood"
    ATTACK_DESCRIPTION = "TCP SYN flood to exhaust connection queue"
    ATTACK_PARAMETERS = [
        AttackParameter(
            name="target_ip",
            param_type="ip",
            description="Target IP address",
            required=True,
            validation_hint="e.g., 192.168.1.100"
        ),
        AttackParameter(
            name="target_port",
            param_type="int",
            description="Target port",
            required=True,
            validation_hint="e.g., 80"
        ),
        AttackParameter(
            name="num_packets",
            param_type="int",
            description="Number of SYN packets",
            required=False,
            default=5000,
            validation_hint="Default: 5000"
        ),
    ]
    
    def generate(self, parameters: Dict[str, Any], output_path: str) -> bool:
        try:
            is_valid, error_msg = self.validate_parameters(parameters)
            if not is_valid:
                raise ValueError(f"Invalid parameters: {error_msg}")
            
            target_ip = str(parameters.get('target_ip')).strip()
            target_port = int(parameters.get('target_port'))
            num_packets = int(parameters.get('num_packets', 5000))
            
            packets = []
            base_time = time.time()
            
            for i in range(num_packets):
                # Random source IP to evade filtering
                src_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}." \
                         f"{random.randint(0, 255)}.{random.randint(1, 254)}"
                src_port = random.randint(1024, 65535)
                seq = random.randint(0, 4294967295)
                
                syn = IP(src=src_ip, dst=target_ip) / TCP(
                    sport=src_port,
                    dport=target_port,
                    flags="S",
                    seq=seq,
                    window=65535
                )
                
                # Recalculate checksums
                del syn[IP].chksum
                del syn[TCP].chksum
                syn = IP(bytes(syn))
                
                syn.time = base_time + i * 0.0001  # Very fast rate
                packets.append(syn)
            
            wrpcap(output_path, packets)
            print(f"Generated {len(packets)} SYN packets")
            return True
            
        except Exception as e:
            print(f"Error: {e}")
            return False
```

### Example 3: DNS Amplification

```python
from typing import List, Dict, Any
from scapy.all import IP, UDP, DNS, DNSQR, wrpcap
import time
import random

from .attack_base import AttackBase, AttackParameter


class DNSAmplificationAttack(AttackBase):
    ATTACK_NAME = "DNS Amplification"
    ATTACK_DESCRIPTION = "DNS amplification DDoS attack"
    ATTACK_PARAMETERS = [
        AttackParameter(
            name="victim_ip",
            param_type="ip",
            description="Victim IP (spoofed source)",
            required=True,
            validation_hint="e.g., 192.168.1.100"
        ),
        AttackParameter(
            name="dns_server",
            param_type="ip",
            description="DNS server to query",
            required=True,
            validation_hint="e.g., 8.8.8.8"
        ),
        AttackParameter(
            name="num_queries",
            param_type="int",
            description="Number of DNS queries",
            required=False,
            default=100,
            validation_hint="Default: 100"
        ),
    ]
    
    def generate(self, parameters: Dict[str, Any], output_path: str) -> bool:
        try:
            is_valid, error_msg = self.validate_parameters(parameters)
            if not is_valid:
                raise ValueError(f"Invalid parameters: {error_msg}")
            
            victim_ip = str(parameters.get('victim_ip')).strip()
            dns_server = str(parameters.get('dns_server')).strip()
            num_queries = int(parameters.get('num_queries', 100))
            
            packets = []
            base_time = time.time()
            
            # Domains that generate large responses
            domains = [
                "example.com",
                "google.com",
                "microsoft.com",
                "amazon.com"
            ]
            
            for i in range(num_queries):
                # Spoofed source (victim IP)
                query = IP(src=victim_ip, dst=dns_server) / \
                       UDP(sport=random.randint(1024, 65535), dport=53) / \
                       DNS(rd=1, qd=DNSQR(qname=random.choice(domains), qtype="ANY"))
                
                query.time = base_time + i * 0.01
                packets.append(query)
            
            wrpcap(output_path, packets)
            print(f"Generated {len(packets)} DNS queries")
            return True
            
        except Exception as e:
            print(f"Error: {e}")
            return False
```

---

## Advanced Topics

### Custom Parameter Types

You can extend parameter validation by overriding `_validate_single_parameter()`:

```python
def _validate_single_parameter(self, param: AttackParameter, value: Any) -> bool:
    if param.param_type == 'custom_type':
        # Your custom validation logic
        return your_validation_function(value)
    return super()._validate_single_parameter(param, value)
```

### Fragmented Packets

For attacks involving fragmentation:

```python
from scapy.all import fragment

# Create large packet
large_pkt = IP(dst=target) / ("X" * 10000)

# Fragment it
fragments = fragment(large_pkt, fragsize=1400)

for i, frag in enumerate(fragments):
    frag.time = base_time + i * 0.0001
    packets.append(frag)
```

### Layer 2 Attacks

For attacks at the data link layer:

```python
from scapy.all import Ether, ARP

arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / \
          ARP(op="who-has", psrc=gateway_ip, pdst=victim_ip)
```

---

## Summary Checklist

When creating a new attack, ensure you have:

- [ ] Created file in `src/features/attacks/` with `_generator.py` suffix
- [ ] Imported `AttackBase` and `AttackParameter`
- [ ] Defined `ATTACK_NAME`, `ATTACK_DESCRIPTION`, `ATTACK_PARAMETERS`
- [ ] Implemented `generate()` method
- [ ] Added parameter validation
- [ ] Generated realistic packet timing
- [ ] Recalculated checksums for modified packets
- [ ] Included error handling with informative messages
- [ ] Added docstrings and comments
- [ ] Tested standalone execution
- [ ] Verified attack appears in UI
- [ ] Validated PCAP output with Wireshark

---

## Additional Resources

- **Scapy Documentation**: https://scapy.readthedocs.io/
- **PCAP File Format**: https://wiki.wireshark.org/Development/LibpcapFileFormat
- **TCP/IP Protocol Suite**: Study network protocols for realistic attacks
- **Wireshark**: Essential tool for validating generated traffic

---

## Support

If you encounter issues:

1. Check the console output for error messages
2. Review existing attacks for reference patterns
3. Validate your PCAP files with Wireshark
4. Ensure all dependencies are installed

For questions or contributions, refer to the project repository.

---

**Last Updated**: December 3, 2025
**Version**: 1.0
