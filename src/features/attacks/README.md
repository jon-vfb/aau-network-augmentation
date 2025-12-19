# Attack Generators

This directory contains all attack generators for the network augmentation system.

## Overview

Each file in this directory defines one or more network attack types that can be used to augment network traffic with malicious patterns. Attacks are automatically discovered and registered by the system.

## Available Attacks

- **ARP Spoofing** (`arp_spoofing_generator.py`) - ARP cache poisoning attack
- **Port Scan** (`scanning_port_generator.py`) - TCP port scanning attack
- **Ping of Death** (`ping_of_death_generator.py`) - Oversized ICMP packet attack

## Creating New Attacks

Want to add a new attack type? See the comprehensive guides:

📖 **[Attack Development Guide](../../../docs/ATTACK_DEVELOPMENT_GUIDE.md)** - Complete tutorial with examples

📋 **[Quick Reference](../../../docs/ATTACK_QUICK_REFERENCE.md)** - Quick lookup for common patterns

### Quick Start

1. Create a new file: `my_attack_generator.py`
2. Inherit from `AttackBase`
3. Define `ATTACK_NAME`, `ATTACK_DESCRIPTION`, `ATTACK_PARAMETERS`
4. Implement `generate()` method
5. Your attack will automatically appear in the UI!

### Minimal Example

```python
from typing import Dict, Any
from scapy.all import IP, wrpcap
import time
from .attack_base import AttackBase, AttackParameter

class MyAttack(AttackBase):
    ATTACK_NAME = "My Attack"
    ATTACK_DESCRIPTION = "Brief description"
    ATTACK_PARAMETERS = [
        AttackParameter(
            name="target_ip",
            param_type="ip",
            description="Target IP address",
            required=True,
            validation_hint="e.g., 192.168.1.100"
        ),
    ]
    
    def generate(self, parameters: Dict[str, Any], output_path: str) -> bool:
        try:
            is_valid, error_msg = self.validate_parameters(parameters)
            if not is_valid:
                raise ValueError(f"Invalid: {error_msg}")
            
            target_ip = str(parameters.get('target_ip')).strip()
            packets = []
            
            # Generate attack packets
            pkt = IP(dst=target_ip)
            pkt.time = time.time()
            packets.append(pkt)
            
            wrpcap(output_path, packets)
            return True
        except Exception as e:
            print(f"Error: {e}")
            return False
```

## Architecture

### Auto-Discovery

The `AttackRegistry` class in `__init__.py` automatically discovers and loads all attack generators. You don't need to manually register your attacks.

### Base Class

All attacks inherit from `AttackBase` which provides:
- Parameter validation
- Metadata management
- Consistent interface

### Parameter Types

- `ip` - IP addresses
- `int` - Integers
- `float` - Floating-point numbers
- `str` - Strings
- `ports` - Port lists (e.g., "80,443" or "80-100")

## Testing

### Standalone Testing

Most attack generators can be run directly:

```bash
python src/features/attacks/my_attack_generator.py
```

### Validate PCAP Output

```bash
# View with tshark
tshark -r output.pcap

# View with Wireshark (GUI)
wireshark output.pcap
```

## Best Practices

✅ **DO:**
- Generate realistic timing between packets
- Include both attack and response traffic
- Recalculate checksums after modifying packets
- Validate all input parameters
- Provide clear error messages
- Document your attack thoroughly

❌ **DON'T:**
- Forget to set packet timestamps
- Skip parameter validation
- Generate all packets at the same time
- Modify `__init__.py` or `attack_base.py`

## File Naming

- Use lowercase with underscores
- End with `_generator.py` (recommended) or `.py`
- Examples: `syn_flood_generator.py`, `dns_amplification_generator.py`

## Support Files

- `attack_base.py` - Base class and parameter definitions (DO NOT MODIFY)
- `__init__.py` - Auto-discovery system (DO NOT MODIFY)

## Questions?

Refer to the documentation:
- [Attack Development Guide](../../../docs/ATTACK_DEVELOPMENT_GUIDE.md)
- [Quick Reference](../../../docs/ATTACK_QUICK_REFERENCE.md)
