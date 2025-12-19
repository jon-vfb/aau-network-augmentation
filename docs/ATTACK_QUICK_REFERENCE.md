# Attack Development Quick Reference

Quick reference for creating new attack generators.

## Minimal Attack Template

```python
from typing import Dict, Any
from scapy.all import IP, TCP, wrpcap
import time
from .attack_base import AttackBase, AttackParameter

class MyAttack(AttackBase):
    ATTACK_NAME = "My Attack"
    ATTACK_DESCRIPTION = "What it does"
    ATTACK_PARAMETERS = [
        AttackParameter(
            name="target_ip",
            param_type="ip",
            description="Target IP",
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
            base_time = time.time()
            
            # Generate packets here
            pkt = IP(dst=target_ip) / TCP(dport=80)
            pkt.time = base_time
            packets.append(pkt)
            
            wrpcap(output_path, packets)
            return True
        except Exception as e:
            print(f"Error: {e}")
            return False
```

## Parameter Types

| Type | Description | Example |
|------|-------------|---------|
| `"ip"` | IP address | `"192.168.1.100"` |
| `"int"` | Integer | `100` |
| `"float"` | Float | `1.5` |
| `"str"` | String | `"example"` |
| `"ports"` | Port list | `"80,443"` or `"80-100"` |

## Common Scapy Layers

```python
from scapy.all import (
    IP,      # IPv4
    IPv6,    # IPv6
    Ether,   # Ethernet
    ARP,     # ARP
    TCP,     # TCP
    UDP,     # UDP
    ICMP,    # ICMP
    DNS,     # DNS
    DNSQR,   # DNS Query
)
```

## TCP Flags

```python
TCP(flags="S")     # SYN
TCP(flags="A")     # ACK
TCP(flags="SA")    # SYN-ACK
TCP(flags="F")     # FIN
TCP(flags="R")     # RST
TCP(flags="P")     # PSH
TCP(flags="PA")    # PSH-ACK
```

## ICMP Types

```python
ICMP(type=8, code=0)  # Echo Request (ping)
ICMP(type=0, code=0)  # Echo Reply
ICMP(type=3, code=0)  # Destination Unreachable
ICMP(type=11, code=0) # Time Exceeded
```

## Packet Creation Patterns

### Basic Packet
```python
pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=80)
```

### With Timestamp
```python
pkt.time = time.time()
```

### Recalculate Checksums
```python
del pkt[IP].chksum
del pkt[TCP].chksum
pkt = IP(bytes(pkt))
```

### Fragmentation
```python
from scapy.all import fragment
fragments = fragment(large_pkt, fragsize=1400)
```

## Common Patterns

### Request/Response Pair
```python
# Request
req = IP(src=attacker, dst=victim) / TCP(flags="S", seq=1000)
req.time = base_time
packets.append(req)

# Response
rtt = random.uniform(0.001, 0.050)
resp = IP(src=victim, dst=attacker) / TCP(flags="SA", seq=2000, ack=1001)
resp.time = base_time + rtt
packets.append(resp)
```

### Timing with Jitter
```python
for i in range(num_packets):
    interval = random.uniform(0.9, 1.1)  # 1s ± 10%
    pkt.time = base_time + i * interval
```

### Random Source IP
```python
src_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}." \
         f"{random.randint(0, 255)}.{random.randint(1, 254)}"
```

### Random MAC Address
```python
mac = [random.randint(0, 255) for _ in range(6)]
mac[0] = (mac[0] & 0xfc) | 0x02  # Locally administered
mac_str = ':'.join([f"{x:02x}" for x in mac])
```

## Parameter Examples

### Required IP Parameter
```python
AttackParameter(
    name="target_ip",
    param_type="ip",
    description="IP address of the target",
    required=True,
    validation_hint="e.g., 192.168.1.100"
)
```

### Optional Integer with Default
```python
AttackParameter(
    name="num_packets",
    param_type="int",
    description="Number of packets to generate",
    required=False,
    default=100,
    validation_hint="Default: 100"
)
```

### Optional Float with Default
```python
AttackParameter(
    name="interval",
    param_type="float",
    description="Time between packets (seconds)",
    required=False,
    default=1.0,
    validation_hint="Default: 1.0 seconds"
)
```

### Ports Parameter
```python
AttackParameter(
    name="ports",
    param_type="ports",
    description="Ports to scan",
    required=True,
    validation_hint="e.g., 80,443 or 80-100"
)
```

## Error Handling

```python
def generate(self, parameters: Dict[str, Any], output_path: str) -> bool:
    try:
        # Validation
        is_valid, error_msg = self.validate_parameters(parameters)
        if not is_valid:
            raise ValueError(f"Invalid parameters: {error_msg}")
        
        # Generation
        packets = []
        # ... packet generation logic ...
        
        if not packets:
            raise ValueError("No packets generated")
        
        # Save
        wrpcap(output_path, packets)
        print(f"Generated {len(packets)} packets")
        return True
        
    except ValueError as e:
        print(f"Parameter error: {e}")
        return False
    except Exception as e:
        print(f"Error generating attack: {e}")
        import traceback
        traceback.print_exc()
        return False
```

## Testing Commands

```bash
# Run attack standalone
python src/features/attacks/my_attack_generator.py

# View generated PCAP
tshark -r output.pcap

# Count packets
tshark -r output.pcap -T fields -e frame.number | wc -l

# Filter by protocol
tshark -r output.pcap -Y "tcp"

# Show TCP flags
tshark -r output.pcap -T fields -e tcp.flags
```

## File Locations

```
src/features/attacks/
├── __init__.py                 # Auto-discovery (don't edit)
├── attack_base.py              # Base class (don't edit)
├── your_attack_generator.py    # Your attack (create this)
```

## Checklist

- [ ] File in `src/features/attacks/`
- [ ] Filename ends with `_generator.py`
- [ ] Import `AttackBase`, `AttackParameter`
- [ ] Define `ATTACK_NAME`, `ATTACK_DESCRIPTION`, `ATTACK_PARAMETERS`
- [ ] Implement `generate()` method
- [ ] Validate parameters
- [ ] Generate packets with timing
- [ ] Save with `wrpcap()`
- [ ] Return `True` on success
- [ ] Handle exceptions

## Common Mistakes

❌ **Wrong**: No checksum recalculation
```python
pkt = IP(src=src, dst=dst) / TCP(dport=80)
```

✅ **Right**: Recalculate checksums
```python
pkt = IP(src=src, dst=dst) / TCP(dport=80)
del pkt[IP].chksum
del pkt[TCP].chksum
pkt = IP(bytes(pkt))
```

---

❌ **Wrong**: No timing
```python
packets.append(pkt)
```

✅ **Right**: Add timestamps
```python
pkt.time = base_time + i * 0.1
packets.append(pkt)
```

---

❌ **Wrong**: No validation
```python
target_ip = parameters.get('target_ip')
```

✅ **Right**: Validate first
```python
is_valid, error_msg = self.validate_parameters(parameters)
if not is_valid:
    raise ValueError(f"Invalid: {error_msg}")
target_ip = str(parameters.get('target_ip')).strip()
```

## Need More Help?

See the comprehensive guide: `docs/ATTACK_DEVELOPMENT_GUIDE.md`
