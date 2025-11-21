#!/usr/bin/env python3
"""Quick test to verify imports work"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

print("Testing imports...")

try:
    print("1. Importing attack_base...")
    from features.attacks.attack_base import AttackBase
    print("   ✓ attack_base imported")
    
    print("2. Importing arp_spoofing_generator...")
    from features.attacks.arp_spoofing_generator import ARPSpoofingAttack
    print("   ✓ arp_spoofing_generator imported")
    
    print("3. Importing scanning_port_generator...")
    from features.attacks.scanning_port_generator import PortScanAttack
    print("   ✓ scanning_port_generator imported")
    
    print("4. Importing attacks package...")
    from features.attacks import get_available_attacks, get_attack_instance
    print("   ✓ attacks package imported")
    
    print("5. Getting available attacks...")
    attacks = get_available_attacks()
    print(f"   ✓ Found {len(attacks)} attacks:")
    for attack in attacks:
        print(f"     - {attack['name']}: {attack['description']}")
    
    print("\n✓ All imports successful!")
    
except Exception as e:
    print(f"\n✗ Import failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
