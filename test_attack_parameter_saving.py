#!/usr/bin/env python3
"""
Test script to verify attack parameters are being saved correctly.
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from user_interfaces.curses.logic.curses_logic import CursesLogic
from features.attacks import get_available_attacks, get_attack_instance


def test_parameter_saving():
    """Test that parameters are saved correctly"""
    print("\n" + "="*80)
    print("TESTING ATTACK PARAMETER SAVING")
    print("="*80)
    
    # Initialize logic
    logic = CursesLogic()
    
    # Get available attacks
    attacks = get_available_attacks()
    print(f"\nAvailable attacks: {len(attacks)}")
    for attack in attacks:
        print(f"  - {attack['name']}: {attack['key']}")
    
    if not attacks:
        print("❌ No attacks found!")
        return False
    
    # Set the first attack
    first_attack = attacks[0]
    attack_key = first_attack['key']
    print(f"\nUsing attack: {first_attack['name']} (key: {attack_key})")
    
    if not logic.set_attack(attack_key):
        print(f"❌ Failed to set attack: {logic.last_error}")
        return False
    
    print("✓ Attack set successfully")
    
    # Get the attack config state
    config_state = logic.get_attack_config_state()
    print(f"\nAttack config state:")
    print(f"  Attack name: {config_state.get('attack_name')}")
    print(f"  Parameters: {len(config_state.get('parameters', []))}")
    print(f"  Input values: {config_state.get('input_values')}")
    
    # Get parameters
    parameters = config_state.get('parameters', [])
    if not parameters:
        print("ℹ No parameters to configure")
        return True
    
    print(f"\nParameters to configure:")
    for param in parameters:
        print(f"  - {param['name']} ({param.get('param_type', 'str')}): {param.get('description')}")
        print(f"    Required: {param.get('required')}, Default: {param.get('default')}")
    
    # Test setting each parameter
    print("\nTesting parameter setting...")
    test_values = {
        'victim_ip': '192.168.1.100',
        'gateway_ip': '192.168.1.1',
        'num_packets': '10',
        'interval': '0.5',
        'target_ip': '192.168.1.50',
        'attacker_ip': '10.0.0.1',
        'ports': '80,443,22',
        'open_ports': '2',
    }
    
    for param in parameters:
        param_name = param['name']
        if param_name in test_values:
            test_value = test_values[param_name]
            
            print(f"\n  Setting {param_name} = {test_value}")
            
            if not logic.set_attack_parameter_value(param_name, test_value):
                print(f"    ❌ Failed: {logic.last_error}")
                return False
            
            print(f"    ✓ Set successfully")
            
            # Verify it was saved
            saved_value = config_state['input_values'].get(param_name)
            print(f"    Saved value: {saved_value}")
            
            if saved_value != test_value:
                print(f"    ❌ Value not saved correctly! Expected {test_value}, got {saved_value}")
                return False
            
            print(f"    ✓ Value saved correctly")
    
    print("\n" + "="*80)
    print("✓ ALL TESTS PASSED")
    print("="*80)
    return True


if __name__ == "__main__":
    success = test_parameter_saving()
    sys.exit(0 if success else 1)
