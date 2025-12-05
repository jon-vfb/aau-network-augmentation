"""
Attack module with automatic attack discovery.
All attacks in this directory are automatically discovered and registered.
"""

import os
import sys
import importlib.util
from typing import Dict, Type, List

from .attack_base import AttackBase


class AttackRegistry:
    """Registry for all available attacks with auto-discovery."""
    
    _registry: Dict[str, Type[AttackBase]] = {}
    _initialized = False
    
    @classmethod
    def _discover_attacks(cls):
        """Auto-discover and load all attack classes from the attacks folder."""
        if cls._initialized:
            return
        
        attacks_dir = os.path.dirname(__file__)
        package_name = __name__  # Get the current package name
        
        # Scan all Python files in the attacks directory
        for filename in os.listdir(attacks_dir):
            if filename.endswith('_generator.py') or filename == 'attack_base.py' or filename == '__init__.py':
                continue
            
            if filename.endswith('.py') and not filename.startswith('_'):
                module_name = filename[:-3]  # Remove .py extension
                module_path = os.path.join(attacks_dir, filename)
                
                try:
                    # Load the module dynamically
                    full_module_name = f"{package_name}.{module_name}"
                    spec = importlib.util.spec_from_file_location(full_module_name, module_path)
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        sys.modules[full_module_name] = module
                        spec.loader.exec_module(module)
                        
                        # Find all AttackBase subclasses in the module
                        for name in dir(module):
                            obj = getattr(module, name)
                            if (isinstance(obj, type) and 
                                issubclass(obj, AttackBase) and 
                                obj is not AttackBase and
                                hasattr(obj, 'ATTACK_NAME')):
                                attack_key = obj.ATTACK_NAME.lower().replace(' ', '_')
                                cls._registry[attack_key] = obj
                
                except Exception as e:
                    print(f"Warning: Failed to load attack from {filename}: {e}")
        
        # Also load from _generator.py files
        for filename in os.listdir(attacks_dir):
            if filename.endswith('_generator.py'):
                module_name = filename[:-3]  # Remove .py extension
                module_path = os.path.join(attacks_dir, filename)
                
                try:
                    full_module_name = f"{package_name}.{module_name}"
                    spec = importlib.util.spec_from_file_location(full_module_name, module_path)
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        sys.modules[full_module_name] = module
                        spec.loader.exec_module(module)
                        
                        # Find all AttackBase subclasses
                        for name in dir(module):
                            obj = getattr(module, name)
                            if (isinstance(obj, type) and 
                                issubclass(obj, AttackBase) and 
                                obj is not AttackBase and
                                hasattr(obj, 'ATTACK_NAME')):
                                attack_key = obj.ATTACK_NAME.lower().replace(' ', '_')
                                cls._registry[attack_key] = obj
                
                except Exception as e:
                    print(f"Warning: Failed to load attack from {filename}: {e}")
        
        cls._initialized = True
    
    @classmethod
    def get_registry(cls) -> Dict[str, Type[AttackBase]]:
        """Get all registered attacks."""
        cls._discover_attacks()
        return cls._registry
    
    @classmethod
    def get_attack(cls, attack_key: str) -> Type[AttackBase]:
        """Get a specific attack by key."""
        cls._discover_attacks()
        return cls._registry.get(attack_key)
    
    @classmethod
    def list_attacks(cls) -> List[str]:
        """Get list of available attack keys."""
        cls._discover_attacks()
        return list(cls._registry.keys())
    
    @classmethod
    def get_attacks_list(cls) -> List[Dict]:
        """Get list of attacks with metadata."""
        cls._discover_attacks()
        attacks_list = []
        for key, attack_class in cls._registry.items():
            attacks_list.append({
                'key': key,
                'name': attack_class.ATTACK_NAME,
                'description': attack_class.ATTACK_DESCRIPTION,
                'class': attack_class
            })
        return attacks_list


def get_available_attacks() -> List[Dict]:
    """
    Get list of all available attacks with their metadata.
    
    Returns:
        List of dicts with 'key', 'name', 'description', 'class'
    """
    return AttackRegistry.get_attacks_list()


def get_attack_instance(attack_key: str) -> AttackBase:
    """
    Get an instance of a specific attack.
    
    Args:
        attack_key: Key of the attack (from get_available_attacks)
        
    Returns:
        Instance of the attack class
    """
    attack_class = AttackRegistry.get_attack(attack_key)
    if attack_class is None:
        raise ValueError(f"Unknown attack: {attack_key}")
    return attack_class()
