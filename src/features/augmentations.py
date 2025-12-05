"""
Augmentation orchestrator for the Network Augmentation tool.
Handles merging of benign and malicious pcaps with labeling and tracking.
"""

import os
import sys
import re
import ipaddress
from pathlib import Path
from typing import Tuple, Optional, Dict, Any

# Ensure the repository's `src` directory is on sys.path
_THIS_DIR = os.path.dirname(__file__)
_SRC_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from features.labeler import Labeler
from features.merger.pcap_merger import PcapMerger
from features.attacks import get_available_attacks, get_attack_instance


class InputValidator:
    """Validates user input for augmentation parameters."""
    
    @staticmethod
    def validate_project_name(name: str) -> Tuple[bool, str]:
        """
        Validate project name.
        
        Args:
            name (str): Project name to validate
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        if not name or not name.strip():
            return False, "Project name cannot be empty"
        
        name = name.strip()
        
        # Check length
        if len(name) > 100:
            return False, "Project name must be 100 characters or less"
        
        # Check for valid characters (alphanumeric, underscore, hyphen, space)
        if not re.match(r'^[a-zA-Z0-9_\-\s]+$', name):
            return False, "Project name can only contain letters, numbers, underscores, hyphens, and spaces"
        
        return True, ""
    
    @staticmethod
    def validate_ip_range(ip_range: str) -> Tuple[bool, str]:
        """
        Validate IP range in CIDR notation.
        
        Args:
            ip_range (str): IP range in CIDR format (e.g., '192.168.100.0/24')
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        if not ip_range or not ip_range.strip():
            return True, ""  # Empty is valid - means no IP translation
        
        ip_range = ip_range.strip()
        
        try:
            # Try to parse as a valid network
            network = ipaddress.ip_network(ip_range, strict=False)
            
            # Check if it's a reasonable subnet size (at least /25 to ensure enough IPs)
            if network.prefixlen > 25:
                return False, f"IP range must be /25 or larger (requested: /{network.prefixlen}). Minimum 2 usable IPs required."
            
            # Check if it's not too large (reasonable limit at /8)
            if network.prefixlen < 8:
                return False, f"IP range is too large (/{network.prefixlen}). Maximum /8 supported."
            
            return True, ""
        except ValueError as e:
            return False, f"Invalid CIDR notation: {str(e)}. Use format like '192.168.100.0/24'"
        except Exception as e:
            return False, f"Error validating IP range: {str(e)}"
    
    @staticmethod
    def validate_jitter(jitter_str: str) -> Tuple[bool, float, str]:
        """
        Validate jitter value.
        
        Args:
            jitter_str (str): Jitter value as string (in seconds)
            
        Returns:
            Tuple[bool, float, str]: (is_valid, jitter_value, error_message)
        """
        if not jitter_str or not jitter_str.strip():
            return True, 0.1, ""  # Default value
        
        jitter_str = jitter_str.strip()
        
        try:
            jitter = float(jitter_str)
            
            # Validate range
            if jitter < 0:
                return False, 0.0, "Jitter cannot be negative"
            
            if jitter > 10.0:
                return False, 0.0, "Jitter must be 10 seconds or less"
            
            return True, jitter, ""
        except ValueError:
            return False, 0.0, "Jitter must be a valid number (e.g., 0.1 for 100 milliseconds)"
        except Exception as e:
            return False, 0.0, f"Error validating jitter: {str(e)}"


def get_user_input_interactive() -> Tuple[str, Optional[str], float]:
    """
    Interactively collect augmentation parameters from user with validation.
    
    Returns:
        Tuple[str, Optional[str], float]: (project_name, ip_range, jitter_max)
    """
    validator = InputValidator()
    
    # Get project name
    while True:
        print("\n" + "="*80)
        print("PROJECT CONFIGURATION")
        print("="*80)
        project_name = input("Enter project name: ").strip()
        is_valid, error_msg = validator.validate_project_name(project_name)
        if is_valid:
            break
        print(f"✗ Invalid project name: {error_msg}")
    
    # Get IP translation range
    while True:
        print("\nIP TRANSLATION RANGE")
        print("-" * 80)
        print("Enter IP range in CIDR notation (e.g., '192.168.100.0/24')")
        print("Leave blank to skip IP translation")
        ip_range_input = input("IP range (or press Enter to skip): ").strip()
        is_valid, error_msg = validator.validate_ip_range(ip_range_input)
        if is_valid:
            ip_range = ip_range_input if ip_range_input else None
            break
        print(f"✗ Invalid IP range: {error_msg}")
    
    # Get jitter value
    while True:
        print("\nJITTER CONFIGURATION")
        print("-" * 80)
        print("Jitter adds random delays to malicious traffic timestamps (in seconds)")
        print("Valid range: 0 to 10 seconds (default: 0.1 for 100 milliseconds)")
        jitter_input = input("Enter jitter value or press Enter for default (0.1): ").strip()
        is_valid, jitter_value, error_msg = validator.validate_jitter(jitter_input)
        if is_valid:
            break
        print(f"✗ Invalid jitter value: {error_msg}")
    
    # Confirmation
    print("\n" + "="*80)
    print("CONFIGURATION SUMMARY")
    print("="*80)
    print(f"Project Name: {project_name}")
    print(f"IP Translation Range: {ip_range if ip_range else 'Not set (no translation)'}")
    print(f"Jitter: {jitter_value} seconds")
    print("="*80)
    
    confirm = input("\nProceed with these settings? (y/N): ").strip().lower()
    if confirm != 'y':
        print("Configuration cancelled.")
        return None, None, None
    
    return project_name, ip_range, jitter_value


class MergeAugmentation:
    """Orchestrates the merging of benign and malicious pcap files with labeling."""
    
    def __init__(self, project_name: str, output_base_dir: str = None):
        """
        Initialize the MergeAugmentation.
        
        Args:
            project_name (str): Name of the project (used for folder organization)
            output_base_dir (str): Base directory for project output (defaults to src/features/augmentations)
        """
        self.project_name = project_name
        
        if output_base_dir is None:
            output_base_dir = os.path.join(_SRC_DIR, "features", "augmentations")
        
        self.output_dir = os.path.join(output_base_dir, project_name)
        self.labeler = Labeler()
        self.merger = PcapMerger()
        
        # Create project directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Subdirectory for CSVs (input_info folder containing labeled packet data)
        self.input_info_dir = os.path.join(self.output_dir, "input_info")
        os.makedirs(self.input_info_dir, exist_ok=True)
    
    def run(self, benign_pcap: str, malicious_pcap: str, 
            ip_translation_range: str = None, jitter_max: float = 0.1) -> dict:
        """
        Execute the merge augmentation workflow:
        1. Label benign pcap as benign (save CSV)
        2. Label malicious pcap as malicious (save CSV)
        3. Merge both pcaps with optional IP translation and jitter
        4. Generate merged pcap and merged label CSV with IP/timestamp tracking
        
        Args:
            benign_pcap (str): Path to benign pcap file
            malicious_pcap (str): Path to malicious pcap file
            ip_translation_range (str): Optional CIDR range for IP translation (e.g., '192.168.100.0/24')
            jitter_max (float): Maximum jitter in seconds to apply to malicious traffic
        
        Returns:
            dict: Results dictionary with paths and status information
        """
        results = {
            "success": False,
            "project_name": self.project_name,
            "project_dir": self.output_dir,
            "benign_pcap_input": benign_pcap,
            "malicious_pcap_input": malicious_pcap,
            "benign_csv": None,
            "malicious_csv": None,
            "merged_pcap": None,
            "merged_csv": None,
            "ip_translation_report": None,
            "messages": []
        }
        
        # Validate input files
        if not os.path.exists(benign_pcap):
            results["messages"].append(f"Error: Benign pcap not found: {benign_pcap}")
            return results
        
        if not os.path.exists(malicious_pcap):
            results["messages"].append(f"Error: Malicious pcap not found: {malicious_pcap}")
            return results
        
        # Step 1: Label benign pcap
        benign_csv = os.path.join(self.input_info_dir, "benign_labeled.csv")
        try:
            self.labeler.label_and_export(benign_pcap, benign_csv, "benign")
            results["benign_csv"] = benign_csv
            results["messages"].append(f"✓ Labeled benign pcap: {benign_csv}")
        except Exception as e:
            results["messages"].append(f"✗ Failed to label benign pcap: {e}")
            return results
        
        # Step 2: Label malicious pcap
        malicious_csv = os.path.join(self.input_info_dir, "malicious_labeled.csv")
        try:
            self.labeler.label_and_export(malicious_pcap, malicious_csv, "malicious")
            results["malicious_csv"] = malicious_csv
            results["messages"].append(f"✓ Labeled malicious pcap: {malicious_csv}")
        except Exception as e:
            results["messages"].append(f"✗ Failed to label malicious pcap: {e}")
            return results
        
        # Step 3: Merge pcaps
        merged_pcap = os.path.join(self.output_dir, f"{self.project_name}_merged.pcapng")
        merged_csv = os.path.join(self.output_dir, f"{self.project_name}_merged_labels.csv")
        
        try:
            # Configure merger with jitter
            merger = PcapMerger(jitter_max=jitter_max)
            
            # Optionally set IP translation range
            if ip_translation_range:
                if not merger.set_ip_translation_range(ip_translation_range):
                    results["messages"].append(f"Warning: Could not set IP translation range: {ip_translation_range}")
                else:
                    results["messages"].append(f"✓ Set IP translation range: {ip_translation_range}")
            
            # Load and merge pcaps WITH label tracking
            # The benign_csv and malicious_csv generated above are now inputs to the merger
            if not merger.load_pcaps(benign_pcap, malicious_pcap, benign_csv, malicious_csv):
                results["messages"].append("✗ Failed to load pcap files for merging")
                return results
            
            # Merge and generate merged labels CSV
            if not merger.merge(merged_pcap, merged_csv):
                results["messages"].append("✗ Failed to merge pcap files")
                return results
            
            results["merged_pcap"] = merged_pcap
            results["merged_csv"] = merged_csv
            results["messages"].append(f"✓ Merged pcaps: {merged_pcap}")
            results["messages"].append(f"✓ Generated merged labels: {merged_csv}")
            
            # IP translation report is always generated
            output_dir = os.path.dirname(merged_pcap)
            output_base_name = os.path.splitext(os.path.basename(merged_pcap))[0]
            ip_report_path = os.path.join(output_dir, f"{output_base_name}_ip_translation_report.csv")
            if os.path.exists(ip_report_path):
                results["ip_translation_report"] = ip_report_path
                # Count translations in the report
                try:
                    import pandas as pd
                    report_df = pd.read_csv(ip_report_path)
                    translation_count = len(report_df)
                    results["messages"].append(f"✓ Generated IP translation report: {ip_report_path} ({translation_count} translations)")
                except:
                    results["messages"].append(f"✓ Generated IP translation report: {ip_report_path}")
            
            # Get and report merge statistics
            stats = merger.get_merge_statistics()
            results["merge_statistics"] = stats
            results["messages"].append(f"  Benign packets: {stats['left_packets']}")
            results["messages"].append(f"  Malicious packets: {stats['right_packets']}")
            results["messages"].append(f"  Total packets: {stats['total_expected_packets']}")
            
        except Exception as e:
            results["messages"].append(f"✗ Failed to merge pcaps: {e}")
            return results
        
        results["success"] = True
        results["messages"].append(f"\n✓ Augmentation completed successfully!")
        return results
    
    def print_results(self, results: dict):
        """Print a formatted summary of augmentation results."""
        print(f"\n{'='*80}")
        print(f"Merge Augmentation Results: {results['project_name']}")
        print(f"{'='*80}")
        
        for msg in results.get("messages", []):
            print(msg)
        
        if results["success"]:
            print(f"\nProject Directory: {results['project_dir']}")
            print(f"Benign CSV (input): {results['benign_csv']}")
            print(f"Malicious CSV (input): {results['malicious_csv']}")
            print(f"Merged PCAP: {results['merged_pcap']}")
            print(f"Merged CSV (output): {results['merged_csv']}")
            if results.get("ip_translation_report"):
                print(f"IP Translation Report: {results['ip_translation_report']}")
        
        print(f"{'='*80}\n")


class AttackAndMergeAugmentation:
    """Orchestrates attack generation and merging with a benign PCAP."""
    
    def __init__(self, project_name: str, output_base_dir: str = None):
        """
        Initialize the AttackAndMergeAugmentation.
        
        Args:
            project_name (str): Name of the project (used for folder organization)
            output_base_dir (str): Base directory for project output (defaults to src/features/augmentations)
        """
        self.project_name = project_name
        
        if output_base_dir is None:
            output_base_dir = os.path.join(_SRC_DIR, "features", "augmentations")
        
        self.output_dir = os.path.join(output_base_dir, project_name)
        self.labeler = Labeler()
        self.merger = PcapMerger()
    
    def run(self, benign_pcap: str, attack_key: str, attack_parameters: Dict[str, Any],
            ip_translation_range: Optional[str] = None, jitter_max: float = 0.1) -> dict:
        """
        Generate an attack PCAP and merge it with a benign PCAP.
        
        Args:
            benign_pcap (str): Path to benign PCAP file
            attack_key (str): Key of the attack to generate
            attack_parameters (dict): Parameters specific to the attack
            ip_translation_range (str): Optional CIDR range for IP translation
            jitter_max (float): Maximum jitter in seconds
            
        Returns:
            dict: Results dictionary
        """
        results = {
            "success": False,
            "project_name": self.project_name,
            "project_dir": self.output_dir,
            "messages": []
        }
        
        try:
            # Create project directory
            os.makedirs(self.output_dir, exist_ok=True)
            results["messages"].append(f"✓ Project directory: {self.output_dir}")
            
            # Generate attack PCAP
            attack_pcap = os.path.join(self.output_dir, f"{self.project_name}_attack.pcap")
            
            results["messages"].append(f"\nGenerating {attack_key} attack...")
            try:
                attack_instance = get_attack_instance(attack_key)
                if not attack_instance.generate(attack_parameters, attack_pcap):
                    results["messages"].append(f"✗ Failed to generate attack PCAP")
                    return results
                results["messages"].append(f"✓ Generated attack PCAP: {attack_pcap}")
            except Exception as e:
                results["messages"].append(f"✗ Error generating attack: {e}")
                return results
            
            # Now use MergeAugmentation to merge the attack with benign
            results["messages"].append(f"\nMerging attack with benign PCAP...")
            
            merge_aug = MergeAugmentation(self.project_name, os.path.dirname(self.output_dir))
            merge_results = merge_aug.run(
                benign_pcap=benign_pcap,
                malicious_pcap=attack_pcap,
                ip_translation_range=ip_translation_range,
                jitter_max=jitter_max
            )
            
            # Merge the results
            results["success"] = merge_results.get("success", False)
            results["messages"].extend(merge_results.get("messages", []))
            results.update({
                "benign_csv": merge_results.get("benign_csv"),
                "malicious_csv": merge_results.get("malicious_csv"),
                "merged_pcap": merge_results.get("merged_pcap"),
                "merged_csv": merge_results.get("merged_csv"),
                "merge_statistics": merge_results.get("merge_statistics"),
                "ip_translation_report": merge_results.get("ip_translation_report"),
            })
            
        except Exception as e:
            results["messages"].append(f"✗ Failed to complete augmentation: {e}")
        
        return results
    
    def print_results(self, results: dict):
        """Print a formatted summary of augmentation results."""
        print(f"\n{'='*80}")
        print(f"Attack & Merge Augmentation Results: {results['project_name']}")
        print(f"{'='*80}")
        
        for msg in results.get("messages", []):
            print(msg)
        
        if results["success"]:
            print(f"\nProject Directory: {results['project_dir']}")
            print(f"Benign CSV (input): {results.get('benign_csv', 'N/A')}")
            print(f"Malicious CSV (input): {results.get('malicious_csv', 'N/A')}")
            print(f"Merged PCAP: {results.get('merged_pcap', 'N/A')}")
            print(f"Merged CSV (output): {results.get('merged_csv', 'N/A')}")
            if results.get("ip_translation_report"):
                print(f"IP Translation Report: {results['ip_translation_report']}")
        
        print(f"{'='*80}\n")


def merge_augmentation(benign_pcap: str, malicious_pcap: str, project_name: str,
                       output_base_dir: str = None, ip_translation_range: str = None,
                       jitter_max: float = 0.1) -> dict:
    """
    Convenience function to run merge augmentation in a single call.
    
    Args:
        benign_pcap (str): Path to benign pcap file
        malicious_pcap (str): Path to malicious pcap file
        project_name (str): Name of the project
        output_base_dir (str): Base directory for output
        ip_translation_range (str): Optional CIDR range for IP translation
        jitter_max (float): Maximum jitter in seconds
    
    Returns:
        dict: Results dictionary
    """
    aug = MergeAugmentation(project_name, output_base_dir)
    results = aug.run(benign_pcap, malicious_pcap, ip_translation_range, jitter_max)
    aug.print_results(results)
    return results


def attack_and_merge_augmentation(benign_pcap: str, attack_key: str, 
                                   attack_parameters: Dict[str, Any],
                                   project_name: str, output_base_dir: str = None,
                                   ip_translation_range: Optional[str] = None,
                                   jitter_max: float = 0.1) -> dict:
    """
    Convenience function to generate an attack and merge it with a benign PCAP.
    
    Args:
        benign_pcap (str): Path to benign pcap file
        attack_key (str): Key of the attack to generate
        attack_parameters (dict): Parameters specific to the attack
        project_name (str): Name of the project
        output_base_dir (str): Base directory for output
        ip_translation_range (str): Optional CIDR range for IP translation
        jitter_max (float): Maximum jitter in seconds
    
    Returns:
        dict: Results dictionary
    """
    aug = AttackAndMergeAugmentation(project_name, output_base_dir)
    results = aug.run(benign_pcap, attack_key, attack_parameters, 
                      ip_translation_range, jitter_max)
    aug.print_results(results)
    return results


if __name__ == "__main__":
    import sys
    
    # Check if pcap files are provided as command-line arguments
    if len(sys.argv) < 3:
        print("Usage: python augmentations.py <benign_pcap> <malicious_pcap> [project_name] [ip_range] [jitter]")
        print("\nExample with arguments:")
        print("  python augmentations.py benign.pcap malicious.pcap my_project 192.168.100.0/24 0.1")
        print("\nExample with interactive input:")
        print("  python augmentations.py benign.pcap malicious.pcap")
        sys.exit(1)
    
    benign_path = sys.argv[1]
    malicious_path = sys.argv[2]
    
    # Validate PCAP files
    if not os.path.exists(benign_path):
        print(f"Error: Benign PCAP file not found: {benign_path}")
        sys.exit(1)
    
    if not os.path.exists(malicious_path):
        print(f"Error: Malicious PCAP file not found: {malicious_path}")
        sys.exit(1)
    
    # Get parameters
    if len(sys.argv) >= 4:
        # Use command-line arguments
        proj_name = sys.argv[3]
        ip_range = sys.argv[4] if len(sys.argv) > 4 else None
        jitter_max = float(sys.argv[5]) if len(sys.argv) > 5 else 0.1
        
        # Validate inputs
        validator = InputValidator()
        is_valid, error_msg = validator.validate_project_name(proj_name)
        if not is_valid:
            print(f"Invalid project name: {error_msg}")
            sys.exit(1)
        
        if ip_range:
            is_valid, error_msg = validator.validate_ip_range(ip_range)
            if not is_valid:
                print(f"Invalid IP range: {error_msg}")
                sys.exit(1)
        
        is_valid, jitter_max, error_msg = validator.validate_jitter(str(jitter_max))
        if not is_valid:
            print(f"Invalid jitter value: {error_msg}")
            sys.exit(1)
    else:
        # Use interactive input
        result = get_user_input_interactive()
        if result[0] is None:
            sys.exit(1)
        proj_name, ip_range, jitter_max = result
    
    # Run augmentation
    merge_augmentation(benign_path, malicious_path, proj_name, 
                      ip_translation_range=ip_range, jitter_max=jitter_max)
