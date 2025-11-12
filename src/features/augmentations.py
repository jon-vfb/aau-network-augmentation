"""
Augmentation orchestrator for the Network Augmentation tool.
Handles merging of benign and malicious pcaps with labeling and tracking.
"""

import os
import sys
from pathlib import Path

# Ensure the repository's `src` directory is on sys.path
_THIS_DIR = os.path.dirname(__file__)
_SRC_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from features.labeler import Labeler
from features.merger.pcap_merger import PcapMerger


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
        4. Save merged pcap to output directory
        
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
        
        try:
            # Configure merger with jitter
            merger = PcapMerger(jitter_max=jitter_max)
            
            # Optionally set IP translation range
            if ip_translation_range:
                if not merger.set_ip_translation_range(ip_translation_range):
                    results["messages"].append(f"Warning: Could not set IP translation range: {ip_translation_range}")
                else:
                    results["messages"].append(f"✓ Set IP translation range: {ip_translation_range}")
            
            # Load and merge pcaps
            if not merger.load_pcaps(benign_pcap, malicious_pcap):
                results["messages"].append("✗ Failed to load pcap files for merging")
                return results
            
            if not merger.merge(merged_pcap):
                results["messages"].append("✗ Failed to merge pcap files")
                return results
            
            results["merged_pcap"] = merged_pcap
            results["messages"].append(f"✓ Merged pcaps: {merged_pcap}")
            
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
            print(f"Benign CSV: {results['benign_csv']}")
            print(f"Malicious CSV: {results['malicious_csv']}")
            print(f"Merged PCAP: {results['merged_pcap']}")
        
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


if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) < 4:
        print("Usage: python augmentations.py <benign_pcap> <malicious_pcap> <project_name>")
        sys.exit(1)
    
    benign_path = sys.argv[1]
    malicious_path = sys.argv[2]
    proj_name = sys.argv[3]
    
    merge_augmentation(benign_path, malicious_path, proj_name)
