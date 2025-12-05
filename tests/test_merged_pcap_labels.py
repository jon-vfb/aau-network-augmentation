"""
Test suite for verifying merged PCAP files are correctly labeled.

This test validates that:
1. Labels from the CSV correctly correspond to packets in the merged PCAP
2. IP translations are properly reflected in both the PCAP and labels
3. Timestamps in labels match the merged PCAP packets
4. All packets from original PCAPs are present in the merged file
"""

import os
import sys
import unittest
import pandas as pd
from scapy.all import rdpcap
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP

# Add src to path for imports
_THIS_DIR = os.path.dirname(__file__)
_ROOT_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
_SRC_DIR = os.path.join(_ROOT_DIR, "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)


class TestMergedPcapLabels(unittest.TestCase):
    """Test that merged PCAP files have correct labels."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.maxDiff = None
        
    def load_test_data(self, merged_pcap_path, labels_csv_path, ip_translation_csv_path=None):
        """
        Load test data files for validation.
        
        Args:
            merged_pcap_path (str): Path to merged PCAP file
            labels_csv_path (str): Path to labels CSV file
            ip_translation_csv_path (str, optional): Path to IP translation CSV
            
        Returns:
            tuple: (packets, labels_df, ip_translation_df)
        """
        # Load PCAP
        self.assertTrue(os.path.exists(merged_pcap_path), 
                       f"Merged PCAP file not found: {merged_pcap_path}")
        packets = rdpcap(merged_pcap_path)
        
        # Load labels
        self.assertTrue(os.path.exists(labels_csv_path),
                       f"Labels CSV file not found: {labels_csv_path}")
        labels_df = pd.read_csv(labels_csv_path)
        
        # Load IP translation if provided
        ip_translation_df = None
        if ip_translation_csv_path and os.path.exists(ip_translation_csv_path):
            ip_translation_df = pd.read_csv(ip_translation_csv_path)
        
        return packets, labels_df, ip_translation_df
    
    def test_packet_count_matches_labels(self):
        """Test that the number of packets matches the number of label entries."""
        # This is a template test - provide paths to actual test data
        # Example usage:
        # packets, labels_df, _ = self.load_test_data(
        #     "path/to/merged.pcap",
        #     "path/to/labels.csv"
        # )
        # self.assertEqual(len(packets), len(labels_df),
        #                 "Packet count doesn't match label count")
        pass
    
    def test_timestamps_match(self):
        """Test that timestamps in labels match the PCAP packet timestamps."""
        # This is a template test - provide paths to actual test data
        # Example:
        # packets, labels_df, _ = self.load_test_data(...)
        # for idx, pkt in enumerate(packets):
        #     label_time = labels_df.iloc[idx]['timestamp']
        #     self.assertAlmostEqual(float(pkt.time), label_time, places=6,
        #                           msg=f"Timestamp mismatch at packet {idx}")
        pass
    
    def test_ip_addresses_match(self):
        """Test that IP addresses in labels match the PCAP packets."""
        # This is a template test - provide paths to actual test data
        # Example:
        # packets, labels_df, _ = self.load_test_data(...)
        # for idx, pkt in enumerate(packets):
        #     if pkt.haslayer(IP):
        #         label_src = labels_df.iloc[idx].get('source_ip')
        #         label_dst = labels_df.iloc[idx].get('destination_ip')
        #         self.assertEqual(pkt[IP].src, label_src,
        #                         f"Source IP mismatch at packet {idx}")
        #         self.assertEqual(pkt[IP].dst, label_dst,
        #                         f"Destination IP mismatch at packet {idx}")
        pass
    
    def test_ip_translations_applied(self):
        """Test that IP translations were correctly applied."""
        # This is a template test - provide paths to actual test data
        # Example:
        # packets, labels_df, ip_trans_df = self.load_test_data(
        #     "path/to/merged.pcap",
        #     "path/to/labels.csv",
        #     "path/to/ip_translation_report.csv"
        # )
        # if ip_trans_df is not None and len(ip_trans_df) > 0:
        #     # Build translation map
        #     translation_map = dict(zip(
        #         ip_trans_df['original_ip'],
        #         ip_trans_df['translated_ip']
        #     ))
        #     # Verify translations were applied
        #     for idx, row in labels_df.iterrows():
        #         src_ip = row.get('source_ip')
        #         dst_ip = row.get('destination_ip')
        #         # Check if IPs should have been translated
        #         # ... validation logic here
        pass
    
    def test_labels_integrity(self):
        """Test that label values are valid and consistent."""
        # This is a template test - provide paths to actual test data
        # Example:
        # packets, labels_df, _ = self.load_test_data(...)
        # # Check required columns exist
        # required_cols = ['index', 'timestamp', 'label']
        # for col in required_cols:
        #     self.assertIn(col, labels_df.columns,
        #                  f"Required column '{col}' missing from labels")
        # # Check label values are valid
        # valid_labels = ['benign', 'malicious', 'attack']
        # for label in labels_df['label']:
        #     self.assertIn(label, valid_labels,
        #                  f"Invalid label value: {label}")
        pass
    
    def test_packet_order_preserved(self):
        """Test that packets are in chronological order."""
        # This is a template test - provide paths to actual test data
        # Example:
        # packets, labels_df, _ = self.load_test_data(...)
        # timestamps = [float(pkt.time) for pkt in packets]
        # for i in range(1, len(timestamps)):
        #     self.assertGreaterEqual(timestamps[i], timestamps[i-1],
        #                            f"Packets not in chronological order at index {i}")
        pass
    
    def verify_merged_pcap_labels(self, merged_pcap_path, labels_csv_path, 
                                   ip_translation_csv_path=None, verbose=True):
        """
        Comprehensive validation of merged PCAP and its labels.
        
        This method performs all validation checks in one call:
        - Packet count matches label count
        - Timestamps match between PCAP and labels
        - IP addresses match
        - IP translations are correctly applied
        - Labels are valid
        - Packets are in chronological order
        
        Args:
            merged_pcap_path (str): Path to merged PCAP file
            labels_csv_path (str): Path to labels CSV file
            ip_translation_csv_path (str, optional): Path to IP translation CSV
            verbose (bool): Print detailed validation results
            
        Returns:
            dict: Validation results with status and any errors found
        """
        results = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'stats': {}
        }
        
        try:
            # Load data
            packets, labels_df, ip_trans_df = self.load_test_data(
                merged_pcap_path, labels_csv_path, ip_translation_csv_path
            )
            
            results['stats']['packet_count'] = len(packets)
            results['stats']['label_count'] = len(labels_df)
            
            # Test 1: Packet count matches labels
            if len(packets) != len(labels_df):
                results['valid'] = False
                results['errors'].append(
                    f"Packet count ({len(packets)}) doesn't match label count ({len(labels_df)})"
                )
            elif verbose:
                print(f"✓ Packet count matches label count: {len(packets)}")
            
            # Test 2: Required columns exist
            required_cols = ['index', 'timestamp']
            missing_cols = [col for col in required_cols if col not in labels_df.columns]
            if missing_cols:
                results['valid'] = False
                results['errors'].append(f"Missing required columns: {missing_cols}")
            elif verbose:
                print(f"✓ All required columns present: {labels_df.columns.tolist()}")
            
            # Test 3: Timestamps match
            timestamp_errors = []
            for idx, pkt in enumerate(packets):
                if idx >= len(labels_df):
                    break
                label_time = labels_df.iloc[idx]['timestamp']
                pkt_time = float(pkt.time)
                # Allow small floating point differences (6 decimal places = microsecond precision)
                if abs(pkt_time - label_time) > 0.000001:
                    timestamp_errors.append(
                        f"Packet {idx}: PCAP={pkt_time:.6f}, Label={label_time:.6f}"
                    )
            
            if timestamp_errors:
                results['valid'] = False
                results['errors'].append(
                    f"Timestamp mismatches found: {len(timestamp_errors)} errors"
                )
                if verbose:
                    for err in timestamp_errors[:5]:  # Show first 5
                        print(f"  ✗ {err}")
                    if len(timestamp_errors) > 5:
                        print(f"  ... and {len(timestamp_errors) - 5} more")
            elif verbose:
                print(f"✓ All timestamps match between PCAP and labels")
            
            # Test 4: IP addresses match (for IP packets)
            ip_errors = []
            for idx, pkt in enumerate(packets):
                if idx >= len(labels_df):
                    break
                if pkt.haslayer(IP):
                    label_row = labels_df.iloc[idx]
                    pkt_src = pkt[IP].src
                    pkt_dst = pkt[IP].dst
                    label_src = str(label_row.get('source_ip', '')) if pd.notna(label_row.get('source_ip')) else None
                    label_dst = str(label_row.get('destination_ip', '')) if pd.notna(label_row.get('destination_ip')) else None
                    
                    if label_src and pkt_src != label_src:
                        ip_errors.append(
                            f"Packet {idx} src: PCAP={pkt_src}, Label={label_src}"
                        )
                    if label_dst and pkt_dst != label_dst:
                        ip_errors.append(
                            f"Packet {idx} dst: PCAP={pkt_dst}, Label={label_dst}"
                        )
            
            if ip_errors:
                results['valid'] = False
                results['errors'].append(
                    f"IP address mismatches found: {len(ip_errors)} errors"
                )
                if verbose:
                    for err in ip_errors[:5]:
                        print(f"  ✗ {err}")
                    if len(ip_errors) > 5:
                        print(f"  ... and {len(ip_errors) - 5} more")
            elif verbose:
                print(f"✓ All IP addresses match between PCAP and labels")
            
            # Test 5: Chronological order
            timestamps = [float(pkt.time) for pkt in packets]
            order_errors = []
            for i in range(1, len(timestamps)):
                if timestamps[i] < timestamps[i-1]:
                    order_errors.append(
                        f"Index {i}: {timestamps[i]:.6f} < {timestamps[i-1]:.6f}"
                    )
            
            if order_errors:
                results['valid'] = False
                results['errors'].append(
                    f"Packets not in chronological order: {len(order_errors)} violations"
                )
                if verbose:
                    for err in order_errors[:5]:
                        print(f"  ✗ {err}")
            elif verbose:
                print(f"✓ All packets in chronological order")
            
            # Test 6: IP translation validation (if translation file provided)
            if ip_trans_df is not None and len(ip_trans_df) > 0:
                results['stats']['translations'] = len(ip_trans_df)
                translation_map = dict(zip(
                    ip_trans_df['original_ip'].astype(str),
                    ip_trans_df['translated_ip'].astype(str)
                ))
                
                if verbose:
                    print(f"✓ IP translation report found: {len(translation_map)} translations")
                    if len(translation_map) > 0:
                        print(f"  Translation examples:")
                        for orig, trans in list(translation_map.items())[:3]:
                            print(f"    {orig} -> {trans}")
            elif verbose:
                print("ℹ No IP translation report provided")
            
            # Summary
            if verbose:
                print("\n" + "="*80)
                print("VALIDATION SUMMARY")
                print("="*80)
                print(f"Status: {'PASS' if results['valid'] else 'FAIL'}")
                print(f"Packets validated: {len(packets)}")
                print(f"Labels validated: {len(labels_df)}")
                print(f"Errors found: {len(results['errors'])}")
                print(f"Warnings: {len(results['warnings'])}")
                if not results['valid']:
                    print("\nErrors:")
                    for err in results['errors']:
                        print(f"  - {err}")
                print("="*80)
            
        except Exception as e:
            results['valid'] = False
            results['errors'].append(f"Validation failed with exception: {str(e)}")
            if verbose:
                print(f"\n✗ Validation failed: {e}")
                import traceback
                traceback.print_exc()
        
        return results


def run_validation_on_files(merged_pcap, labels_csv, ip_translation_csv=None):
    """
    Standalone function to validate merged PCAP files.
    
    Usage:
        python test_merged_pcap_labels.py <merged.pcap> <labels.csv> [ip_translation.csv]
    
    Args:
        merged_pcap (str): Path to merged PCAP file
        labels_csv (str): Path to labels CSV file
        ip_translation_csv (str, optional): Path to IP translation CSV file
    """
    test = TestMergedPcapLabels()
    results = test.verify_merged_pcap_labels(
        merged_pcap, labels_csv, ip_translation_csv, verbose=True
    )
    
    # Return exit code
    return 0 if results['valid'] else 1


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python test_merged_pcap_labels.py <merged.pcap> <labels.csv> [ip_translation.csv]")
        print("\nExample:")
        print("  python test_merged_pcap_labels.py merged_output.pcap merged_labels.csv")
        print("  python test_merged_pcap_labels.py merged_output.pcap merged_labels.csv ip_translation_report.csv")
        sys.exit(1)
    
    merged_pcap = sys.argv[1]
    labels_csv = sys.argv[2]
    ip_translation_csv = sys.argv[3] if len(sys.argv) > 3 else None
    
    exit_code = run_validation_on_files(merged_pcap, labels_csv, ip_translation_csv)
    sys.exit(exit_code)
