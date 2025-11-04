from scapy.all import *
from scapy.utils import rdpcap, wrpcap
import os
import random
import time
from typing import List, Dict, Optional, Tuple
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from classes.pcapparser import pcapparser


class PcapMerger:
    def __init__(self, jitter_max: float = 0.1):
        """
        Initialize PCAP merger with jitter parameter.
        
        Args:
            jitter_max (float): Maximum jitter to add to timestamps (in seconds)
        """
        self.jitter_max = jitter_max
        self.left_parser = None
        self.right_parser = None
        
    def load_pcaps(self, left_pcap: str, right_pcap: str) -> bool:
        """
        Load both PCAP files.
        
        Args:
            left_pcap (str): Path to left PCAP file
            right_pcap (str): Path to right PCAP file
            
        Returns:
            bool: Success status
        """
        try:
            self.left_parser = pcapparser(left_pcap)
            self.right_parser = pcapparser(right_pcap)
            
            # Load packets
            left_packets = self.left_parser.load()
            right_packets = self.right_parser.load()
            
            if not left_packets:
                print(f"Error: No packets found in left PCAP: {left_pcap}")
                return False
            if not right_packets:
                print(f"Error: No packets found in right PCAP: {right_pcap}")
                return False
                
            print(f"Loaded {len(left_packets)} packets from left PCAP")
            print(f"Loaded {len(right_packets)} packets from right PCAP")
            return True
            
        except Exception as e:
            print(f"Error loading PCAP files: {e}")
            return False
    
    def _apply_jitter(self, delta: float) -> float:
        """
        Apply random jitter to a time delta.
        
        Args:
            delta (float): Original time delta
            
        Returns:
            float: Delta with jitter applied
        """
        if self.jitter_max <= 0:
            return delta
        
        # Apply jitter as a percentage of the original delta, capped by jitter_max
        jitter_range = min(abs(delta * 0.1), self.jitter_max)
        jitter = random.uniform(-jitter_range, jitter_range)
        return max(0, delta + jitter)  # Ensure positive delta
    
    def _extract_netflows_with_timing(self, parser: pcapparser) -> Dict[str, Dict]:
        """
        Extract netflows with detailed timing information.
        
        Args:
            parser (pcapparser): Parser containing loaded packets
            
        Returns:
            Dict[str, Dict]: Dictionary of netflows with timing data
        """
        packets = parser.get_packets()
        flows = {}
        
        for i, pkt in enumerate(packets):
            if not pkt.haslayer(IP):
                continue
                
            ip_layer = pkt[IP]
            flow_key = None
            protocol = None
            src_port = dst_port = 0
            
            # Extract protocol and ports
            if pkt.haslayer(TCP):
                protocol = 'TCP'
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                protocol = 'UDP'
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
            elif pkt.haslayer(ICMP):
                protocol = 'ICMP'
                src_port = dst_port = 0
            else:
                protocol = str(ip_layer.proto)
                src_port = dst_port = 0
            
            # Create unidirectional flow key to preserve separate flows
            flow_key = f"{ip_layer.src}:{src_port}->{ip_layer.dst}:{dst_port}-{protocol}"
            
            if flow_key not in flows:
                flows[flow_key] = {
                    'packets': [],
                    'timestamps': [],
                    'protocol': protocol,
                    'src_ip': ip_layer.src,
                    'src_port': src_port,
                    'dst_ip': ip_layer.dst,
                    'dst_port': dst_port
                }
            
            flows[flow_key]['packets'].append(pkt)
            flows[flow_key]['timestamps'].append(float(pkt.time))
        
        return flows
    
    def _calculate_flow_deltas(self, flow_data: Dict) -> List[float]:
        """
        Calculate time deltas between packets in a flow.
        
        Args:
            flow_data (Dict): Flow data containing timestamps
            
        Returns:
            List[float]: List of time deltas
        """
        timestamps = flow_data['timestamps']
        if len(timestamps) <= 1:
            return []
        
        deltas = []
        for i in range(1, len(timestamps)):
            delta = timestamps[i] - timestamps[i-1]
            deltas.append(delta)
        
        return deltas
    
    def _schedule_flow_packets(self, flow_data: Dict, start_time: float) -> List[Tuple[float, any]]:
        """
        Schedule packets from a flow with proper timing and jitter.
        
        Args:
            flow_data (Dict): Flow data with packets and timing
            start_time (float): When to start this flow
            
        Returns:
            List[Tuple[float, packet]]: List of (timestamp, packet) tuples
        """
        packets = flow_data['packets']
        if not packets:
            return []
        
        scheduled_packets = []
        current_time = start_time
        
        # First packet at start time
        scheduled_packets.append((current_time, packets[0].copy()))
        
        # Calculate deltas and schedule remaining packets
        deltas = self._calculate_flow_deltas(flow_data)
        for i, delta in enumerate(deltas):
            jittered_delta = self._apply_jitter(delta)
            current_time += jittered_delta
            
            # Copy packet and update timestamp
            pkt_copy = packets[i + 1].copy()
            scheduled_packets.append((current_time, pkt_copy))
        
        return scheduled_packets
    
    def _find_insertion_points(self, left_flows: Dict, right_flows: Dict) -> Dict[str, float]:
        """
        Find appropriate insertion points for right-side flows into left-side timeline.
        
        Args:
            left_flows (Dict): Left-side netflows
            right_flows (Dict): Right-side netflows
            
        Returns:
            Dict[str, float]: Mapping of right flow keys to insertion times
        """
        insertion_points = {}
        
        # Get the time range of left-side traffic
        all_left_times = []
        for flow_data in left_flows.values():
            all_left_times.extend(flow_data['timestamps'])
        
        if not all_left_times:
            # If no left traffic, start right flows at time 0
            base_time = 0.0
        else:
            min_time = min(all_left_times)
            max_time = max(all_left_times)
            base_time = min_time
        
        # Distribute right flows across the timeline
        right_flow_keys = list(right_flows.keys())
        if len(right_flow_keys) == 1:
            # Single flow - place it at a random point
            if all_left_times:
                insertion_points[right_flow_keys[0]] = random.uniform(min_time, max_time)
            else:
                insertion_points[right_flow_keys[0]] = 0.0
        else:
            # Multiple flows - distribute them
            if all_left_times:
                time_span = max_time - min_time
                for i, flow_key in enumerate(right_flow_keys):
                    # Distribute evenly with some randomness
                    progress = i / max(1, len(right_flow_keys) - 1)
                    base_insertion = min_time + (progress * time_span)
                    # Add some randomness (±10% of time span)
                    jitter = random.uniform(-0.1 * time_span, 0.1 * time_span)
                    insertion_points[flow_key] = max(min_time, base_insertion + jitter)
            else:
                # No left traffic, space them out starting from 0
                for i, flow_key in enumerate(right_flow_keys):
                    insertion_points[flow_key] = i * 1.0  # 1 second apart
        
        return insertion_points
    
    def merge(self, output_file: str) -> bool:
        """
        Merge the loaded PCAP files and save the result.
        
        Args:
            output_file (str): Path for the output merged PCAP file
            
        Returns:
            bool: Success status
        """
        if not self.left_parser or not self.right_parser:
            print("Error: PCAP files not loaded. Call load_pcaps() first.")
            return False
        
        try:
            # Extract netflows from both sides
            print("Extracting netflows from left PCAP...")
            left_flows = self._extract_netflows_with_timing(self.left_parser)
            
            print("Extracting netflows from right PCAP...")
            right_flows = self._extract_netflows_with_timing(self.right_parser)
            
            print(f"Left PCAP has {len(left_flows)} netflows")
            print(f"Right PCAP has {len(right_flows)} netflows")
            
            # Collect all packets with their scheduled times
            all_scheduled_packets = []
            
            # Add all left-side packets (maintain original timestamps)
            print("Scheduling left-side packets...")
            for flow_key, flow_data in left_flows.items():
                for i, pkt in enumerate(flow_data['packets']):
                    timestamp = flow_data['timestamps'][i]
                    all_scheduled_packets.append((timestamp, pkt.copy()))
            
            # Find insertion points for right-side flows
            print("Calculating insertion points for right-side flows...")
            insertion_points = self._find_insertion_points(left_flows, right_flows)
            
            # Schedule right-side packets
            print("Scheduling right-side packets...")
            for flow_key, flow_data in right_flows.items():
                start_time = insertion_points.get(flow_key, 0.0)
                scheduled_packets = self._schedule_flow_packets(flow_data, start_time)
                all_scheduled_packets.extend(scheduled_packets)
            
            # Sort all packets by timestamp
            print("Sorting packets by timestamp...")
            all_scheduled_packets.sort(key=lambda x: x[0])
            
            # Update packet timestamps and create final packet list
            print("Updating packet timestamps...")
            final_packets = []
            for timestamp, pkt in all_scheduled_packets:
                # Update the packet's timestamp
                pkt.time = timestamp
                final_packets.append(pkt)
            
            # Verify netflow count
            print("Verifying merged netflows...")
            merged_parser = pcapparser("temp")
            merged_parser.packets = final_packets
            merged_parser._loaded = True
            merged_flows = merged_parser.get_netflows()
            
            expected_flows = len(left_flows) + len(right_flows)
            actual_flows = len(merged_flows)
            
            print(f"Expected netflows: {expected_flows}")
            print(f"Actual netflows: {actual_flows}")
            
            if actual_flows != expected_flows:
                print(f"Warning: Flow count mismatch! Expected {expected_flows}, got {actual_flows}")
            
            # Save the merged PCAP
            print(f"Saving merged PCAP to {output_file}...")
            wrpcap(output_file, final_packets)
            
            print(f"Successfully merged {len(final_packets)} packets into {output_file}")
            print(f"Jitter parameter used: ±{self.jitter_max} seconds")
            
            return True
            
        except Exception as e:
            print(f"Error during merge: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def merge_pcaps(self, left_pcap: str, right_pcap: str, output_file: str) -> bool:
        """
        Convenience method to load and merge PCAP files in one call.
        
        Args:
            left_pcap (str): Path to left PCAP file
            right_pcap (str): Path to right PCAP file
            output_file (str): Path for output merged PCAP file
            
        Returns:
            bool: Success status
        """
        if not self.load_pcaps(left_pcap, right_pcap):
            return False
        
        return self.merge(output_file)
    
    def get_merge_statistics(self) -> Dict:
        """
        Get statistics about the last merge operation.
        
        Returns:
            Dict: Statistics dictionary
        """
        if not self.left_parser or not self.right_parser:
            return {}
        
        left_flows = self._extract_netflows_with_timing(self.left_parser)
        right_flows = self._extract_netflows_with_timing(self.right_parser)
        
        stats = {
            'left_packets': len(self.left_parser.get_packets()),
            'right_packets': len(self.right_parser.get_packets()),
            'left_netflows': len(left_flows),
            'right_netflows': len(right_flows),
            'total_expected_netflows': len(left_flows) + len(right_flows),
            'jitter_max': self.jitter_max
        }
        
        return stats
    
    def print_merge_info(self):
        """Print detailed information about the merge process."""
        stats = self.get_merge_statistics()
        if not stats:
            print("No merge statistics available")
            return
        
        print(f"\n{'='*60}")
        print(f"PCAP Merge Information")
        print(f"{'='*60}")
        print(f"Left PCAP:")
        print(f"  Packets: {stats['left_packets']}")
        print(f"  Netflows: {stats['left_netflows']}")
        print(f"Right PCAP:")
        print(f"  Packets: {stats['right_packets']}")
        print(f"  Netflows: {stats['right_netflows']}")
        print(f"Merge Settings:")
        print(f"  Jitter: ±{stats['jitter_max']} seconds")
        print(f"Expected Output:")
        print(f"  Total Packets: {stats['left_packets'] + stats['right_packets']}")
        print(f"  Total Netflows: {stats['total_expected_netflows']}")
        print(f"{'='*60}\n")


def main():
    """Example usage of PcapMerger"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Merge two PCAP files maintaining netflows')
    parser.add_argument('left_pcap', help='Path to left PCAP file')
    parser.add_argument('right_pcap', help='Path to right PCAP file')
    parser.add_argument('output', help='Path for output merged PCAP file')
    parser.add_argument('--jitter', type=float, default=0.1, 
                       help='Maximum jitter to apply to timestamps (seconds)')
    
    args = parser.parse_args()
    
    # Create merger with specified jitter
    merger = PcapMerger(jitter_max=args.jitter)
    
    # Print merge info
    print("Loading PCAP files...")
    if merger.load_pcaps(args.left_pcap, args.right_pcap):
        merger.print_merge_info()
        
        # Perform merge
        if merger.merge(args.output):
            print(f"\nMerge completed successfully!")
        else:
            print(f"\nMerge failed!")
            return 1
    else:
        print("Failed to load PCAP files!")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
