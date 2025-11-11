import os
import sys
import scapy.all as scapy
from scapy.layers.inet import IP
import pandas as pd


# Ensure the repository's `src` directory is on sys.path so `classes` can be imported
_THIS_DIR = os.path.dirname(__file__)
_SRC_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from classes.pcapparser import pcapparser

class Labeler:
    def __init__(self):
        pass
        
    def label_benign(self, packages, csv_path=None):
        for package in packages:
            print(":)")
        return "happy :)"
    
    def label_malicious(self, packages, csv_path=None):
        for package in packages:
            print(":(")
        return "sad"


    def extract_time(self, pcap_path: str):
        packets = scapy.rdpcap(pcap_path)
        for i, pkt in enumerate(packets, start=1):
                if IP in pkt:
                    ts = pkt.time  # packet timestamp
                    print(f"Packet {i} Time: {ts}")
    

    def extract_IP_header(self, pcap_path: str):
        packets = scapy.rdpcap(pcap_path)
        for i, pkt in enumerate(packets, start=1):
            if IP in pkt:
                ip_layer = pkt[IP]
                print(f"Packet {i}:")
                print(f"Packet {i} IP Layer:")
                ip_layer.show()  # prints all fields of the IP header
                print("-" * 40) # divider i terminalen så man kan skælne mellem pakkerne


    def print_packet_indices(self, pcap_path: str):
        """
        Load a pcap file using classes.pcapparser and print the index of each packet to the terminal.

        Args:
            pcap_path (str): Path to the pcap/pcapng file to inspect.

        This method will print one line per packet in the form:
            Packet <index>: <short summary>

        Returns:
            int: number of packets printed (or -1 on error)
        """
        try:
            parser = pcapparser(pcap_path)
            packets = parser.get_packets()
        except Exception as e:
            print(f"Error opening PCAP file '{pcap_path}': {e}")
            return -1

        if not packets:
            print(f"No packets found in '{pcap_path}'")
            return 0

        for idx, pkt in enumerate(packets):
            # Use scapy summary for a concise one-line representation
            try:
                summary = pkt.summary()
            except Exception:
                summary = str(type(pkt))
            print(f"Packet {idx}: {summary}")

        return len(packets)

    def label_packets(self, pcap_path: str, labeling_strategy: dict, output_csv: str):
        """
        Label packets based on a labeling strategy and save the results to a CSV file.

        Args:
            pcap_path (str): Path to the pcap/pcapng file to inspect.
            labeling_strategy (dict): A dictionary mapping packet indices to labels.
            output_csv (str): Path to the output CSV file.

        This method will label each packet based on the provided strategy and save the results to a CSV file.
        """
        packets = scapy.rdpcap(pcap_path)
        labeled_data = []

        for index, packet in enumerate(packets):
            label = labeling_strategy.get(index, 1)  # Default to benign (1)
            labeled_data.append({'index': index, 'label': label})

        # Save to CSV
        df = pd.DataFrame(labeled_data)
        df.to_csv(output_csv, index=False)
        print(f"Labeled packets saved to {output_csv}")


    def label_and_export(self, pcap_path: str, csv_path: str, label: str):
        """
        Label packets and export relevant information to a CSV file.

        Args:
            pcap_path (str): Path to the pcap/pcapng file to inspect.
            csv_path (str): Path to the output CSV file.
            label (str): The label to assign to each packet.

        This method will label each packet and export the relevant information to a CSV file.
        The CSV will include common fields like timestamp, index, protocol, length, and layer-specific
        information when available.
        """
        packets = scapy.rdpcap(pcap_path)
        data = []
        
        for idx, pkt in enumerate(packets):
            # Common packet information available for all packets
            packet_info = {
                'index': idx,
                'timestamp': pkt.time,
                'length': len(pkt),
                'protocol': pkt.name,
                'label': label
            }
            
            # Add IP layer information if present
            if IP in pkt:
                ip_layer = pkt[IP]
                packet_info.update({
                    'source_ip': ip_layer.src,
                    'destination_ip': ip_layer.dst,
                    'ip_version': ip_layer.version,
                    'ttl': ip_layer.ttl,
                    'ip_len': ip_layer.len
                })
            
            # Add layer specific information based on protocol
            if 'TCP' in pkt:
                tcp_layer = pkt['TCP']
                packet_info.update({
                    'source_port': tcp_layer.sport,
                    'destination_port': tcp_layer.dport,
                    'tcp_flags': tcp_layer.flags
                })
            elif 'UDP' in pkt:
                udp_layer = pkt['UDP']
                packet_info.update({
                    'source_port': udp_layer.sport,
                    'destination_port': udp_layer.dport,
                    'udp_len': udp_layer.len
                })
            elif 'ICMP' in pkt:
                icmp_layer = pkt['ICMP']
                packet_info.update({
                    'icmp_type': icmp_layer.type,
                    'icmp_code': icmp_layer.code
                })
            elif 'ARP' in pkt:
                arp_layer = pkt['ARP']
                packet_info.update({
                    'arp_op': arp_layer.op,
                    'arp_hwsrc': arp_layer.hwsrc,
                    'arp_hwdst': arp_layer.hwdst,
                    'arp_psrc': arp_layer.psrc,
                    'arp_pdst': arp_layer.pdst
                })
            
            data.append(packet_info)

        # Create a DataFrame and save to CSV
        df = pd.DataFrame(data)
        df.to_csv(csv_path, index=False)
        print(f"Data exported to {csv_path}")
        print(f"Total packets processed: {len(packets)}")


if __name__ == "__main__":  # For testing
    labeler = Labeler()
    # Use absolute path to the test pcap file
    test_pcap = os.path.join(os.path.dirname(__file__), "testpcap", "labeltest.pcapng")
    #print(labeler.extract_time(test_pcap))
    #print(labeler.extract_IP_header(test_pcap))
    labeler.label_and_export(test_pcap, "labeled_output.csv", "benign")





