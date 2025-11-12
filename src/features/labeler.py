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
                'label': label,
                'timestamp': pkt.time,
                'length': len(pkt),
                'protocol': pkt.name,
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


if __name__ == "__main__":
    labeler = Labeler()
    base_dir = os.path.dirname(__file__)
    samples_dir = os.path.abspath(os.path.join(base_dir, "..", "..", "samples"))
    test_pcap = os.path.join(samples_dir, "pcaphandshake_1.pcapng")
    output_csv = os.path.join(samples_dir, "labeled_output.csv")
    labeler.label_and_export(test_pcap, output_csv, "benign")
