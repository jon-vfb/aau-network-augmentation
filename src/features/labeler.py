import os
import sys
import scapy.all as scapy
from scapy.layers.inet import IP


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
                    print(f"Time: {ts}")
    

    def extract_IP_header(self, pcap_path: str):
        packets = scapy.rdpcap(pcap_path)
        for i, pkt in enumerate(packets, start=1):
            if IP in pkt:
                ip_layer = pkt[IP]
                print(f"Packet {i}:")
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



if __name__ == "__main__":  # For testing
    labeler = Labeler()
    # Use absolute path to the test pcap file
    test_pcap = os.path.join(os.path.dirname(__file__), "testpcap", "labeltest.pcapng")
    print(labeler.extract_time(test_pcap))
    print(labeler.extract_IP_header(test_pcap))
    




