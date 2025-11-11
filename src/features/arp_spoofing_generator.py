from scapy.all import Ether, ARP, wrpcap, rdpcap
from scapy.layers.inet import IP
from typing import List, Optional
import random
import time

def extract_intervals_from_pcap(pcap_path):
    """
    Extract inter-packet intervals from a benign PCAP file.
    Returns a list of time differences between consecutive packets.
    """
    packets = rdpcap(pcap_path)
    times = [pkt.time for pkt in packets]
    intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
    # Filter out any zero or negative intervals (shouldn't happen, but just in case)
    intervals = [i for i in intervals if i > 0]
    return intervals

def generate_timestamps(num_packets, intervals, start_time=None):
    """
    Generate a list of timestamps for attack packets using sampled intervals.
    """
    if not intervals:
        # Fallback: use 0.1s interval if none found
        intervals = [0.1]
    if start_time is None:
        start_time = time.time()
    timestamps = [start_time]
    for i in range(num_packets - 1):
        interval = random.choice(intervals)
        timestamps.append(timestamps[-1] + interval)
    return timestamps

def extract_macs_from_pcap(pcap_path, victim_ip: Optional[str] = None, gateway_ip: Optional[str] = None):
    """
    Scan a pcap and try to find the Ethernet MAC addresses for the given
    victim_ip and gateway_ip. Returns (victim_mac, gateway_mac) or (None, None)
    when not found.
    """
    packets = rdpcap(pcap_path)
    victim_mac = None
    gateway_mac = None
    for pkt in packets:
        # Only examine packets that have IP and Ether layers
        if pkt.haslayer(IP) and hasattr(pkt, 'src'):
            try:
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
            except Exception:
                continue
            # Ether src/dst may be present as pkt.src / pkt.dst
            eth_src = getattr(pkt, 'src', None)
            eth_dst = getattr(pkt, 'dst', None)
            if victim_ip:
                if ip_src == victim_ip and eth_src:
                    victim_mac = eth_src
                elif ip_dst == victim_ip and eth_dst:
                    victim_mac = eth_dst
            if gateway_ip:
                if ip_src == gateway_ip and eth_src:
                    gateway_mac = eth_src
                elif ip_dst == gateway_ip and eth_dst:
                    gateway_mac = eth_dst
        # early exit if both resolved
        if (not victim_ip or victim_mac) and (not gateway_ip or gateway_mac):
            break
    return victim_mac, gateway_mac

def make_mac_with_oui(oui: str) -> str:
    """Given an OUI like 'aa:bb:cc', generate a random MAC that starts with that OUI."""
    parts = oui.split(":")
    if len(parts) != 3:
        # invalid OUI, fallback to random
        mac = [random.randint(0, 255) for _ in range(6)]
        mac[0] = (mac[0] & 0xfc) | 0x02
        return ':'.join([f"{x:02x}" for x in mac])
    tail = [random.randint(0, 255) for _ in range(3)]
    mac_parts = parts + [f"{x:02x}" for x in tail]
    return ':'.join(mac_parts)


def extract_ips_from_pcap(pcap_path):
    """Return a list of unique IPv4 addresses seen in the pcap (src and dst)."""
    packets = rdpcap(pcap_path)
    ips = []
    for pkt in packets:
        if pkt.haslayer(IP):
            try:
                s = pkt[IP].src
                d = pkt[IP].dst
            except Exception:
                continue
            if s not in ips:
                ips.append(s)
            if d not in ips:
                ips.append(d)
    return ips


class ARPSpoofGenerator:
    """Generator for creating ARP spoofing attack traffic"""
    def __init__(self, 
                 victim_ip: str,
                 victim_mac: str,
                 gateway_ip: str,
                 gateway_mac: str,
                 attacker_mac: Optional[str] = None):
        """
        Initialize the ARP spoof generator
        
        Args:
            victim_ip: IP address of the victim
            victim_mac: MAC address of the victim
            gateway_ip: IP address of the gateway/router
            gateway_mac: MAC address of the gateway/router
            attacker_mac: MAC address of the attacker (generated if None)
        """
        self.victim_ip = victim_ip
        self.victim_mac = victim_mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.attacker_mac = attacker_mac or self._generate_mac()
        
    def _generate_mac(self) -> str:
        """Generate a random MAC address"""
        # Generate random MAC but keep the locally administered bit set
        mac = [random.randint(0, 255) for _ in range(6)]
        mac[0] = (mac[0] & 0xfc) | 0x02  # Set locally administered bit
        return ':'.join([f"{x:02x}" for x in mac])
    
    def generate_spoof_packets(self, 
         num_packets: int = 10,
         interval_seconds: float = 1.0,
         start_time: Optional[float] = None) -> List[Ether]:
        """
        Generate a sequence of ARP packets including:
        1. Initial legitimate ARP traffic
        2. Attack traffic with spoofed packets
        3. Victim/gateway responses
        
        Args:
            num_packets: Number of ARP packet sequences to generate
            interval_seconds: Base time interval between packets
            start_time: Starting timestamp (default: current time)
            
        Returns:
            List of Scapy packets representing the complete ARP traffic
        """
        if start_time is None:
            start_time = time.time()
            
        packets = []
        current_time = start_time
        
        # 1. Add initial legitimate ARP traffic (before attack)
        # Victim asks who has gateway IP
        packets.append(
            Ether(src=self.victim_mac, dst="ff:ff:ff:ff:ff:ff") /
            ARP(
                op="who-has",  # ARP request
                hwsrc=self.victim_mac,
                hwdst="00:00:00:00:00:00",
                psrc=self.victim_ip,
                pdst=self.gateway_ip
            )
        )
        packets[-1].time = current_time
        current_time += 0.001  # 1ms later
        
        # Gateway responds with real MAC
        packets.append(
            Ether(src=self.gateway_mac, dst=self.victim_mac) /
            ARP(
                op="is-at",  # ARP reply
                hwsrc=self.gateway_mac,
                hwdst=self.victim_mac,
                psrc=self.gateway_ip,
                pdst=self.victim_ip
            )
        )
        packets[-1].time = current_time
        current_time += interval_seconds
        
        # 2. Attack sequence with responses
        for i in range(num_packets):
            # Attacker spoofs gateway -> victim: "I'm the gateway at attacker's MAC"
            packets.append(
                Ether(src=self.attacker_mac, dst=self.victim_mac) /
                ARP(
                    op="is-at",
                    hwsrc=self.attacker_mac,
                    hwdst=self.victim_mac,
                    psrc=self.gateway_ip,
                    pdst=self.victim_ip
                )
            )
            packets[-1].time = current_time
            current_time += 0.001
            
            # Victim's ARP cache update response (who-has verification)
            packets.append(
                Ether(src=self.victim_mac, dst="ff:ff:ff:ff:ff:ff") /
                ARP(
                    op="who-has",
                    hwsrc=self.victim_mac,
                    hwdst="00:00:00:00:00:00",
                    psrc=self.victim_ip,
                    pdst=self.gateway_ip
                )
            )
            packets[-1].time = current_time
            current_time += 0.001
            
            # Attacker spoofs victim -> gateway: "I'm the victim at attacker's MAC"
            packets.append(
                Ether(src=self.attacker_mac, dst=self.gateway_mac) /
                ARP(
                    op="is-at",
                    hwsrc=self.attacker_mac,
                    hwdst=self.gateway_mac,
                    psrc=self.victim_ip,
                    pdst=self.gateway_ip
                )
            )
            packets[-1].time = current_time
            current_time += 0.001
            
            # Gateway's ARP cache update response (who-has verification)
            packets.append(
                Ether(src=self.gateway_mac, dst="ff:ff:ff:ff:ff:ff") /
                ARP(
                    op="who-has",
                    hwsrc=self.gateway_mac,
                    hwdst="00:00:00:00:00:00",
                    psrc=self.gateway_ip,
                    pdst=self.victim_ip
                )
            )
            packets[-1].time = current_time
            current_time += interval_seconds
            
        return packets
    
    def save_pcap(self, 
                  filepath: str,
                  num_packets: int = 10,
                  interval_seconds: float = 1.0):
        """
        Generate complete ARP spoofing scenario and save to PCAP file.
        The scenario includes:
        1. Initial legitimate ARP traffic (victim and gateway)
        2. ARP spoofing attack packets
        3. Victim and gateway responses/verifications
        
        Args:
            filepath: Path to save the PCAP file
            num_packets: Number of attack sequences to generate
            interval_seconds: Base time interval between sequences
        """
        packets = self.generate_spoof_packets(
            num_packets=num_packets,
            interval_seconds=interval_seconds
        )
        wrpcap(filepath, packets)

    def save_pcap_with_realistic_timing(self, filepath: str, benign_pcap_path: str, num_packets: int = 10):
        """
        Generate ARP spoofing packets and save to PCAP file with realistic timestamps
        based on inter-packet intervals from a benign PCAP file.
        The first packet timestamp will match the benign PCAP's first packet.
        """
        packets = self.generate_spoof_packets(num_packets=num_packets)
        benign_packets = rdpcap(benign_pcap_path)
        intervals = extract_intervals_from_pcap(benign_pcap_path)
        start_time = benign_packets[0].time if len(benign_packets) > 0 else None
        timestamps = generate_timestamps(len(packets), intervals, start_time=start_time)
        for pkt, ts in zip(packets, timestamps):
            pkt.time = ts
        wrpcap(filepath, packets)

def main():
    """Generate an ARP spoofing PCAP using IPs, MACs and timing strictly taken from a benign PCAP.

    Behavior:
    - The benign PCAP path is required. The script extracts at least two IPs (victim and gateway),
      the corresponding MAC addresses, and the inter-packet timing. If any of these cannot be
      extracted the script fails with an error.
    - The generated PCAP will use those IPs and MACs and realistic timestamps based on the
      benign PCAP.
    """
    try:
        benign_pcap_path = input("Enter path to benign PCAP (required): ").strip()
        if not benign_pcap_path:
            print("Error: benign PCAP path is required")
            return

        # Extract IPs from benign pcap
        ips = extract_ips_from_pcap(benign_pcap_path)
        if len(ips) < 2:
            print("Error: benign PCAP must contain at least two distinct IP addresses")
            return
        victim_ip = ips[0]
        gateway_ip = ips[1]

        # Extract MACs for the selected IPs
        victim_mac, gateway_mac = extract_macs_from_pcap(benign_pcap_path, victim_ip=victim_ip, gateway_ip=gateway_ip)
        if not victim_mac or not gateway_mac:
            print("Error: could not extract both victim and gateway MAC addresses from benign PCAP")
            return

        # Prepare generator with values taken from benign pcap
        generator = ARPSpoofGenerator(
            victim_ip=victim_ip,
            victim_mac=victim_mac,
            gateway_ip=gateway_ip,
            gateway_mac=gateway_mac
        )

        # Generate a plausible attacker MAC that shares the gateway OUI but does not collide
        oui = ':'.join(gateway_mac.split(':')[:3])
        attacker_mac_candidate = make_mac_with_oui(oui)
        for _ in range(5):
            if attacker_mac_candidate not in (victim_mac, gateway_mac):
                break
            attacker_mac_candidate = make_mac_with_oui(oui)
        if attacker_mac_candidate in (victim_mac, gateway_mac):
            print("Error: failed to create non-colliding attacker MAC")
            return
        generator.attacker_mac = attacker_mac_candidate

        output_file = "arp_spoof_attack.pcap"
        # Create and save the attack pcap using benign timing and addresses
        generator.save_pcap_with_realistic_timing(
            filepath=output_file,
            benign_pcap_path=benign_pcap_path,
            num_packets=20
        )

        print("Generated ARP spoofing PCAP with realistic timing:", output_file)
        print("Attack simulation:")
        print(f"- Attacker MAC: {generator.attacker_mac}")
        print(f"- Victim: {victim_ip} ({victim_mac})")
        print(f"- Gateway: {gateway_ip} ({gateway_mac})")
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return
    except Exception as e:
        print(f"Error: {e}")
        return
    
if __name__ == "__main__":
    main()
