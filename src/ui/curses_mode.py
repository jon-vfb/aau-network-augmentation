import curses
import os
import sys
from typing import List, Optional, Dict, Any
import traceback

# Add the src directory to the path to import pcapparser
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from classes.pcapparser import pcapparser


class PcapCursesUI:
    def __init__(self):
        self.stdscr = None
        self.parser: Optional[pcapparser] = None
        self.current_packets = []
        self.selected_index = 0
        self.scroll_offset = 0
        self.mode = "main"  # main, packet_view, filter, search, help, modify
        self.status_message = "Welcome to PCAP Analyzer"
        self.filter_text = ""
        self.search_text = ""
        self.search_results = []
        self.colors_initialized = False
        self.modify_field = ""
        self.modify_value = ""
        self.modify_step = 0  # 0: select field, 1: enter value
        
    def init_colors(self):
        """Initialize color pairs for the interface."""
        if not self.colors_initialized and curses.has_colors():
            curses.start_color()
            curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)    # Header
            curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_CYAN)    # Selected
            curses.init_pair(3, curses.COLOR_GREEN, curses.COLOR_BLACK)   # Success
            curses.init_pair(4, curses.COLOR_RED, curses.COLOR_BLACK)     # Error
            curses.init_pair(5, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Warning
            curses.init_pair(6, curses.COLOR_MAGENTA, curses.COLOR_BLACK) # Info
            curses.init_pair(7, curses.COLOR_CYAN, curses.COLOR_BLACK)    # Highlight
            self.colors_initialized = True

    def draw_header(self):
        """Draw the header bar with title and file info."""
        height, width = self.stdscr.getmaxyx()
        
        # Clear header line
        self.stdscr.hline(0, 0, ' ', width)
        
        # Title
        title = "PCAP Network Analyzer"
        if self.parser:
            filename = os.path.basename(self.parser.filename)
            title += f" - {filename}"
        
        # Draw header with color
        self.stdscr.addstr(0, 0, title[:width-1], curses.color_pair(1) | curses.A_BOLD)
        
        # Packet count info
        if self.parser:
            packet_info = f"Packets: {len(self.current_packets)}"
            if len(packet_info) < width - len(title) - 5:
                self.stdscr.addstr(0, width - len(packet_info) - 1, packet_info, curses.color_pair(1))

    def draw_status_bar(self):
        """Draw the status bar at the bottom."""
        height, width = self.stdscr.getmaxyx()
        status_y = height - 1
        
        # Clear status line
        self.stdscr.hline(status_y, 0, ' ', width)
        
        # Status message
        self.stdscr.addstr(status_y, 0, self.status_message[:width-1])
        
        # Mode indicator
        mode_text = f"[{self.mode.upper()}]"
        if len(mode_text) < width - len(self.status_message) - 5:
            self.stdscr.addstr(status_y, width - len(mode_text) - 1, mode_text)

    def draw_help_bar(self):
        """Draw the help bar with key bindings."""
        height, width = self.stdscr.getmaxyx()
        help_y = height - 2
        
        # Clear help line
        self.stdscr.hline(help_y, 0, ' ', width)
        
        if self.mode == "main":
            help_text = "q:Quit | o:Open | f:Filter | s:Search | Enter:View | h:Help"
        elif self.mode == "packet_view":
            help_text = "ESC:Back | j/k:Navigate | d:Delete | m:Modify | s:Save"
        elif self.mode == "filter":
            help_text = "ESC:Cancel | Enter:Apply | Tab:Protocol/IP/Port filters"
        elif self.mode == "search":
            help_text = "ESC:Cancel | Enter:Search | n:Next result"
        elif self.mode == "modify":
            if self.modify_step == 0:
                help_text = "ESC:Cancel | Enter:Select field | 1-8:Field number"
            else:
                help_text = "ESC:Cancel | Enter:Apply | Backspace:Delete"
        else:
            help_text = "ESC:Back | q:Quit"
        
        self.stdscr.addstr(help_y, 0, help_text[:width-1], curses.color_pair(7))

    def draw_packet_list(self):
        """Draw the main packet list."""
        height, width = self.stdscr.getmaxyx()
        start_y = 1
        end_y = height - 3
        visible_lines = end_y - start_y
        
        # Headers
        headers = f"{'#':<6} {'Time':<12} {'Source':<18} {'Dest':<18} {'Proto':<8} {'Info'}"
        self.stdscr.addstr(start_y, 0, headers[:width-1], curses.color_pair(1) | curses.A_UNDERLINE)
        
        # Packet entries
        for i in range(visible_lines - 1):
            packet_index = self.scroll_offset + i
            if packet_index >= len(self.current_packets):
                break
                
            y_pos = start_y + 1 + i
            packet = self.current_packets[packet_index]
            
            # Format packet info
            pkt_num = str(packet_index).ljust(6)
            
            # Extract timestamp (simplified)
            timestamp = f"{packet.time:.3f}"[-12:] if hasattr(packet, 'time') else "N/A"
            timestamp = timestamp.ljust(12)
            
            # Extract source and destination
            src = "N/A"
            dst = "N/A"
            proto = "Unknown"
            info = packet.summary()[:30] if hasattr(packet, 'summary') else "N/A"
            
            if hasattr(packet, 'haslayer'):
                from scapy.all import IP, TCP, UDP, ICMP, ARP
                
                if packet.haslayer(IP):
                    src = str(packet[IP].src)[:17]
                    dst = str(packet[IP].dst)[:17]
                    
                    if packet.haslayer(TCP):
                        proto = "TCP"
                        info = f"{packet[TCP].sport}->{packet[TCP].dport}"
                    elif packet.haslayer(UDP):
                        proto = "UDP" 
                        info = f"{packet[UDP].sport}->{packet[UDP].dport}"
                    elif packet.haslayer(ICMP):
                        proto = "ICMP"
                        info = f"Type {packet[ICMP].type}"
                elif packet.haslayer(ARP):
                    proto = "ARP"
                    src = str(packet[ARP].psrc)[:17] if hasattr(packet[ARP], 'psrc') else "N/A"
                    dst = str(packet[ARP].pdst)[:17] if hasattr(packet[ARP], 'pdst') else "N/A"
            
            src = src.ljust(18)
            dst = dst.ljust(18)
            proto = proto.ljust(8)
            
            line = f"{pkt_num}{timestamp}{src}{dst}{proto}{info}"
            
            # Highlight selected line
            if packet_index == self.selected_index:
                self.stdscr.addstr(y_pos, 0, line[:width-1], curses.color_pair(2) | curses.A_BOLD)
            else:
                self.stdscr.addstr(y_pos, 0, line[:width-1])

    def draw_packet_detail(self):
        """Draw detailed packet information."""
        height, width = self.stdscr.getmaxyx()
        
        if not self.current_packets or self.selected_index >= len(self.current_packets):
            self.stdscr.addstr(2, 0, "No packet selected")
            return
            
        packet = self.current_packets[self.selected_index]
        
        # Title
        title = f"Packet #{self.selected_index} Details"
        self.stdscr.addstr(1, 0, title, curses.color_pair(1) | curses.A_BOLD)
        
        # Get packet details
        try:
            # Use packet.show() to get detailed info
            import io
            from contextlib import redirect_stdout
            
            f = io.StringIO()
            with redirect_stdout(f):
                packet.show()
            details = f.getvalue().split('\n')
            
            # Display details with scrolling
            start_y = 3
            max_lines = height - 5
            
            for i, line in enumerate(details[:max_lines]):
                if start_y + i < height - 2:
                    self.stdscr.addstr(start_y + i, 0, line[:width-1])
                    
        except Exception as e:
            self.stdscr.addstr(3, 0, f"Error displaying packet details: {str(e)}")

    def draw_filter_dialog(self):
        """Draw the filter dialog."""
        height, width = self.stdscr.getmaxyx()
        
        # Dialog box
        dialog_height = 10
        dialog_width = min(60, width - 4)
        start_y = (height - dialog_height) // 2
        start_x = (width - dialog_width) // 2
        
        # Draw dialog background
        for y in range(dialog_height):
            self.stdscr.hline(start_y + y, start_x, ' ', dialog_width)
        
        # Draw border
        self.stdscr.addstr(start_y, start_x, "┌" + "─" * (dialog_width - 2) + "┐")
        for y in range(1, dialog_height - 1):
            self.stdscr.addstr(start_y + y, start_x, "│")
            self.stdscr.addstr(start_y + y, start_x + dialog_width - 1, "│")
        self.stdscr.addstr(start_y + dialog_height - 1, start_x, "└" + "─" * (dialog_width - 2) + "┘")
        
        # Title
        title = "Filter Packets"
        self.stdscr.addstr(start_y + 1, start_x + 2, title, curses.color_pair(1) | curses.A_BOLD)
        
        # Filter options
        options = [
            "1. Filter by Protocol (TCP/UDP/ICMP/HTTP/DNS/ARP)",
            "2. Filter by IP Address",
            "3. Filter by Port",
            "4. Clear all filters",
            "",
            "Enter filter text:"
        ]
        
        for i, option in enumerate(options):
            self.stdscr.addstr(start_y + 2 + i, start_x + 2, option[:dialog_width-4])
        
        # Input field
        self.stdscr.addstr(start_y + 8, start_x + 2, self.filter_text[:dialog_width-4])
        self.stdscr.addstr(start_y + 8, start_x + 2 + len(self.filter_text), "_")

    def draw_search_dialog(self):
        """Draw the search dialog."""
        height, width = self.stdscr.getmaxyx()
        
        # Dialog box
        dialog_height = 8
        dialog_width = min(50, width - 4)
        start_y = (height - dialog_height) // 2
        start_x = (width - dialog_width) // 2
        
        # Draw dialog background
        for y in range(dialog_height):
            self.stdscr.hline(start_y + y, start_x, ' ', dialog_width)
        
        # Draw border
        self.stdscr.addstr(start_y, start_x, "┌" + "─" * (dialog_width - 2) + "┐")
        for y in range(1, dialog_height - 1):
            self.stdscr.addstr(start_y + y, start_x, "│")
            self.stdscr.addstr(start_y + y, start_x + dialog_width - 1, "│")
        self.stdscr.addstr(start_y + dialog_height - 1, start_x, "└" + "─" * (dialog_width - 2) + "┘")
        
        # Title
        title = "Search Packets"
        self.stdscr.addstr(start_y + 1, start_x + 2, title, curses.color_pair(1) | curses.A_BOLD)
        
        # Instructions
        self.stdscr.addstr(start_y + 3, start_x + 2, "Search in packet payload:")
        
        # Input field
        self.stdscr.addstr(start_y + 5, start_x + 2, self.search_text[:dialog_width-4])
        self.stdscr.addstr(start_y + 5, start_x + 2 + len(self.search_text), "_")
        
        # Results info
        if self.search_results:
            result_info = f"Found: {len(self.search_results)} matches"
            self.stdscr.addstr(start_y + 6, start_x + 2, result_info)

    def draw_modify_dialog(self):
        """Draw the packet modification dialog."""
        height, width = self.stdscr.getmaxyx()
        
        # Dialog box
        dialog_height = 15
        dialog_width = min(70, width - 4)
        start_y = (height - dialog_height) // 2
        start_x = (width - dialog_width) // 2
        
        # Draw dialog background
        for y in range(dialog_height):
            self.stdscr.hline(start_y + y, start_x, ' ', dialog_width)
        
        # Draw border
        self.stdscr.addstr(start_y, start_x, "┌" + "─" * (dialog_width - 2) + "┐")
        for y in range(1, dialog_height - 1):
            self.stdscr.addstr(start_y + y, start_x, "│")
            self.stdscr.addstr(start_y + y, start_x + dialog_width - 1, "│")
        self.stdscr.addstr(start_y + dialog_height - 1, start_x, "└" + "─" * (dialog_width - 2) + "┘")
        
        # Title
        title = "Modify Packet"
        self.stdscr.addstr(start_y + 1, start_x + 2, title, curses.color_pair(1) | curses.A_BOLD)
        
        if self.modify_step == 0:
            # Field selection step
            instructions = [
                "Select field to modify:",
                "",
                "1. IP Source Address",
                "2. IP Destination Address", 
                "3. TCP/UDP Source Port",
                "4. TCP/UDP Destination Port",
                "5. TCP Flags (for TCP packets)",
                "6. Payload Data",
                "7. TTL (Time To Live)",
                "8. Packet Size",
                ""
            ]
            
            for i, instruction in enumerate(instructions):
                if start_y + 3 + i < start_y + dialog_height - 2:
                    self.stdscr.addstr(start_y + 3 + i, start_x + 2, instruction[:dialog_width-4])
            
            self.stdscr.addstr(start_y + dialog_height - 3, start_x + 2, "Enter field number (1-8):")
            
        else:
            # Value entry step
            field_names = {
                "1": "IP Source Address",
                "2": "IP Destination Address",
                "3": "TCP/UDP Source Port", 
                "4": "TCP/UDP Destination Port",
                "5": "TCP Flags",
                "6": "Payload Data",
                "7": "TTL",
                "8": "Packet Size"
            }
            
            field_name = field_names.get(self.modify_field, "Unknown")
            self.stdscr.addstr(start_y + 3, start_x + 2, f"Modifying: {field_name}")
            
            # Show current value if possible
            if self.current_packets and self.selected_index < len(self.current_packets):
                packet = self.current_packets[self.selected_index]
                current_val = self.get_current_field_value(packet, self.modify_field)
                if current_val:
                    self.stdscr.addstr(start_y + 5, start_x + 2, f"Current: {current_val}")
            
            self.stdscr.addstr(start_y + 7, start_x + 2, "New value:")
            self.stdscr.addstr(start_y + 9, start_x + 2, self.modify_value[:dialog_width-4])
            self.stdscr.addstr(start_y + 9, start_x + 2 + len(self.modify_value), "_")
            
            # Instructions
            self.stdscr.addstr(start_y + 11, start_x + 2, "Press Enter to apply, ESC to cancel")

    def get_current_field_value(self, packet, field_id):
        """Get the current value of a field in the packet."""
        try:
            from scapy.all import IP, TCP, UDP, Raw
            
            if field_id == "1" and packet.haslayer(IP):
                return str(packet[IP].src)
            elif field_id == "2" and packet.haslayer(IP):
                return str(packet[IP].dst)
            elif field_id == "3":
                if packet.haslayer(TCP):
                    return str(packet[TCP].sport)
                elif packet.haslayer(UDP):
                    return str(packet[UDP].sport)
            elif field_id == "4":
                if packet.haslayer(TCP):
                    return str(packet[TCP].dport)
                elif packet.haslayer(UDP):
                    return str(packet[UDP].dport)
            elif field_id == "5" and packet.haslayer(TCP):
                return f"0x{packet[TCP].flags:02x}"
            elif field_id == "6" and packet.haslayer(Raw):
                payload = packet[Raw].load
                if len(payload) > 50:
                    return f"{payload[:47]}..."
                return str(payload)
            elif field_id == "7" and packet.haslayer(IP):
                return str(packet[IP].ttl)
            elif field_id == "8":
                return str(len(packet))
        except Exception:
            pass
        return "N/A"

    def apply_packet_modification(self):
        """Apply the modification to the current packet."""
        if not self.current_packets or self.selected_index >= len(self.current_packets):
            self.status_message = "No packet selected"
            return False
            
        try:
            from scapy.all import IP, TCP, UDP, Raw
            
            packet = self.current_packets[self.selected_index]
            original_packet = packet.copy()
            
            # Apply modification based on field
            if self.modify_field == "1" and packet.haslayer(IP):
                packet[IP].src = self.modify_value
            elif self.modify_field == "2" and packet.haslayer(IP):
                packet[IP].dst = self.modify_value
            elif self.modify_field == "3":
                port = int(self.modify_value)
                if packet.haslayer(TCP):
                    packet[TCP].sport = port
                elif packet.haslayer(UDP):
                    packet[UDP].sport = port
            elif self.modify_field == "4":
                port = int(self.modify_value)
                if packet.haslayer(TCP):
                    packet[TCP].dport = port
                elif packet.haslayer(UDP):
                    packet[UDP].dport = port
            elif self.modify_field == "5" and packet.haslayer(TCP):
                # TCP flags - accept hex or decimal
                if self.modify_value.startswith("0x"):
                    flags = int(self.modify_value, 16)
                else:
                    flags = int(self.modify_value)
                packet[TCP].flags = flags
            elif self.modify_field == "6":
                # Payload modification
                if packet.haslayer(Raw):
                    packet[Raw].load = self.modify_value.encode()
                else:
                    packet = packet / Raw(load=self.modify_value.encode())
            elif self.modify_field == "7" and packet.haslayer(IP):
                packet[IP].ttl = int(self.modify_value)
            elif self.modify_field == "8":
                # Packet size - this is more complex, just pad or truncate payload
                current_size = len(packet)
                target_size = int(self.modify_value)
                if target_size > current_size and packet.haslayer(Raw):
                    # Pad with zeros
                    padding = b'\x00' * (target_size - current_size)
                    packet[Raw].load += padding
                elif target_size < current_size and packet.haslayer(Raw):
                    # Truncate payload
                    payload = packet[Raw].load
                    new_payload_size = len(payload) - (current_size - target_size)
                    if new_payload_size > 0:
                        packet[Raw].load = payload[:new_payload_size]
            
            # Recalculate checksums
            if packet.haslayer(IP):
                del packet[IP].chksum
            if packet.haslayer(TCP):
                del packet[TCP].chksum
            if packet.haslayer(UDP):
                del packet[UDP].chksum
            
            # Update the packet in the list
            self.current_packets[self.selected_index] = packet
            
            # Update in the parser if it's the original packet list
            if self.parser and self.current_packets == self.parser.get_packets():
                # Find and update in the original parser
                def modifier_func(pkt):
                    return packet if pkt == original_packet else pkt
                
                # This is a bit hacky, but we need to update the parser's packet list
                original_packets = self.parser.get_packets()
                for i, pkt in enumerate(original_packets):
                    if pkt == original_packet:
                        original_packets[i] = packet
                        break
            
            self.status_message = f"Modified packet field successfully"
            return True
            
        except ValueError as e:
            self.status_message = f"Invalid value: {str(e)}"
            return False
        except Exception as e:
            self.status_message = f"Modification error: {str(e)}"
            return False

    def draw_help_screen(self):
        """Draw the help screen."""
        height, width = self.stdscr.getmaxyx()
        
        help_text = [
            "PCAP Network Analyzer - Help",
            "",
            "Main View Commands:",
            "  q, Q          - Quit application",
            "  o, O          - Open PCAP file",
            "  h, H, F1      - Show this help",
            "  f, F          - Filter packets",
            "  s, S          - Search packets",
            "  Enter, Space  - View packet details",
            "  j, Down       - Move down",
            "  k, Up         - Move up",
            "  g, Home       - Go to first packet",
            "  G, End        - Go to last packet",
            "  Page Down     - Scroll down page",
            "  Page Up       - Scroll up page",
            "",
            "Packet Detail View:",
            "  ESC           - Return to main view",
            "  j, k          - Navigate packets",
            "  d             - Delete packet",
            "  m             - Modify packet (opens modification dialog)",
            "  s             - Save changes",
            "  i             - Show packet info/statistics",
            "",
            "Filter Options:",
            "  Protocol filters: TCP, UDP, ICMP, HTTP, DNS, ARP",
            "  IP filters: src:1.2.3.4 or dst:1.2.3.4 or 1.2.3.4",
            "  Port filters: port:80 or sport:443 or dport:22",
            "",
            "Modify Options:",
            "  1. IP Source/Dest - Enter IP address (e.g., 192.168.1.1)",
            "  2. Ports - Enter port number (e.g., 80, 443)",
            "  3. TCP Flags - Enter hex (0x18) or decimal (24)",
            "  4. Payload - Enter text or hex data",
            "  5. TTL - Enter number (1-255)",
            "",
            "Press ESC to return to main view"
        ]
        
        start_y = 2
        for i, line in enumerate(help_text):
            if start_y + i < height - 2:
                if i == 0:  # Title
                    self.stdscr.addstr(start_y + i, 2, line, curses.color_pair(1) | curses.A_BOLD)
                elif line.startswith("  "):  # Command descriptions
                    self.stdscr.addstr(start_y + i, 2, line[:width-4])
                else:  # Section headers
                    self.stdscr.addstr(start_y + i, 2, line, curses.color_pair(7) | curses.A_BOLD)

    def handle_file_open(self):
        """Handle opening a PCAP file."""
        # Simple file selection - in a real implementation, you'd want a file browser
        self.mode = "main"
        
        # For demo purposes, try to load sample files
        sample_files = []
        samples_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'samples')
        if os.path.exists(samples_dir):
            for f in os.listdir(samples_dir):
                if f.endswith(('.pcap', '.pcapng')):
                    sample_files.append(os.path.join(samples_dir, f))
        
        if sample_files:
            # Load the first sample file found
            try:
                self.parser = pcapparser(sample_files[0])
                self.current_packets = self.parser.load()
                self.selected_index = 0
                self.scroll_offset = 0
                self.status_message = f"Loaded {len(self.current_packets)} packets from {os.path.basename(sample_files[0])}"
            except Exception as e:
                self.status_message = f"Error loading file: {str(e)}"
        else:
            self.status_message = "No sample PCAP files found in samples/ directory"

    def apply_filter(self, filter_text: str):
        """Apply a filter to the packets."""
        if not self.parser:
            self.status_message = "No PCAP file loaded"
            return
            
        if not filter_text:
            self.current_packets = self.parser.get_packets()
            self.status_message = "Filter cleared"
            return
        
        try:
            # Parse filter
            if filter_text.lower() in ['tcp', 'udp', 'icmp', 'http', 'dns', 'arp']:
                # Protocol filter
                filtered = self.parser.filter_by_protocol(filter_text)
                self.status_message = f"Filtered by protocol: {filter_text.upper()}"
            elif filter_text.startswith('src:'):
                # Source IP filter
                ip = filter_text[4:]
                filtered = self.parser.filter_by_ip(ip, 'src')
                self.status_message = f"Filtered by source IP: {ip}"
            elif filter_text.startswith('dst:'):
                # Destination IP filter
                ip = filter_text[4:]
                filtered = self.parser.filter_by_ip(ip, 'dst')
                self.status_message = f"Filtered by destination IP: {ip}"
            elif filter_text.startswith('port:'):
                # Port filter
                port = int(filter_text[5:])
                filtered = self.parser.filter_by_port(port)
                self.status_message = f"Filtered by port: {port}"
            elif filter_text.startswith('sport:'):
                # Source port filter
                port = int(filter_text[6:])
                filtered = self.parser.filter_by_port(port, 'src')
                self.status_message = f"Filtered by source port: {port}"
            elif filter_text.startswith('dport:'):
                # Destination port filter
                port = int(filter_text[6:])
                filtered = self.parser.filter_by_port(port, 'dst')
                self.status_message = f"Filtered by destination port: {port}"
            else:
                # Try as IP address
                filtered = self.parser.filter_by_ip(filter_text)
                self.status_message = f"Filtered by IP: {filter_text}"
            
            self.current_packets = filtered
            self.selected_index = 0
            self.scroll_offset = 0
            
        except Exception as e:
            self.status_message = f"Filter error: {str(e)}"

    def perform_search(self, search_text: str):
        """Perform a search in packet payloads."""
        if not self.parser:
            self.status_message = "No PCAP file loaded"
            return
            
        if not search_text:
            self.search_results = []
            self.status_message = "Search cleared"
            return
        
        try:
            self.search_results = self.parser.search_packets(search_text)
            if self.search_results:
                # Jump to first result
                self.selected_index = self.search_results[0]
                self.update_scroll()
                self.status_message = f"Found {len(self.search_results)} matches"
            else:
                self.status_message = f"No matches found for '{search_text}'"
                
        except Exception as e:
            self.status_message = f"Search error: {str(e)}"

    def update_scroll(self):
        """Update scroll offset to keep selected item visible."""
        height, width = self.stdscr.getmaxyx()
        visible_lines = height - 5  # Account for header, help, status bars
        
        if self.selected_index < self.scroll_offset:
            self.scroll_offset = self.selected_index
        elif self.selected_index >= self.scroll_offset + visible_lines:
            self.scroll_offset = self.selected_index - visible_lines + 1

    def handle_input(self, key):
        """Handle keyboard input based on current mode."""
        if self.mode == "main":
            return self.handle_main_input(key)
        elif self.mode == "packet_view":
            return self.handle_packet_view_input(key)
        elif self.mode == "filter":
            return self.handle_filter_input(key)
        elif self.mode == "search":
            return self.handle_search_input(key)
        elif self.mode == "modify":
            return self.handle_modify_input(key)
        elif self.mode == "help":
            return self.handle_help_input(key)
        
        return True

    def handle_main_input(self, key):
        """Handle input in main packet list mode."""
        if key in (ord('q'), ord('Q')):
            return False
        elif key in (ord('o'), ord('O')):
            self.handle_file_open()
        elif key in (ord('h'), ord('H'), curses.KEY_F1):
            self.mode = "help"
        elif key in (ord('f'), ord('F')):
            self.mode = "filter"
            self.filter_text = ""
        elif key in (ord('s'), ord('S')):
            self.mode = "search"
            self.search_text = ""
        elif key in (ord('\n'), ord(' ')):  # Enter or Space
            if self.current_packets:
                self.mode = "packet_view"
        elif key == curses.KEY_DOWN or key == ord('j'):
            if self.selected_index < len(self.current_packets) - 1:
                self.selected_index += 1
                self.update_scroll()
        elif key == curses.KEY_UP or key == ord('k'):
            if self.selected_index > 0:
                self.selected_index -= 1
                self.update_scroll()
        elif key == curses.KEY_HOME or key == ord('g'):
            self.selected_index = 0
            self.scroll_offset = 0
        elif key == curses.KEY_END or key == ord('G'):
            if self.current_packets:
                self.selected_index = len(self.current_packets) - 1
                self.update_scroll()
        elif key == curses.KEY_NPAGE:  # Page Down
            height, width = self.stdscr.getmaxyx()
            page_size = height - 5
            self.selected_index = min(self.selected_index + page_size, len(self.current_packets) - 1)
            self.update_scroll()
        elif key == curses.KEY_PPAGE:  # Page Up
            height, width = self.stdscr.getmaxyx()
            page_size = height - 5
            self.selected_index = max(self.selected_index - page_size, 0)
            self.update_scroll()
        
        return True

    def handle_packet_view_input(self, key):
        """Handle input in packet detail view mode."""
        if key == 27:  # ESC
            self.mode = "main"
        elif key == ord('j') or key == curses.KEY_DOWN:
            if self.selected_index < len(self.current_packets) - 1:
                self.selected_index += 1
        elif key == ord('k') or key == curses.KEY_UP:
            if self.selected_index > 0:
                self.selected_index -= 1
        elif key == ord('d'):
            # Delete packet
            if self.parser and self.current_packets:
                try:
                    # Find the actual index in the parser's packet list
                    packet = self.current_packets[self.selected_index]
                    original_packets = self.parser.get_packets()
                    for i, orig_pkt in enumerate(original_packets):
                        if orig_pkt == packet:
                            if self.parser.remove_packet(i):
                                self.current_packets = self.parser.get_packets()
                                if self.selected_index >= len(self.current_packets):
                                    self.selected_index = len(self.current_packets) - 1
                                self.status_message = f"Deleted packet #{i}"
                            break
                except Exception as e:
                    self.status_message = f"Error deleting packet: {str(e)}"
        elif key == ord('m'):
            # Modify packet
            self.mode = "modify"
            self.modify_step = 0
            self.modify_field = ""
            self.modify_value = ""
        elif key == ord('i'):
            # Show packet info
            if self.current_packets and self.selected_index < len(self.current_packets):
                packet = self.current_packets[self.selected_index]
                try:
                    # Get basic packet info
                    size = len(packet)
                    layers = []
                    pkt_copy = packet
                    while pkt_copy:
                        layers.append(pkt_copy.__class__.__name__)
                        pkt_copy = pkt_copy.payload if hasattr(pkt_copy, 'payload') else None
                        if pkt_copy.__class__.__name__ == 'NoPayload':
                            break
                    
                    info = f"Size: {size} bytes, Layers: {' -> '.join(layers[:5])}"
                    self.status_message = info
                except Exception as e:
                    self.status_message = f"Error getting packet info: {str(e)}"
        elif key == ord('s'):
            # Save file
            if self.parser:
                try:
                    self.parser.save()
                    self.status_message = "File saved successfully"
                except Exception as e:
                    self.status_message = f"Error saving file: {str(e)}"
        
        return True

    def handle_filter_input(self, key):
        """Handle input in filter mode."""
        if key == 27:  # ESC
            self.mode = "main"
        elif key == ord('\n'):  # Enter
            self.apply_filter(self.filter_text)
            self.mode = "main"
        elif key == curses.KEY_BACKSPACE or key == 127:
            if self.filter_text:
                self.filter_text = self.filter_text[:-1]
        elif 32 <= key <= 126:  # Printable characters
            self.filter_text += chr(key)
        
        return True

    def handle_search_input(self, key):
        """Handle input in search mode."""
        if key == 27:  # ESC
            self.mode = "main"
        elif key == ord('\n'):  # Enter
            self.perform_search(self.search_text)
            self.mode = "main"
        elif key == ord('n'):  # Next result
            if self.search_results and len(self.search_results) > 1:
                current_pos = self.search_results.index(self.selected_index) if self.selected_index in self.search_results else -1
                next_pos = (current_pos + 1) % len(self.search_results)
                self.selected_index = self.search_results[next_pos]
                self.update_scroll()
        elif key == curses.KEY_BACKSPACE or key == 127:
            if self.search_text:
                self.search_text = self.search_text[:-1]
        elif 32 <= key <= 126:  # Printable characters
            self.search_text += chr(key)
        
        return True

    def handle_modify_input(self, key):
        """Handle input in modify mode."""
        if key == 27:  # ESC
            self.mode = "packet_view"
        elif key == ord('\n'):  # Enter
            if self.modify_step == 0:
                # Field selection step
                if self.modify_field in ['1', '2', '3', '4', '5', '6', '7', '8']:
                    self.modify_step = 1
                    self.modify_value = ""
            else:
                # Apply modification
                if self.apply_packet_modification():
                    self.mode = "packet_view"
                    self.modify_step = 0
                    self.modify_field = ""
                    self.modify_value = ""
        elif self.modify_step == 0:
            # Field selection
            if ord('1') <= key <= ord('8'):
                self.modify_field = chr(key)
        elif self.modify_step == 1:
            # Value entry
            if key == curses.KEY_BACKSPACE or key == 127:
                if self.modify_value:
                    self.modify_value = self.modify_value[:-1]
            elif 32 <= key <= 126:  # Printable characters
                self.modify_value += chr(key)
        
        return True

    def handle_help_input(self, key):
        """Handle input in help mode."""
        if key == 27:  # ESC
            self.mode = "main"
        return True

    def run(self, stdscr):
        """Main UI loop."""
        self.stdscr = stdscr
        self.init_colors()
        
        # Configure curses
        curses.curs_set(0)  # Hide cursor
        stdscr.keypad(True)  # Enable special keys
        stdscr.nodelay(False)  # Blocking input
        
        # Load sample file on startup
        self.handle_file_open()
        
        running = True
        while running:
            try:
                # Clear screen
                stdscr.clear()
                
                # Draw interface based on mode
                self.draw_header()
                
                if self.mode == "main":
                    self.draw_packet_list()
                elif self.mode == "packet_view":
                    self.draw_packet_detail()
                elif self.mode == "filter":
                    self.draw_packet_list()
                    self.draw_filter_dialog()
                elif self.mode == "search":
                    self.draw_packet_list()
                    self.draw_search_dialog()
                elif self.mode == "modify":
                    self.draw_packet_detail()
                    self.draw_modify_dialog()
                elif self.mode == "help":
                    self.draw_help_screen()
                
                self.draw_help_bar()
                self.draw_status_bar()
                
                # Refresh screen
                stdscr.refresh()
                
                # Get input
                key = stdscr.getch()
                running = self.handle_input(key)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.status_message = f"Error: {str(e)}"


def run_curses_ui():
    """Run the curses-based PCAP analyzer UI."""
    ui = PcapCursesUI()
    try:
        curses.wrapper(ui.run)
    except Exception as e:
        print(f"Error running curses UI: {e}")
        traceback.print_exc()