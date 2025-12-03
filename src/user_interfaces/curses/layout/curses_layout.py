import curses
from typing import List, Dict, Any, Optional


class CursesLayout:
    """Handles all the UI layout and rendering for the curses interface"""
    
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.colors_initialized = False
        self.init_colors()
    
    def init_colors(self):
        """Initialize color pairs for the interface"""
        if not self.colors_initialized:
            try:
                if curses.has_colors():
                    curses.start_color()
                    
                    # Use default colors if available (better Windows compatibility)
                    if hasattr(curses, 'use_default_colors'):
                        curses.use_default_colors()
                    
                    # Define color pairs with fallbacks
                    try:
                        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)    # Header
                        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)   # Success
                        curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)     # Error
                        curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Warning
                        curses.init_pair(5, curses.COLOR_CYAN, curses.COLOR_BLACK)    # Info
                        curses.init_pair(6, curses.COLOR_MAGENTA, curses.COLOR_BLACK) # Selected
                        curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_BLACK)   # Normal
                    except curses.error:
                        # Fallback if color initialization fails
                        pass
                        
                self.colors_initialized = True
            except Exception:
                # If color initialization fails completely, continue without colors
                self.colors_initialized = True

    def get_color_pair(self, pair_num: int):
        """Safely get a color pair with fallback"""
        try:
            if curses.has_colors() and self.colors_initialized:
                return curses.color_pair(pair_num)
            else:
                return curses.A_NORMAL
        except:
            return curses.A_NORMAL
    
    def clear_screen(self):
        """Clear the entire screen"""
        self.stdscr.clear()
    
    def draw_header(self, title: str):
        """Draw the header bar with title"""
        height, width = self.stdscr.getmaxyx()
        
        # Clear header line
        self.stdscr.hline(0, 0, ' ', width)
        
        # Draw header with color
        header_text = f" {title} "
        self.stdscr.addstr(0, 0, header_text[:width-1], self.get_color_pair(1) | curses.A_BOLD)
        
        # Fill rest of header line
        remaining_width = width - len(header_text)
        if remaining_width > 0:
            self.stdscr.addstr(0, len(header_text), " " * remaining_width, self.get_color_pair(1))
    
    def draw_status_bar(self, message: str, mode: str = ""):
        """Draw the status bar at the bottom"""
        height, width = self.stdscr.getmaxyx()
        status_y = height - 1
        
        # Clear status line
        self.stdscr.hline(status_y, 0, ' ', width)
        
        # Status message
        self.stdscr.addstr(status_y, 0, message[:width-20])
        
        # Mode indicator
        if mode:
            mode_text = f"[{mode.upper()}]"
            if len(mode_text) < 15:
                self.stdscr.addstr(status_y, width - len(mode_text) - 1, mode_text, curses.color_pair(5))
    
    def draw_help_bar(self, help_text: str):
        """Draw the help bar with key bindings"""
        height, width = self.stdscr.getmaxyx()
        help_y = height - 2
        
        # Clear help line
        self.stdscr.hline(help_y, 0, ' ', width)
        
        self.stdscr.addstr(help_y, 0, help_text[:width-1], curses.color_pair(7))
    
    def draw_pcap_list(self, pcap_files: List[str], selected_index: int, scroll_offset: int):
        """Draw the list of available PCAP files"""
        height, width = self.stdscr.getmaxyx()
        start_y = 2
        end_y = height - 3
        visible_lines = end_y - start_y
        
        # Title
        title = "Available PCAP Files:"
        self.stdscr.addstr(start_y, 2, title, curses.color_pair(1) | curses.A_BOLD)
        
        if not pcap_files:
            self.stdscr.addstr(start_y + 2, 4, "No PCAP files found in samples directory", curses.color_pair(3))
            return
        
        # File entries
        for i in range(visible_lines - 2):
            file_index = i + scroll_offset
            if file_index >= len(pcap_files):
                break
            
            y_pos = start_y + 2 + i
            filename = os.path.basename(pcap_files[file_index])
            
            # Highlight selected item
            if file_index == selected_index:
                attr = curses.color_pair(6) | curses.A_REVERSE
                prefix = "> "
            else:
                attr = curses.color_pair(7)
                prefix = "  "
            
            display_text = f"{prefix}{filename}"
            self.stdscr.addstr(y_pos, 4, display_text[:width-6], attr)
    
    def draw_pcap_info(self, pcap_info: Dict[str, Any]):
        """Draw information about the selected PCAP file"""
        height, width = self.stdscr.getmaxyx()
        start_y = 2
        
        # Title
        title = f"PCAP Information: {pcap_info.get('filename', 'Unknown')}"
        self.stdscr.addstr(start_y, 2, title, curses.color_pair(1) | curses.A_BOLD)
        
        # Basic info
        info_lines = [
            f"Total Packets: {pcap_info.get('total_packets', 0)}",
            f"File Size: {pcap_info.get('file_size', 0)} bytes",
            f"Duration: {pcap_info.get('duration', 0):.2f} seconds",
            "",
            "Protocols:"
        ]
        
        # Add protocol information
        protocols = pcap_info.get('protocols', {})
        for proto, count in protocols.items():
            info_lines.append(f"  {proto}: {count} packets")
        
        info_lines.extend([
            "",
            f"Unique IP Addresses: {len(pcap_info.get('ip_addresses', {}))}"
        ])
        
        # Draw info lines
        for i, line in enumerate(info_lines):
            if start_y + 2 + i < height - 3:
                self.stdscr.addstr(start_y + 2 + i, 4, line[:width-6], curses.color_pair(7))
    
    def draw_main_menu(self, selected_option: int):
        """Draw the main menu options for PCAP viewing"""
        height, width = self.stdscr.getmaxyx()
        menu_start_y = height // 2
        
        menu_options = [
            "1. View Netflows",
            "2. Back to PCAP List"
        ]
        
        self.stdscr.addstr(menu_start_y - 1, 4, "Options:", curses.color_pair(1) | curses.A_BOLD)
        
        for i, option in enumerate(menu_options):
            y_pos = menu_start_y + i
            
            if i == selected_option:
                attr = curses.color_pair(6) | curses.A_REVERSE
                prefix = "> "
            else:
                attr = curses.color_pair(7)
                prefix = "  "
            
            display_text = f"{prefix}{option}"
            self.stdscr.addstr(y_pos, 4, display_text[:width-6], attr)
    
    def draw_netflow_list(self, netflows: List[Dict[str, Any]], selected_index: int, scroll_offset: int):
        """Draw the list of netflows"""
        height, width = self.stdscr.getmaxyx()
        start_y = 2
        # Reserve space for header(1) + title(1) + headers(1) + help(1) + status(1) = 5 lines
        content_start_y = start_y + 3  # After title and headers
        content_end_y = height - 3  # Before help and status bars
        visible_lines = content_end_y - content_start_y
        
        # Title
        title = f"Netflows ({len(netflows)} total):"
        self.stdscr.addstr(start_y, 2, title, curses.color_pair(1) | curses.A_BOLD)
        
        # Headers
        headers = f"{'#':<4} {'Source':<18} {'Dest':<18} {'Port':<8} {'Proto':<8} {'Pkts':<6} {'Bytes':<10}"
        self.stdscr.addstr(start_y + 1, 2, headers[:width-4], curses.color_pair(1) | curses.A_UNDERLINE)
        
        if not netflows:
            self.stdscr.addstr(content_start_y, 4, "No netflows found", curses.color_pair(3))
            return
        
        # Netflow entries
        for i in range(visible_lines):
            flow_index = i + scroll_offset
            if flow_index >= len(netflows):
                break
            
            y_pos = content_start_y + i
            flow = netflows[flow_index]
            
            # Format flow information
            flow_text = f"{flow_index+1:<4} {flow['src_ip']:<18} {flow['dst_ip']:<18} " \
                       f"{flow['src_port']:<8} {flow['protocol']:<8} " \
                       f"{flow['packet_count']:<6} {flow['bytes_transferred']:<10}"
            
            # Highlight selected item
            if flow_index == selected_index:
                attr = curses.color_pair(6) | curses.A_REVERSE
            else:
                attr = curses.color_pair(7)
            
            self.stdscr.addstr(y_pos, 2, flow_text[:width-4], attr)
    
    def draw_netflow_details(self, netflow_info: Dict[str, Any]):
        """Draw detailed information about a selected netflow"""
        height, width = self.stdscr.getmaxyx()
        start_y = 2
        
        # Title
        title = f"Netflow Details"
        self.stdscr.addstr(start_y, 2, title, curses.color_pair(1) | curses.A_BOLD)
        
        # Netflow details
        details = [
            f"Source: {netflow_info['src_ip']}:{netflow_info['src_port']}",
            f"Destination: {netflow_info['dst_ip']}:{netflow_info['dst_port']}",
            f"Protocol: {netflow_info['protocol']}",
            f"Packet Count: {netflow_info['packet_count']}",
            f"Bytes Transferred: {netflow_info['bytes_transferred']}",
            f"Duration: {netflow_info['last_seen'] - netflow_info['first_seen']:.2f} seconds",
            "",
            "Press 'p' to view packets in this flow"
        ]
        
        for i, detail in enumerate(details):
            if start_y + 2 + i < height - 3:
                self.stdscr.addstr(start_y + 2 + i, 4, detail[:width-6], curses.color_pair(7))
    
    def draw_packet_list(self, packets: List[Any], selected_index: int, scroll_offset: int):
        """Draw the list of packets in a netflow with detailed information"""
        height, width = self.stdscr.getmaxyx()
        start_y = 2
        # Reserve space for header(1) + title(1) + headers(1) + help(1) + status(1) = 5 lines
        content_start_y = start_y + 2  # After title and headers
        content_end_y = height - 2  # Before help and status bars
        visible_lines = content_end_y - content_start_y
        
        # Title
        title = f"Packets in Netflow ({len(packets)} total):"
        self.stdscr.addstr(start_y, 2, title, curses.color_pair(1) | curses.A_BOLD)
        
        # Enhanced headers with more information
        headers = f"{'#':<4} {'Time':<10} {'Src IP':<15} {'Dst IP':<15} {'Src Port':<8} {'Dst Port':<8} {'Proto':<6} {'Size':<6} {'Flags':<6} {'Info'}"
        self.stdscr.addstr(start_y + 1, 2, headers[:width-4], curses.color_pair(1) | curses.A_UNDERLINE)
        
        if not packets:
            self.stdscr.addstr(content_start_y, 4, "No packets found", curses.color_pair(3))
            return
        
        # Packet entries
        for i in range(visible_lines):
            packet_index = i + scroll_offset
            if packet_index >= len(packets):
                break
            
            y_pos = content_start_y + i
            packet = packets[packet_index]
            
            # Extract detailed packet information
            packet_info = self._extract_packet_info(packet)
            
            packet_text = (f"{packet_index+1:<4} {packet_info['time']:<10} {packet_info['src_ip']:<15} "
                          f"{packet_info['dst_ip']:<15} {packet_info['src_port']:<8} {packet_info['dst_port']:<8} "
                          f"{packet_info['protocol']:<6} {packet_info['size']:<6} {packet_info['flags']:<6} {packet_info['info']}")
            
            # Highlight selected item
            if packet_index == selected_index:
                attr = curses.color_pair(6) | curses.A_REVERSE
            else:
                attr = curses.color_pair(7)
            
            self.stdscr.addstr(y_pos, 2, packet_text[:width-4], attr)

    def _extract_packet_info(self, packet) -> Dict[str, str]:
        """Extract detailed information from a packet"""
        try:
            # Try to import scapy and extract proper packet info
            from scapy.all import IP, TCP, UDP, ICMP, ARP, Raw
            
            info = {
                'time': 'N/A',
                'src_ip': 'Unknown',
                'dst_ip': 'Unknown', 
                'src_port': '0',
                'dst_port': '0',
                'protocol': 'Unknown',
                'size': '0',
                'flags': '',
                'info': ''
            }
            
            # Extract timestamp
            if hasattr(packet, 'time'):
                info['time'] = f"{packet.time:.3f}"[-10:]  # Last 10 chars
            
            # Extract IP layer information
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                info['src_ip'] = str(ip_layer.src)
                info['dst_ip'] = str(ip_layer.dst)
                info['protocol'] = ip_layer.proto
                
                # TCP information
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    info['src_port'] = str(tcp_layer.sport)
                    info['dst_port'] = str(tcp_layer.dport)
                    info['protocol'] = 'TCP'
                    # Safe handling of TCP flags
                    try:
                        info['flags'] = f"0x{int(tcp_layer.flags):02x}"
                    except (ValueError, TypeError):
                        info['flags'] = str(tcp_layer.flags)
                    info['info'] = f"Seq={tcp_layer.seq} Ack={tcp_layer.ack}"
                
                # UDP information  
                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    info['src_port'] = str(udp_layer.sport)
                    info['dst_port'] = str(udp_layer.dport)
                    info['protocol'] = 'UDP'
                    info['info'] = f"Len={udp_layer.len}"
                
                # ICMP information
                elif packet.haslayer(ICMP):
                    icmp_layer = packet[ICMP]
                    info['protocol'] = 'ICMP'
                    info['info'] = f"Type={icmp_layer.type} Code={icmp_layer.code}"
            
            # ARP information
            elif packet.haslayer(ARP):
                arp_layer = packet[ARP]
                info['src_ip'] = str(arp_layer.psrc)
                info['dst_ip'] = str(arp_layer.pdst)
                info['protocol'] = 'ARP'
                info['info'] = f"Op={arp_layer.op}"
            
            # Packet size
            info['size'] = str(len(packet))
            
            # If no specific info, use packet summary
            if not info['info']:
                info['info'] = packet.summary()[:20] if hasattr(packet, 'summary') else ''
            
            return info
            
        except Exception as e:
            # Fallback to basic information
            return {
                'time': f"{getattr(packet, 'time', 0):.3f}"[-10:],
                'src_ip': str(getattr(packet, 'src', 'Unknown'))[:15],
                'dst_ip': str(getattr(packet, 'dst', 'Unknown'))[:15],
                'src_port': str(getattr(packet, 'sport', 0)),
                'dst_port': str(getattr(packet, 'dport', 0)),
                'protocol': str(getattr(packet, 'proto', 'Unknown')),
                'size': str(len(getattr(packet, 'load', b''))),
                'flags': '',
                'info': 'Error extracting info'
            }

    def _safe_format_field(self, field_value, format_spec="") -> str:
        """Safely format a Scapy field value to string"""
        try:
            if format_spec:
                # For fields that support formatting (like integers)
                if isinstance(field_value, int):
                    return format(field_value, format_spec)
                else:
                    # Convert to string first, then try formatting
                    return format(str(field_value), format_spec)
            else:
                # Simple string conversion
                return str(field_value)
        except (ValueError, TypeError):
            # Fallback to simple string conversion
            return str(field_value)

    def draw_packet_detail(self, packet, packet_index: int, scroll_offset: int = 0):
        """Draw detailed information about a specific packet with scrolling support"""
        height, width = self.stdscr.getmaxyx()
        start_y = 2
        
        # Title
        title = f"Packet Detail - Packet #{packet_index + 1}"
        self.stdscr.addstr(start_y, 2, title, self.get_color_pair(1) | curses.A_BOLD)
        
        # Calculate available space for content
        content_start_y = start_y + 2
        content_end_y = height - 2  # Reserve space for help and status bars
        visible_lines = content_end_y - content_start_y
        
        # Generate all packet detail lines first
        detail_lines = self._generate_packet_detail_lines(packet)
        
        # Apply scrolling
        start_line = min(scroll_offset, max(0, len(detail_lines) - visible_lines))
        end_line = start_line + visible_lines
        visible_detail_lines = detail_lines[start_line:end_line]
        
        # Display the visible lines
        current_y = content_start_y
        for line in visible_detail_lines:
            if current_y < content_end_y:
                # Determine color based on line content
                if line.strip().endswith(":") and not line.startswith("    "):
                    # Layer headers
                    color = self.get_color_pair(1) | curses.A_BOLD
                elif line.startswith("  ") and line.strip().endswith(":"):
                    # Sub-layer headers
                    color = self.get_color_pair(1) | curses.A_BOLD
                else:
                    # Regular content
                    color = self.get_color_pair(7)
                
                self.stdscr.addstr(current_y, 4, line[:width-6], color)
                current_y += 1
        
        # Show scroll indicator if there's more content
        if len(detail_lines) > visible_lines:
            scroll_indicator = f"[{start_line + 1}-{min(end_line, len(detail_lines))} of {len(detail_lines)}]"
            self.stdscr.addstr(start_y, width - len(scroll_indicator) - 2, scroll_indicator, self.get_color_pair(5))

    def _generate_packet_detail_lines(self, packet) -> list:
        """Generate all packet detail lines for scrolling display"""
        detail_lines = []
        
        try:
            from scapy.all import IP, TCP, UDP, ICMP, ARP, Raw, Ether
            
            # Basic packet information
            detail_lines.extend([
                f"Packet Size: {len(packet)} bytes",
                f"Timestamp: {getattr(packet, 'time', 'N/A')}",
                "",
                "Layer Information:",
            ])
            
            # Ethernet layer
            if packet.haslayer(Ether):
                eth = packet[Ether]
                detail_lines.extend([
                    "  Ethernet:",
                    f"    Source MAC: {self._safe_format_field(eth.src)}",
                    f"    Dest MAC: {self._safe_format_field(eth.dst)}",
                    f"    Type: 0x{self._safe_format_field(eth.type, '04x')}",
                    ""
                ])
            
            # IP layer
            if packet.haslayer(IP):
                ip = packet[IP]
                detail_lines.extend([
                    "  IP:",
                    f"    Version: {self._safe_format_field(ip.version)}",
                    f"    Header Length: {self._safe_format_field(ip.ihl)}",
                    f"    Type of Service: 0x{self._safe_format_field(ip.tos, '02x')}",
                    f"    Total Length: {self._safe_format_field(ip.len)}",
                    f"    Identification: {self._safe_format_field(ip.id)}",
                    f"    Flags: 0x{self._safe_format_field(ip.flags, '01x')}",
                    f"    Fragment Offset: {self._safe_format_field(ip.frag)}",
                    f"    TTL: {self._safe_format_field(ip.ttl)}",
                    f"    Protocol: {self._safe_format_field(ip.proto)}",
                    f"    Checksum: 0x{self._safe_format_field(ip.chksum, '04x')}",
                    f"    Source IP: {self._safe_format_field(ip.src)}",
                    f"    Dest IP: {self._safe_format_field(ip.dst)}",
                    ""
                ])
            
            # TCP layer
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                # Handle TCP flags safely
                try:
                    flags_hex = f"0x{int(tcp.flags):02x}"
                except (ValueError, TypeError):
                    flags_hex = str(tcp.flags)
                
                detail_lines.extend([
                    "  TCP:",
                    f"    Source Port: {self._safe_format_field(tcp.sport)}",
                    f"    Dest Port: {self._safe_format_field(tcp.dport)}",
                    f"    Sequence Number: {self._safe_format_field(tcp.seq)}",
                    f"    Ack Number: {self._safe_format_field(tcp.ack)}",
                    f"    Data Offset: {self._safe_format_field(tcp.dataofs)}",
                    f"    Flags: {flags_hex} ({self._tcp_flags_to_string(tcp.flags)})",
                    f"    Window Size: {self._safe_format_field(tcp.window)}",
                    f"    Checksum: 0x{self._safe_format_field(tcp.chksum, '04x')}",
                    f"    Urgent Pointer: {self._safe_format_field(tcp.urgptr)}",
                    ""
                ])
            
            # UDP layer
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                detail_lines.extend([
                    "  UDP:",
                    f"    Source Port: {self._safe_format_field(udp.sport)}",
                    f"    Dest Port: {self._safe_format_field(udp.dport)}",
                    f"    Length: {self._safe_format_field(udp.len)}",
                    f"    Checksum: 0x{self._safe_format_field(udp.chksum, '04x')}",
                    ""
                ])
            
            # ICMP layer
            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                detail_lines.extend([
                    "  ICMP:",
                    f"    Type: {self._safe_format_field(icmp.type)}",
                    f"    Code: {self._safe_format_field(icmp.code)}",
                    f"    Checksum: 0x{self._safe_format_field(icmp.chksum, '04x')}",
                    f"    ID: {self._safe_format_field(icmp.id)}",
                    f"    Sequence: {self._safe_format_field(icmp.seq)}",
                    ""
                ])
            
            # ARP layer
            if packet.haslayer(ARP):
                arp = packet[ARP]
                detail_lines.extend([
                    "  ARP:",
                    f"    Hardware Type: {self._safe_format_field(arp.hwtype)}",
                    f"    Protocol Type: 0x{self._safe_format_field(arp.ptype, '04x')}",
                    f"    Hardware Size: {self._safe_format_field(arp.hwlen)}",
                    f"    Protocol Size: {self._safe_format_field(arp.plen)}",
                    f"    Operation: {self._safe_format_field(arp.op)}",
                    f"    Sender HW Addr: {self._safe_format_field(arp.hwsrc)}",
                    f"    Sender Protocol Addr: {self._safe_format_field(arp.psrc)}",
                    f"    Target HW Addr: {self._safe_format_field(arp.hwdst)}",
                    f"    Target Protocol Addr: {self._safe_format_field(arp.pdst)}",
                    ""
                ])
            
            # Raw payload
            if packet.haslayer(Raw):
                raw = packet[Raw]
                payload = raw.load
                
                detail_lines.extend([
                    "  Payload:",
                ])
                
                # Show hex dump of payload (first 1024 bytes to avoid excessive data)
                hex_data = payload[:1024]
                for i in range(0, len(hex_data), 16):
                    chunk = hex_data[i:i+16]
                    hex_str = ' '.join(f'{b:02x}' for b in chunk)
                    ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                    line = f"    {i:04x}: {hex_str:<48} {ascii_str}"
                    detail_lines.append(line)
                
                # Add info if payload was truncated
                if len(payload) > 1024:
                    detail_lines.append(f"    ... (showing first 1024 of {len(payload)} bytes)")
                detail_lines.append("")
            
        except Exception as e:
            # Fallback to simple packet display
            detail_lines.extend([
                f"Error displaying packet details: {str(e)}",
                "",
                "Packet Summary:",
                f"{packet.summary() if hasattr(packet, 'summary') else str(packet)}"
            ])
        
        return detail_lines

    def _tcp_flags_to_string(self, flags) -> str:
        """Convert TCP flags to readable string"""
        try:
            # Convert flags to integer if it's not already
            if isinstance(flags, int):
                flags_int = flags
            else:
                flags_int = int(flags)
            
            flag_names = []
            if flags_int & 0x01: flag_names.append("FIN")
            if flags_int & 0x02: flag_names.append("SYN") 
            if flags_int & 0x04: flag_names.append("RST")
            if flags_int & 0x08: flag_names.append("PSH")
            if flags_int & 0x10: flag_names.append("ACK")
            if flags_int & 0x20: flag_names.append("URG")
            if flags_int & 0x40: flag_names.append("ECE")
            if flags_int & 0x80: flag_names.append("CWR")
            return ",".join(flag_names) if flag_names else "None"
        except (ValueError, TypeError):
            return str(flags)
    
    def draw_error_message(self, message: str):
        """Draw an error message in the center of the screen"""
        height, width = self.stdscr.getmaxyx()
        y = height // 2
        x = (width - len(message)) // 2
        
        self.stdscr.addstr(y, x, message, curses.color_pair(3) | curses.A_BOLD)
    
    def draw_loading_message(self, message: str):
        """Draw a loading message in the center of the screen"""
        height, width = self.stdscr.getmaxyx()
        y = height // 2
        x = (width - len(message)) // 2
        
        self.stdscr.addstr(y, x, message, curses.color_pair(5) | curses.A_BOLD)
    
    def refresh(self):
        """Refresh the screen"""
        self.stdscr.refresh()
    
    def draw_menu(self, menu_items: List[str], selected_index: int, title: str = ""):
        """Draw a simple menu with selectable items"""
        height, width = self.stdscr.getmaxyx()
        menu_start_y = height // 2 - len(menu_items) // 2
        
        if title:
            self.stdscr.addstr(menu_start_y - 2, 4, title, self.get_color_pair(1) | curses.A_BOLD)
        
        for i, item in enumerate(menu_items):
            y_pos = menu_start_y + i
            
            if i == selected_index:
                attr = self.get_color_pair(6) | curses.A_REVERSE
                prefix = "> "
            else:
                attr = self.get_color_pair(7)
                prefix = "  "
            
            display_text = f"{prefix}{item}"
            self.stdscr.addstr(y_pos, 4, display_text[:width-6], attr)
    
    def draw_text_box(self, text: str, y_start: int = 2, x_start: int = 2):
        """Draw a text box with the given text"""
        height, width = self.stdscr.getmaxyx()
        
        lines = text.split('\n')
        for i, line in enumerate(lines):
            y_pos = y_start + i
            if y_pos < height - 2:
                self.stdscr.addstr(y_pos, x_start, line[:width-x_start-2], self.get_color_pair(7))
    
    def get_text_input(self, y: int, x: int, prompt: str = "", max_length: int = 100, 
                       validator_func=None, validation_hint: str = "") -> Optional[str]:
        """
        Get text input from user at specified position.
        
        Args:
            y: Y position
            x: X position
            prompt: Prompt text to display
            max_length: Maximum input length
            validator_func: Optional function(str) -> Tuple[bool, str] that returns (is_valid, error_msg)
            validation_hint: Hint text to show below input
            
        Returns:
            The input string or None if ESC was pressed.
        """
        import curses
        
        height, width = self.stdscr.getmaxyx()
        
        # Display prompt
        self.stdscr.addstr(y, x, prompt, self.get_color_pair(7))
        input_x = x + len(prompt)
        
        # Input buffer
        input_str = ""
        validation_error = ""
        
        # Show cursor
        curses.curs_set(1)
        
        try:
            while True:
                # Draw input field with current content
                display_width = width - input_x - 2
                if display_width > 0:
                    # Clear previous input area
                    clear_str = " " * min(display_width, max_length + 5)
                    self.stdscr.addstr(y, input_x, clear_str)
                    # Display current input with underline
                    if input_str:
                        display_str = input_str[:display_width]
                        self.stdscr.addstr(y, input_x, display_str, curses.A_UNDERLINE)
                    else:
                        # Show placeholder when empty
                        self.stdscr.addstr(y, input_x, "_", curses.A_DIM)
                
                # Show validation hint or error below input
                hint_y = y + 1
                if hint_y < height - 3:
                    clear_line = " " * (width - x - 2)
                    self.stdscr.addstr(hint_y, x, clear_line)
                    if validation_error:
                        error_text = f"✗ {validation_error}"
                        if len(error_text) < width - x - 2:
                            self.stdscr.addstr(hint_y, x, error_text, self.get_color_pair(1))  # Red
                    elif validation_hint and not input_str:
                        hint_text = f"ℹ {validation_hint}"
                        if len(hint_text) < width - x - 2:
                            self.stdscr.addstr(hint_y, x, hint_text, curses.A_DIM)
                
                # Position cursor at end of input (or at start if empty)
                cursor_x = input_x + len(input_str)
                if cursor_x >= width - 1:
                    cursor_x = width - 2
                self.stdscr.move(y, cursor_x)
                self.stdscr.refresh()
                
                # Get input
                key = self.stdscr.getch()
                
                if key == 27:  # ESC
                    curses.curs_set(0)
                    return None
                elif key == curses.KEY_BACKSPACE or key == 8 or key == 127:  # Backspace
                    if input_str:
                        input_str = input_str[:-1]
                        validation_error = ""  # Clear error on edit
                elif key == ord('\n') or key == 10 or key == 13:  # Enter
                    # Validate before accepting
                    if validator_func:
                        is_valid, error_msg = validator_func(input_str)
                        if not is_valid:
                            validation_error = error_msg
                            continue  # Don't accept, show error
                    curses.curs_set(0)
                    return input_str
                elif 32 <= key <= 126:  # Printable characters
                    if len(input_str) < max_length:
                        input_str += chr(key)
                        validation_error = ""  # Clear error on edit
        except KeyboardInterrupt:
            curses.curs_set(0)
            return None
        except Exception as e:
            curses.curs_set(0)
            # If there's an error during input, return None
            return None
        finally:
            curses.curs_set(0)


# Import os for the layout class
import os
