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
        if not self.colors_initialized and curses.has_colors():
            curses.start_color()
            
            # Define color pairs
            curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)    # Header
            curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)   # Success
            curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)     # Error
            curses.init_pair(4, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Warning
            curses.init_pair(5, curses.COLOR_CYAN, curses.COLOR_BLACK)    # Info
            curses.init_pair(6, curses.COLOR_MAGENTA, curses.COLOR_BLACK) # Selected
            curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_BLACK)   # Normal
            
            self.colors_initialized = True
    
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
        self.stdscr.addstr(0, 0, header_text[:width-1], curses.color_pair(1) | curses.A_BOLD)
        
        # Fill rest of header line
        remaining_width = width - len(header_text)
        if remaining_width > 0:
            self.stdscr.addstr(0, len(header_text), " " * remaining_width, curses.color_pair(1))
    
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
        """Draw the main menu options"""
        height, width = self.stdscr.getmaxyx()
        menu_start_y = height // 2
        
        menu_options = [
            "1. View Netflows",
            "2. Augmentations (Coming Soon)",
            "3. Back to PCAP List"
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
        """Draw the list of packets in a netflow"""
        height, width = self.stdscr.getmaxyx()
        start_y = 2
        # Reserve space for header(1) + title(1) + headers(1) + help(1) + status(1) = 5 lines
        content_start_y = start_y + 2  # After title and headers
        content_end_y = height - 1  # Before help and status bars
        visible_lines = content_end_y - content_start_y
        
        # Title
        title = f"Packets in Netflow ({len(packets)} total):"
        self.stdscr.addstr(start_y, 2, title, curses.color_pair(1) | curses.A_BOLD)
        
        # Headers
        headers = f"{'#':<6} {'Time':<12} {'Source':<18} {'Dest':<18} {'Proto':<8} {'Size':<8}"
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
            
            # Format packet information
            try:
                time_str = f"{getattr(packet, 'time', 0):.3f}"
                src = getattr(packet, 'src', 'Unknown')
                dst = getattr(packet, 'dst', 'Unknown')
                proto = getattr(packet, 'proto', 'Unknown')
                size = len(getattr(packet, 'load', b''))
                
                packet_text = f"{packet_index+1:<6} {time_str:<12} {src:<18} {dst:<18} {proto:<8} {size:<8}"
            except:
                packet_text = f"{packet_index+1:<6} {'N/A':<12} {'Unknown':<18} {'Unknown':<18} {'N/A':<8} {'0':<8}"
            
            # Highlight selected item
            if packet_index == selected_index:
                attr = curses.color_pair(6) | curses.A_REVERSE
            else:
                attr = curses.color_pair(7)
            
            self.stdscr.addstr(y_pos, 2, packet_text[:width-4], attr)
    
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


# Import os for the layout class
import os
