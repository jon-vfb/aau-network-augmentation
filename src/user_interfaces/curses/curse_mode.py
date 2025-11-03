import curses
import os
import sys
from typing import Optional

# Check curses compatibility on Windows
try:
    import curses
    # Test basic curses functionality
    curses.wrapper
except ImportError:
    print("ERROR: curses module not available!")
    print("On Windows, you need to install windows-curses:")
    print("  pip install windows-curses")
    print("Or install from requirements-windows.txt:")
    print("  pip install -r requirements-windows.txt")
    sys.exit(1)
except AttributeError as e:
    print(f"ERROR: curses module incomplete: {e}")
    print("Try reinstalling windows-curses:")
    print("  pip uninstall windows-curses")
    print("  pip install windows-curses")
    sys.exit(1)

# Import our components
from layout.curses_layout import CursesLayout
from logic.curses_logic import CursesLogic


class PcapCursesUI:
    """Main curses UI controller for PCAP analysis"""
    
    def __init__(self):
        self.stdscr = None
        self.layout: Optional[CursesLayout] = None
        self.logic: Optional[CursesLogic] = None
        
        # UI state
        self.mode = "pcap_list"  # pcap_list, pcap_info, netflow_list, netflow_details, packet_list, packet_detail
        self.selected_index = 0
        self.scroll_offset = 0
        self.status_message = "Welcome to PCAP Network Analyzer"
        self.menu_selected = 0
        self.selected_packet_index = 0  # For packet detail view
        self.packet_detail_scroll = 0  # For scrolling in packet detail view
        
    def init_ui(self, stdscr):
        """Initialize the UI components"""
        self.stdscr = stdscr
        self.layout = CursesLayout(stdscr)
        self.logic = CursesLogic()
        
        # Configure curses
        curses.curs_set(0)  # Hide cursor
        self.stdscr.keypad(True)  # Enable special keys
        
        # Scan for PCAP files
        pcap_files = self.logic.scan_for_pcaps()
        if not pcap_files:
            self.status_message = "No PCAP files found in samples directory"
        else:
            self.status_message = f"Found {len(pcap_files)} PCAP files"
    
    def run(self, stdscr):
        """Main UI loop"""
        self.init_ui(stdscr)
        
        while True:
            try:
                self.draw_current_screen()
                key = self.stdscr.getch()
                
                if not self.handle_input(key):
                    break
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.status_message = f"Error: {str(e)}"
    
    def draw_current_screen(self):
        """Draw the current screen based on mode"""
        self.layout.clear_screen()
        
        if self.mode == "pcap_list":
            self.draw_pcap_list_screen()
        elif self.mode == "pcap_info":
            self.draw_pcap_info_screen()
        elif self.mode == "netflow_list":
            self.draw_netflow_list_screen()
        elif self.mode == "netflow_details":
            self.draw_netflow_details_screen()
        elif self.mode == "packet_list":
            self.draw_packet_list_screen()
        elif self.mode == "packet_detail":
            self.draw_packet_detail_screen()
        
        self.layout.refresh()
    
    def draw_pcap_list_screen(self):
        """Draw the PCAP file list screen"""
        self.layout.draw_header("PCAP Network Analyzer - File Selection")
        self.layout.draw_pcap_list(self.logic.available_pcaps, self.selected_index, self.scroll_offset)
        self.layout.draw_help_bar("↑↓: Navigate | Enter: Select | q: Quit")
        self.layout.draw_status_bar(self.status_message, self.mode)
    
    def draw_pcap_info_screen(self):
        """Draw the PCAP information and menu screen"""
        pcap_info = self.logic.get_pcap_info()
        self.layout.draw_header(f"PCAP Analysis - {pcap_info.get('filename', 'Unknown')}")
        self.layout.draw_pcap_info(pcap_info)
        self.layout.draw_main_menu(self.menu_selected)
        self.layout.draw_help_bar("↑↓: Navigate | Enter: Select | ESC: Back | q: Quit")
        self.layout.draw_status_bar(self.status_message, self.mode)
    
    def draw_netflow_list_screen(self):
        """Draw the netflow list screen"""
        netflows = self.logic.get_netflows()
        self.layout.draw_header("Netflow Analysis")
        self.layout.draw_netflow_list(netflows, self.selected_index, self.scroll_offset)
        self.layout.draw_help_bar("↑↓: Navigate | Enter: View Details | ESC: Back | q: Quit")
        self.layout.draw_status_bar(self.status_message, self.mode)
    
    def draw_netflow_details_screen(self):
        """Draw the netflow details screen"""
        netflow_info = self.logic.get_selected_netflow_info()
        if netflow_info:
            self.layout.draw_header("Netflow Details")
            self.layout.draw_netflow_details(netflow_info)
            self.layout.draw_help_bar("p: View Packets | ESC: Back | q: Quit")
            self.layout.draw_status_bar(self.status_message, self.mode)
    
    def draw_packet_list_screen(self):
        """Draw the packet list screen"""
        packets = self.logic.get_netflow_packets()
        self.layout.draw_header("Netflow Packets")
        self.layout.draw_packet_list(packets, self.selected_index, self.scroll_offset)
        self.layout.draw_help_bar("↑↓: Navigate | Enter: View Detail | ESC: Back | q: Quit")
        self.layout.draw_status_bar(self.status_message, self.mode)
    
    def draw_packet_detail_screen(self):
        """Draw the packet detail screen"""
        packets = self.logic.get_netflow_packets()
        if self.selected_packet_index < len(packets):
            packet = packets[self.selected_packet_index]
            self.layout.draw_header(f"Packet Detail - #{self.selected_packet_index + 1}")
            self.layout.draw_packet_detail(packet, self.selected_packet_index, self.packet_detail_scroll)
            self.layout.draw_help_bar("↑↓/jk: Scroll | PgUp/PgDn: Page | Home/g: Top | End/G: Bottom | ESC: Back | q: Quit")
            
            # Add scroll indicator to status
            scroll_status = f"Scroll: {self.packet_detail_scroll} | {self.status_message}"
            self.layout.draw_status_bar(scroll_status, self.mode)
        else:
            self.layout.draw_error_message("Invalid packet selected")
    
    def handle_input(self, key) -> bool:
        """Handle keyboard input based on current mode"""
        # Global quit key
        if key in (ord('q'), ord('Q')):
            return False
        
        if self.mode == "pcap_list":
            return self.handle_pcap_list_input(key)
        elif self.mode == "pcap_info":
            return self.handle_pcap_info_input(key)
        elif self.mode == "netflow_list":
            return self.handle_netflow_list_input(key)
        elif self.mode == "netflow_details":
            return self.handle_netflow_details_input(key)
        elif self.mode == "packet_list":
            return self.handle_packet_list_input(key)
        elif self.mode == "packet_detail":
            return self.handle_packet_detail_input(key)
        
        return True
    
    def handle_pcap_list_input(self, key) -> bool:
        """Handle input in PCAP list mode"""
        pcap_count = len(self.logic.available_pcaps)
        
        if key == curses.KEY_DOWN or key == ord('j'):
            if self.selected_index < pcap_count - 1:
                self.selected_index += 1
                self.update_scroll()
        elif key == curses.KEY_UP or key == ord('k'):
            if self.selected_index > 0:
                self.selected_index -= 1
                self.update_scroll()
        elif key in (ord('\n'), ord(' ')):  # Enter or Space
            if pcap_count > 0 and 0 <= self.selected_index < pcap_count:
                pcap_path = self.logic.available_pcaps[self.selected_index]
                if self.logic.load_pcap(pcap_path):
                    self.mode = "pcap_info"
                    self.menu_selected = 0
                    self.status_message = f"Loaded {os.path.basename(pcap_path)}"
                else:
                    error_msg = getattr(self.logic, 'last_error', 'Failed to load PCAP file')
                    self.status_message = error_msg
        
        return True
    
    def handle_pcap_info_input(self, key) -> bool:
        """Handle input in PCAP info mode"""
        if key == 27:  # ESC
            self.mode = "pcap_list"
            self.selected_index = 0
            self.scroll_offset = 0
            self.status_message = "Back to file selection"
        elif key == curses.KEY_DOWN or key == ord('j'):
            if self.menu_selected < 2:  # 3 menu options (0, 1, 2)
                self.menu_selected += 1
        elif key == curses.KEY_UP or key == ord('k'):
            if self.menu_selected > 0:
                self.menu_selected -= 1
        elif key in (ord('\n'), ord(' ')):  # Enter or Space
            if self.menu_selected == 0:  # View Netflows
                self.mode = "netflow_list"
                self.selected_index = 0
                self.scroll_offset = 0
                self.status_message = "Viewing netflows"
            elif self.menu_selected == 1:  # Augmentations
                self.status_message = "Augmentations feature coming soon!"
            elif self.menu_selected == 2:  # Back to PCAP List
                self.mode = "pcap_list"
                self.selected_index = 0
                self.scroll_offset = 0
                self.status_message = "Back to file selection"
        
        return True
    
    def handle_netflow_list_input(self, key) -> bool:
        """Handle input in netflow list mode"""
        netflows = self.logic.get_netflows()
        netflow_count = len(netflows)
        
        if key == 27:  # ESC
            self.mode = "pcap_info"
            self.status_message = "Back to PCAP info"
        elif key == curses.KEY_DOWN or key == ord('j'):
            if self.selected_index < netflow_count - 1:
                self.selected_index += 1
                self.update_scroll()
        elif key == curses.KEY_UP or key == ord('k'):
            if self.selected_index > 0:
                self.selected_index -= 1
                self.update_scroll()
        elif key in (ord('\n'), ord(' ')):  # Enter or Space
            if netflow_count > 0 and 0 <= self.selected_index < netflow_count:
                if self.logic.select_netflow(self.selected_index):
                    self.mode = "netflow_details"
                    self.status_message = f"Viewing netflow {self.selected_index + 1}"
                else:
                    self.status_message = "Failed to select netflow"
        
        return True
    
    def handle_netflow_details_input(self, key) -> bool:
        """Handle input in netflow details mode"""
        if key == 27:  # ESC
            self.mode = "netflow_list"
            self.status_message = "Back to netflow list"
        elif key in (ord('p'), ord('P')):  # View packets
            self.mode = "packet_list"
            self.selected_index = 0
            self.scroll_offset = 0
            packets = self.logic.get_netflow_packets()
            self.status_message = f"Viewing {len(packets)} packets in netflow"
        
        return True
    
    def handle_packet_list_input(self, key) -> bool:
        """Handle input in packet list mode"""
        packets = self.logic.get_netflow_packets()
        packet_count = len(packets)
        
        if key == 27:  # ESC
            self.mode = "netflow_details"
            self.status_message = "Back to netflow details"
        elif key == curses.KEY_DOWN or key == ord('j'):
            if self.selected_index < packet_count - 1:
                self.selected_index += 1
                self.update_scroll()
        elif key == curses.KEY_UP or key == ord('k'):
            if self.selected_index > 0:
                self.selected_index -= 1
                self.update_scroll()
        elif key in (ord('\n'), ord(' ')):  # Enter or Space
            if packet_count > 0 and 0 <= self.selected_index < packet_count:
                self.selected_packet_index = self.selected_index
                self.packet_detail_scroll = 0  # Reset scroll when entering packet detail
                self.mode = "packet_detail"
                self.status_message = f"Viewing packet #{self.selected_index + 1} details"
        
        return True
    
    def handle_packet_detail_input(self, key) -> bool:
        """Handle input in packet detail mode"""
        if key == 27:  # ESC
            self.mode = "packet_list"
            self.packet_detail_scroll = 0  # Reset scroll when leaving
            self.status_message = "Back to packet list"
        elif key == curses.KEY_DOWN or key == ord('j'):
            # Scroll down in packet detail
            self.packet_detail_scroll += 1
            self.status_message = "Scrolled down"
        elif key == curses.KEY_UP or key == ord('k'):
            # Scroll up in packet detail
            if self.packet_detail_scroll > 0:
                self.packet_detail_scroll -= 1
                self.status_message = "Scrolled up"
        elif key == curses.KEY_NPAGE:  # Page Down
            # Scroll down by page
            self.packet_detail_scroll += 10
            self.status_message = "Page down"
        elif key == curses.KEY_PPAGE:  # Page Up
            # Scroll up by page
            self.packet_detail_scroll = max(0, self.packet_detail_scroll - 10)
            self.status_message = "Page up"
        elif key == curses.KEY_HOME or key == ord('g'):
            # Go to top
            self.packet_detail_scroll = 0
            self.status_message = "Top of packet"
        elif key == curses.KEY_END or key == ord('G'):
            # Go to bottom - the layout will clamp this to appropriate value
            self.packet_detail_scroll = 1000  # Large number, will be clamped by layout
            self.status_message = "Bottom of packet"
        
        return True
    
    def update_scroll(self):
        """Update scroll offset to keep selected item visible"""
        height, width = self.stdscr.getmaxyx()
        
        # Calculate visible lines based on mode
        if self.mode == "pcap_list":
            # header(1) + title(1) + help(1) + status(1) = 4 lines reserved
            visible_lines = height - 5  # Extra line for safety
        elif self.mode in ["netflow_list", "packet_list"]:
            # header(1) + title(1) + headers(1) + help(1) + status(1) = 5 lines reserved  
            visible_lines = height - 6  # Extra line for safety
        elif self.mode == "packet_detail":
            # No scrolling needed in packet detail mode
            return
        else:
            visible_lines = height - 6  # Default fallback
        
        # Ensure we have at least 1 visible line
        visible_lines = max(1, visible_lines)
        
        if self.selected_index < self.scroll_offset:
            self.scroll_offset = self.selected_index
        elif self.selected_index >= self.scroll_offset + visible_lines:
            self.scroll_offset = self.selected_index - visible_lines + 1


def run_curses_ui():
    """Entry point for the curses UI"""
    try:
        ui = PcapCursesUI()
        curses.wrapper(ui.run)
        
    except Exception as e:
        print(f"Error running curses UI: {e}")
        print("\nIf you're on Windows and getting curses errors:")
        print("1. Install windows-curses: pip install windows-curses")
        print("2. Or use: pip install -r requirements-windows.txt")
        print("3. Make sure your terminal supports curses (Command Prompt, PowerShell, or Windows Terminal)")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    run_curses_ui()
