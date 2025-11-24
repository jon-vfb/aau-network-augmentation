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
from features.augmentations import InputValidator


class PcapCursesUI:
    """Main curses UI controller for PCAP analysis"""
    
    def __init__(self):
        self.stdscr = None
        self.layout: Optional[CursesLayout] = None
        self.logic: Optional[CursesLogic] = None
        
        # UI state
        self.mode = "main_menu"  # main_menu, pcap_list, pcap_info, netflow_list, netflow_details, packet_list, packet_detail
        self.selected_index = 0
        self.scroll_offset = 0
        self.status_message = "Welcome to PCAP Network Analyzer"
        self.menu_selected = 0
        self.selected_packet_index = 0  # For packet detail view
        self.packet_detail_scroll = 0  # For scrolling in packet detail view
        
        # Augmentation configuration input state
        self.augmentation_config_input_mode = None  # 'project_name', 'ip_range', 'jitter', or None
        self.augmentation_inputs = {
            'project_name': None,
            'ip_translation_range': None,
            'jitter_max': 0.1
        }
        
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
        
        if self.mode == "main_menu":
            self.draw_main_menu_screen()
        elif self.mode == "pcap_list":
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
        elif self.mode == "augmentation_menu":
            self.draw_augmentation_menu_screen()
        elif self.mode == "augmentation_benign_select":
            self.draw_augmentation_benign_select_screen()
        elif self.mode == "augmentation_malicious_select":
            self.draw_augmentation_malicious_select_screen()
        elif self.mode == "augmentation_attack_select":
            self.draw_augmentation_attack_select_screen()
        elif self.mode == "augmentation_attack_config":
            self.draw_augmentation_attack_config_screen()
        elif self.mode == "augmentation_config":
            self.draw_augmentation_config_screen()
        elif self.mode == "augmentation_confirm":
            self.draw_augmentation_confirm_screen()
        elif self.mode == "augmentation_confirm_attack":
            self.draw_augmentation_confirm_attack_screen()
        elif self.mode == "augmentation_confirm_attack_only":
            self.draw_augmentation_confirm_attack_only_screen()
        elif self.mode == "augmentation_running":
            self.draw_augmentation_running_screen()
        elif self.mode == "augmentation_results":
            self.draw_augmentation_results_screen()
        
        self.layout.refresh()
    
    def draw_main_menu_screen(self):
        """Draw the main menu screen"""
        self.layout.draw_header("PCAP Network Analyzer - Main Menu")
        
        menu_items = ["Create Attack PCAP", "Merge PCAPs", "View PCAP", "Quit"]
        self.layout.draw_menu(
            menu_items,
            self.selected_index,
            title="Select Action"
        )
        
        self.layout.draw_help_bar("↑↓: Navigate | Enter: Select | q: Quit")
        self.layout.draw_status_bar(self.status_message, self.mode)
    
    def draw_pcap_list_screen(self):
        """Draw the PCAP file list screen"""
        self.layout.draw_header("PCAP Network Analyzer - File Selection")
        self.layout.draw_pcap_list(self.logic.available_pcaps, self.selected_index, self.scroll_offset)
        self.layout.draw_help_bar("↑↓: Navigate | Enter: Select | ESC: Back | q: Quit")
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
        
        if self.mode == "main_menu":
            return self.handle_main_menu_input(key)
        elif self.mode == "pcap_list":
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
        elif self.mode == "augmentation_menu":
            return self.handle_augmentation_menu_input(key)
        elif self.mode == "augmentation_benign_select":
            return self.handle_augmentation_benign_select_input(key)
        elif self.mode == "augmentation_malicious_select":
            return self.handle_augmentation_malicious_select_input(key)
        elif self.mode == "augmentation_attack_select":
            return self.handle_augmentation_attack_select_input(key)
        elif self.mode == "augmentation_attack_config":
            return self.handle_augmentation_attack_config_input(key)
        elif self.mode == "augmentation_config":
            return self.handle_augmentation_config_input(key)
        elif self.mode == "augmentation_confirm":
            return self.handle_augmentation_confirm_input(key)
        elif self.mode == "augmentation_confirm_attack":
            return self.handle_augmentation_confirm_attack_input(key)
        elif self.mode == "augmentation_confirm_attack_only":
            return self.handle_augmentation_confirm_attack_only_input(key)
        elif self.mode == "augmentation_running":
            return self.handle_augmentation_running_input(key)
        elif self.mode == "augmentation_results":
            return self.handle_augmentation_results_input(key)
        
        return True
    
    def handle_main_menu_input(self, key) -> bool:
        """Handle input in main menu mode"""
        if key == curses.KEY_DOWN or key == ord('j'):
            if self.selected_index < 3:  # 4 menu options (0-3)
                self.selected_index += 1
        elif key == curses.KEY_UP or key == ord('k'):
            if self.selected_index > 0:
                self.selected_index -= 1
        elif key in (ord('\n'), ord(' ')):  # Enter or Space
            if self.selected_index == 0:  # Create Attack PCAP
                self.mode = "augmentation_attack_select"
                self.selected_index = 0
                self.scroll_offset = 0
                self.logic.reset_augmentation_state('attack_only')
                self.status_message = "Select attack type"
            elif self.selected_index == 1:  # Merge PCAPs
                self.mode = "augmentation_benign_select"
                self.selected_index = 0
                self.scroll_offset = 0
                self.logic.reset_augmentation_state('merge')
                self.status_message = "Select benign PCAP"
            elif self.selected_index == 2:  # View PCAP
                self.mode = "pcap_list"
                self.selected_index = 0
                self.scroll_offset = 0
                self.status_message = "Select PCAP to view"
            elif self.selected_index == 3:  # Quit
                return False
        
        return True
    
    def handle_pcap_list_input(self, key) -> bool:
        """Handle input in PCAP list mode"""
        pcap_count = len(self.logic.available_pcaps)
        
        if key == 27:  # ESC - go back to main menu
            self.mode = "main_menu"
            self.selected_index = 0
            self.scroll_offset = 0
            self.status_message = "Back to main menu"
        elif key == curses.KEY_DOWN or key == ord('j'):
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
            if self.menu_selected < 1:  # 2 menu options (0, 1)
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
            elif self.menu_selected == 1:  # Back to PCAP List
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
    
    # ==================== AUGMENTATION SCREENS ====================
    
    def draw_augmentation_menu_screen(self):
        """Draw the augmentation menu screen"""
        self.layout.draw_header("Augmentations")
        
        menu_items = ["Merge PCAPs", "Generate & Merge Attack", "Back"]
        self.layout.draw_menu(
            menu_items, 
            self.menu_selected,
            title="Select Augmentation Option"
        )
        
        self.layout.draw_help_bar("↑↓: Navigate | Enter: Select | ESC: Back | q: Quit")
        self.layout.draw_status_bar(self.status_message, self.mode)
    
    def draw_augmentation_benign_select_screen(self):
        """Draw the benign PCAP selection screen"""
        self.layout.draw_header("Augmentation - Select Benign PCAP")
        self.layout.draw_pcap_list(self.logic.available_pcaps, self.selected_index, self.scroll_offset)
        self.layout.draw_help_bar("↑↓: Navigate | Enter: Select | ESC: Cancel | q: Quit")
        self.layout.draw_status_bar(self.status_message, self.mode)
    
    def draw_augmentation_malicious_select_screen(self):
        """Draw the malicious PCAP selection screen"""
        self.layout.draw_header("Augmentation - Select Malicious PCAP")
        self.layout.draw_pcap_list(self.logic.available_pcaps, self.selected_index, self.scroll_offset)
        self.layout.draw_help_bar("↑↓: Navigate | Enter: Select | ESC: Cancel | q: Quit")
        self.layout.draw_status_bar(self.status_message, self.mode)
    
    def draw_augmentation_attack_select_screen(self):
        """Draw the attack type selection screen"""
        self.layout.draw_header("Augmentation - Select Attack Type")
        
        attacks = self.logic.get_available_attacks()
        attack_names = [f"{a['name']} - {a['description']}" for a in attacks]
        
        if not attack_names:
            self.layout.draw_text_box("No attacks available. Check attacks folder.", 5, 5)
            self.layout.draw_help_bar("ESC: Back | q: Quit")
        else:
            self.layout.draw_menu(
                attack_names,
                self.selected_index,
                title="Available Attacks"
            )
            self.layout.draw_help_bar("↑↓: Navigate | Enter: Select | ESC: Cancel | q: Quit")
        
        self.layout.draw_status_bar(self.status_message, self.mode)
    
    def draw_augmentation_attack_config_screen(self):
        """Draw the attack configuration screen for entering attack parameters"""
        self.layout.draw_header("Augmentation - Configure Attack Parameters")
        
        attack_config = self.logic.get_attack_config_state()
        if not attack_config:
            self.layout.draw_text_box("No attack selected", 5, 5)
            self.layout.draw_help_bar("ESC: Back | q: Quit")
            self.layout.draw_status_bar(self.status_message, self.mode)
            return
        
        attack_name = attack_config.get('attack_name', 'Unknown')
        parameters = attack_config.get('parameters', [])
        current_param_index = attack_config.get('current_parameter_index', 0)
        input_values = attack_config.get('input_values', {})
        
        config_text = f"""
ATTACK CONFIGURATION: {attack_name}
{'='*60}

Configure attack parameters (↑↓ to navigate, ENTER to edit):

"""
        all_filled = True
        for i, param in enumerate(parameters):
            marker = ">> " if i == current_param_index else "   "
            value = input_values.get(param['name'], 
                                   param.get('default', ''))
            status = "✓" if value else "✗"
            
            if param.get('required') and not value:
                all_filled = False
            
            config_text += f"{marker}[{status}] {param['name']}: {value if value else '(empty)'}\n"
            config_text += f"        Type: {param.get('param_type', 'str')} | {param['description']}\n"
            if param.get('validation_hint'):
                config_text += f"        Hint: {param.get('validation_hint')}\n"
            config_text += "\n"
        
        config_text += "\n[↑↓] Navigate | [ENTER] Edit | [D] Done | [ESC] Back\n"
        
        self.layout.draw_text_box(config_text, 2, 2)
        self.layout.draw_help_bar("↑↓: Navigate | ENTER: Edit | D: Done | ESC: Back | q: Quit")
        self.layout.draw_status_bar(self.status_message, self.mode)
    
    def draw_augmentation_config_screen(self):
        """Draw the augmentation configuration screen"""
        self.layout.draw_header("Augmentation - Configure Options")
        
        state = self.logic.get_augmentation_state()
        
        config_text = f"""
CONFIGURATION SCREEN
{'='*60}

Enter configuration details for the augmentation:

1. Project Name (e.g., 'my_augmentation' or 'test_001')
   Current: {state.get('project_name', 'Not set')}

2. IP Translation Range (optional CIDR notation)
   Example: 192.168.100.0/24
   Current: {state.get('ip_translation_range', 'Not set')}

3. Jitter Max (seconds, 0-10)
   Example: 0.1 (for 100 milliseconds)
   Current: {state.get('jitter_max', 0.1)}

Navigation: q=Quit | ESC=Back | ENTER=Input mode
"""
        
        self.layout.draw_text_box(config_text, 2, 2)
        self.layout.draw_help_bar("Press SPACE to enter input mode or ESC to go back")
        self.layout.draw_status_bar(self.status_message, self.mode)
    
    def draw_augmentation_confirm_screen(self):
        """Draw the augmentation confirmation screen"""
        self.layout.draw_header("Augmentation - Confirm Settings")
        
        state = self.logic.get_augmentation_state()
        benign = os.path.basename(state.get('benign_pcap', 'Not selected'))
        malicious = os.path.basename(state.get('malicious_pcap', 'Not selected'))
        
        confirm_text = f"""
Benign PCAP:             {benign}
Malicious PCAP:          {malicious}
Project Name:            {state.get('project_name', 'Not set')}
IP Translation Range:    {state.get('ip_translation_range', 'None')}
Jitter Max (seconds):    {state.get('jitter_max', 0.1)}

Confirm to start augmentation process?

[Confirm] or [Cancel]
"""
        
        menu_items = ["Confirm & Start", "Cancel & Edit"]
        self.layout.draw_text_box(confirm_text, 8, 2)
        self.layout.draw_menu(menu_items, self.menu_selected, title="")
        
        self.layout.draw_help_bar("↑↓: Navigate | Enter: Select | q: Quit")
        self.layout.draw_status_bar(self.status_message, self.mode)
    
    def draw_augmentation_confirm_attack_screen(self):
        """Draw the attack augmentation confirmation screen"""
        self.layout.draw_header("Augmentation - Confirm Attack Settings")
        
        state = self.logic.get_augmentation_state()
        benign = os.path.basename(state.get('benign_pcap', 'Not selected'))
        attack_config = self.logic.get_attack_config_state()
        attack_name = attack_config.get('attack_name', 'Unknown') if attack_config else 'Not selected'
        
        # Build parameters section
        params_text = ""
        if attack_config:
            input_values = attack_config.get('input_values', {})
            parameters = attack_config.get('parameters', [])
            if parameters:
                params_text += "\nAttack Parameters:\n"
                for param in parameters:
                    param_name = param['name']
                    param_value = input_values.get(param_name, '')
                    params_text += f"  {param_name}: {param_value if param_value else '(empty)'}\n"
        
        confirm_text = f"""
Benign PCAP:             {benign}
Attack Type:             {attack_name}
Project Name:            {state.get('project_name', 'Not set')}
IP Translation Range:    {state.get('ip_translation_range', 'None')}
Jitter Max (seconds):    {state.get('jitter_max', 0.1)}{params_text}

Confirm to start attack generation and merge process?

[Confirm] or [Cancel]
"""
        
        menu_items = ["Confirm & Start", "Cancel & Edit"]
        self.layout.draw_text_box(confirm_text, 6, 2)
        self.layout.draw_menu(menu_items, self.menu_selected, title="")
        
        self.layout.draw_help_bar("↑↓: Navigate | Enter: Select | q: Quit")
        self.layout.draw_status_bar(self.status_message, self.mode)
    
    def draw_augmentation_running_screen(self):
        """Draw the augmentation progress screen"""
        self.layout.draw_header("Augmentation - Processing")
        
        progress_text = """
Starting augmentation process...

⟳ Labeling benign packets...
⟳ Labeling malicious packets...
⟳ Merging PCAP files...
⟳ Resolving timestamps...
⟳ Finalizing output...

Please wait...
"""
        
        self.layout.draw_text_box(progress_text, 12, 5)
        self.layout.draw_status_bar("Processing augmentation...", self.mode)
    
    def draw_augmentation_results_screen(self):
        """Draw the augmentation results screen"""
        self.layout.draw_header("Augmentation - Complete")
        
        results = self.logic.get_augmentation_results()
        
        if results and results.get('success'):
            status = "✓ SUCCESS"
            result_text = f"""
Project:                 {results.get('project_name', 'N/A')}
Status:                  {status}

Output Files:
  Project Directory:    {results.get('project_dir', 'N/A')}
  Benign CSV:          {os.path.basename(results.get('benign_csv', 'N/A'))}
  Malicious CSV:       {os.path.basename(results.get('malicious_csv', 'N/A'))}
  Merged PCAP:         {os.path.basename(results.get('merged_pcap', 'N/A'))}

Merge Statistics:
  Benign Packets:      {results.get('merge_statistics', {}).get('left_packets', 0)}
  Malicious Packets:   {results.get('merge_statistics', {}).get('right_packets', 0)}
  Total Packets:       {results.get('merge_statistics', {}).get('total_expected_packets', 0)}

Press ENTER to exit and validate the merged PCAP file
"""
        else:
            status = "✗ FAILED"
            error_msg = results.get('messages', ['Unknown error']) if results else ['Augmentation failed']
            result_text = f"""
Project:                 {results.get('project_name', 'N/A') if results else 'N/A'}
Status:                  {status}

Error Messages:
"""
            for msg in error_msg:
                if '✗' in msg:
                    result_text += f"\n  {msg}"
            
            result_text += "\n\nPress ENTER to return to main menu"
        
        self.layout.draw_text_box(result_text, 10, 2)
        self.layout.draw_help_bar("Enter: Exit & Validate | q: Quit")
        self.layout.draw_status_bar(self.status_message, self.mode)
    
    # ==================== AUGMENTATION INPUT HANDLERS ====================
    
    def handle_augmentation_menu_input(self, key) -> bool:
        """Handle input in augmentation menu mode"""
        if key == 27:  # ESC
            self.mode = "main_menu"
            self.selected_index = 0
            self.status_message = "Back to main menu"
        elif key == curses.KEY_DOWN or key == ord('j'):
            if self.menu_selected < 2:  # 3 options (0, 1, 2)
                self.menu_selected += 1
        elif key == curses.KEY_UP or key == ord('k'):
            if self.menu_selected > 0:
                self.menu_selected -= 1
        elif key in (ord('\n'), ord(' ')):  # Enter or Space
            if self.menu_selected == 0:  # Merge PCAPs
                self.logic.start_augmentation_merge()
                self.mode = "augmentation_benign_select"
                self.selected_index = 0
                self.scroll_offset = 0
                self.status_message = "Select benign PCAP file"
            elif self.menu_selected == 1:  # Generate & Merge Attack
                self.logic.start_augmentation_attack()
                self.mode = "augmentation_attack_select"
                self.selected_index = 0
                self.scroll_offset = 0
                self.status_message = "Select benign PCAP file"
            elif self.menu_selected == 2:  # Back
                self.mode = "main_menu"
                self.selected_index = 0
                self.status_message = "Back to main menu"
        
        return True
    
    def handle_augmentation_benign_select_input(self, key) -> bool:
        """Handle input in benign PCAP selection mode"""
        pcap_count = len(self.logic.available_pcaps)
        
        if key == 27:  # ESC
            self.mode = "main_menu"
            self.selected_index = 0
            self.status_message = "Back to main menu"
        elif key == curses.KEY_DOWN or key == ord('j'):
            if self.selected_index < pcap_count - 1:
                self.selected_index += 1
                self.update_scroll()
        elif key == curses.KEY_UP or key == ord('k'):
            if self.selected_index > 0:
                self.selected_index -= 1
                self.update_scroll()
        elif key in (ord('\n'), ord(' ')):  # Enter or Space
            if pcap_count > 0 and 0 <= self.selected_index < pcap_count:
                benign_path = self.logic.available_pcaps[self.selected_index]
                if self.logic.set_benign_pcap(benign_path):
                    # Check if we're in attack or merge workflow
                    if self.logic.augmentation_state.get('augmentation_type') == 'attack':
                        self.mode = "augmentation_attack_select"
                        self.selected_index = 0
                        self.scroll_offset = 0
                        self.status_message = f"Benign: {os.path.basename(benign_path)} | Select attack type"
                    else:
                        self.mode = "augmentation_malicious_select"
                        self.selected_index = 0
                        self.scroll_offset = 0
                        self.status_message = f"Benign: {os.path.basename(benign_path)} | Select malicious PCAP"
                else:
                    self.status_message = f"Error: {self.logic.last_error}"
        
        return True
    
    def handle_augmentation_malicious_select_input(self, key) -> bool:
        """Handle input in malicious PCAP selection mode"""
        pcap_count = len(self.logic.available_pcaps)
        
        if key == 27:  # ESC
            self.mode = "augmentation_benign_select"
            self.selected_index = 0
            self.scroll_offset = 0
            self.status_message = "Back to benign selection"
        elif key == curses.KEY_DOWN or key == ord('j'):
            if self.selected_index < pcap_count - 1:
                self.selected_index += 1
                self.update_scroll()
        elif key == curses.KEY_UP or key == ord('k'):
            if self.selected_index > 0:
                self.selected_index -= 1
                self.update_scroll()
        elif key in (ord('\n'), ord(' ')):  # Enter or Space
            if pcap_count > 0 and 0 <= self.selected_index < pcap_count:
                malicious_path = self.logic.available_pcaps[self.selected_index]
                if self.logic.set_malicious_pcap(malicious_path):
                    self.mode = "augmentation_config"
                    self.menu_selected = 0
                    self.status_message = f"Malicious: {os.path.basename(malicious_path)} | Configure options"
                else:
                    self.status_message = f"Error: {self.logic.last_error}"
        
        return True
    
    def handle_augmentation_attack_select_input(self, key) -> bool:
        """Handle input in attack type selection mode"""
        attacks = self.logic.get_available_attacks()
        attack_count = len(attacks)
        
        if key == 27:  # ESC
            self.mode = "main_menu"
            self.selected_index = 0
            self.status_message = "Back to main menu"
        elif key == curses.KEY_DOWN or key == ord('j'):
            if self.selected_index < attack_count - 1:
                self.selected_index += 1
        elif key == curses.KEY_UP or key == ord('k'):
            if self.selected_index > 0:
                self.selected_index -= 1
        elif key in (ord('\n'), ord(' ')):  # Enter or Space
            if attack_count > 0 and 0 <= self.selected_index < attack_count:
                attack_key = attacks[self.selected_index]['key']
                attack_name = attacks[self.selected_index]['name']
                
                if self.logic.set_attack(attack_key):
                    self.mode = "augmentation_attack_config"
                    self.status_message = f"Configure {attack_name} parameters"
                else:
                    self.status_message = f"Error: {self.logic.last_error}"
        
        return True
    
    def handle_augmentation_attack_config_input(self, key) -> bool:
        """Handle input in attack configuration mode"""
        attack_config = self.logic.get_attack_config_state()
        if not attack_config:
            self.status_message = "No attack selected"
            return True
        
        parameters = attack_config.get('parameters', [])
        if not parameters:
            # No parameters to configure, move to config entry
            self.mode = "augmentation_config"
            self.menu_selected = 0
            self.status_message = "Configure augmentation options"
            return True
        
        param_count = len(parameters)
        current_idx = attack_config.get('current_parameter_index', 0)
        
        if key == 27:  # ESC
            self.mode = "augmentation_attack_select"
            self.selected_index = 0
            self.status_message = "Back to attack selection"
        elif key == curses.KEY_DOWN or key == ord('j'):
            if current_idx < param_count - 1:
                self.logic.set_attack_parameter_index(current_idx + 1)
        elif key == curses.KEY_UP or key == ord('k'):
            if current_idx > 0:
                self.logic.set_attack_parameter_index(current_idx - 1)
        elif key in (ord('\n'), ord('e'), ord('E'), ord(' '), 10, 13):  # Enter, 'e', space, or common enter codes
            current_param = parameters[current_idx]
            param_name = current_param['name']
            param_type = current_param.get('param_type', 'str')
            current_value = attack_config['input_values'].get(param_name, 
                                                             current_param.get('default', ''))
            
            # Get text input from user
            self.layout.clear_screen()
            self.layout.draw_header(f"Enter value for: {param_name}")
            
            prompt_text = f"""
Parameter: {param_name}
Type: {param_type}
Description: {current_param['description']}
Hint: {current_param.get('validation_hint', 'No hint available')}

Current value: {current_value}

Enter new value (or press ESC to keep current):
"""
            
            self.layout.draw_text_box(prompt_text, 3, 2)
            
            # Get user input using the layout's text input method
            new_value = self.layout.get_text_input(15, 2, f"{param_name}: ", 100)
            
            if new_value is not None and new_value.strip():
                # Update the parameter value
                if self.logic.set_attack_parameter_value(param_name, new_value.strip()):
                    # Verify the value was actually saved
                    config_state = self.logic.get_attack_config_state()
                    saved_val = config_state['input_values'].get(param_name)
                    self.status_message = f"✓ {param_name} = {saved_val}"
                else:
                    self.status_message = f"✗ Invalid value: {self.logic.last_error}"
            elif new_value is None:
                self.status_message = "Input cancelled"
            else:
                self.status_message = "Empty value not allowed"
        elif key in (ord('d'), ord('D')):  # 'D' for Done - proceed to next step
            # Check if all required parameters are filled
            all_filled = True
            for param in parameters:
                pname = param['name']
                pval = attack_config['input_values'].get(pname, '')
                if param.get('required') and not pval:
                    all_filled = False
                    self.status_message = f"✗ Required parameter '{pname}' is empty"
                    break
            
            if all_filled:
                # Move to config screen for project name, IP range, jitter
                self.mode = "augmentation_config"
                self.menu_selected = 0
                self.status_message = "Configure augmentation options"
        
        return True
    
    def handle_augmentation_confirm_attack_input(self, key) -> bool:
        """Handle input in attack confirmation mode"""
        if key == 27:  # ESC
            self.mode = "augmentation_config"
            self.status_message = "Back to configuration"
        elif key == curses.KEY_DOWN or key == ord('j'):
            if self.menu_selected < 1:  # 2 options
                self.menu_selected += 1
        elif key == curses.KEY_UP or key == ord('k'):
            if self.menu_selected > 0:
                self.menu_selected -= 1
        elif key in (ord('\n'), ord(' ')):  # Enter or Space
            if self.menu_selected == 0:  # Confirm & Start
                # Draw running screen BEFORE starting the merge
                self.mode = "augmentation_running"
                self.draw_current_screen()
                self.stdscr.refresh()
                
                # Run attack generation and merge
                success = self.logic.run_augmentation_attack_and_merge()
                if success:
                    self.mode = "augmentation_results"
                    self.status_message = "Attack generation and merge completed"
                else:
                    self.mode = "augmentation_results"
                    self.status_message = f"Augmentation error: {self.logic.last_error}"
            elif self.menu_selected == 1:  # Cancel & Edit
                self.mode = "augmentation_attack_config"
                self.status_message = "Back to attack configuration"
        
        return True
    
    def draw_augmentation_confirm_attack_only_screen(self):
        """Draw the attack generation confirmation screen (no merge)"""
        self.layout.draw_header("Attack Generation - Confirm")
        
        state = self.logic.get_augmentation_state()
        attack_config = self.logic.get_attack_config_state()
        
        confirm_text = f"""
ATTACK GENERATION CONFIRMATION
{'='*60}

Attack Type: {attack_config.get('attack_name', 'Unknown')}
Project Name: {state.get('project_name', 'Not set')}

Attack Parameters:
"""
        
        for param in attack_config.get('parameters', []):
            param_name = param['name']
            param_value = attack_config['input_values'].get(param_name, param.get('default', ''))
            confirm_text += f"  {param_name}: {param_value}\n"
        
        confirm_text += f"""

Output: samples/{state.get('project_name', 'unknown')}_attack.pcap

Ready to generate attack traffic?
"""
        
        self.layout.draw_text_box(confirm_text, 2, 2)
        
        menu_items = ["Confirm & Generate", "Cancel & Edit"]
        self.layout.draw_menu(
            menu_items,
            self.menu_selected,
            title=""
        )
        
        self.layout.draw_help_bar("↑↓: Navigate | Enter: Select | ESC: Back | q: Quit")
        self.layout.draw_status_bar(self.status_message, self.mode)
    
    def handle_augmentation_confirm_attack_only_input(self, key) -> bool:
        """Handle input in attack-only confirmation mode"""
        if key == 27:  # ESC
            self.mode = "augmentation_attack_config"
            self.status_message = "Back to attack configuration"
        elif key == curses.KEY_DOWN or key == ord('j'):
            if self.menu_selected < 1:  # 2 options
                self.menu_selected += 1
        elif key == curses.KEY_UP or key == ord('k'):
            if self.menu_selected > 0:
                self.menu_selected -= 1
        elif key in (ord('\n'), ord(' ')):  # Enter or Space
            if self.menu_selected == 0:  # Confirm & Generate
                # Draw running screen BEFORE starting generation
                self.mode = "augmentation_running"
                self.draw_current_screen()
                self.stdscr.refresh()
                
                # Run attack generation only
                success = self.logic.run_attack_generation()
                if success:
                    self.mode = "augmentation_results"
                    self.status_message = "Attack generation completed"
                else:
                    self.mode = "augmentation_results"
                    self.status_message = f"Attack generation error: {self.logic.last_error}"
            elif self.menu_selected == 1:  # Cancel & Edit
                self.mode = "augmentation_attack_config"
                self.status_message = "Back to attack configuration"
        
        return True

    def handle_augmentation_config_input(self, key) -> bool:
        """Handle input in augmentation config mode"""
        if key == 27:  # ESC - go back
            # Check if we're in attack or merge workflow
            augmentation_type = self.logic.augmentation_state.get('augmentation_type', 'merge')
            if augmentation_type == 'attack':
                self.mode = "augmentation_attack_config"
            else:
                self.mode = "augmentation_malicious_select"
            self.status_message = "Back to previous step"
        elif key == ord(' ') or key == ord('\n'):  # Space or Enter - enter input mode
            self.augmentation_config_input_mode = 'project_name'
            self.show_config_input_dialog()
        elif key == ord('q'):  # q to quit
            return False
        
        return True
    
    def show_config_input_dialog(self):
        """Show an interactive dialog to input all configuration values"""
        augmentation_type = self.logic.augmentation_state.get('augmentation_type', 'merge')
        
        # Input project name
        self.layout.draw_header("Augmentation - Configure Options")
        self.layout.draw_text_box("Entering configuration mode...", 10, 2)
        self.layout.draw_help_bar("ESC: Cancel | ENTER: Confirm")
        self.stdscr.refresh()
        
        # Project name (required for all workflows)
        self.layout.clear_screen()
        self.layout.draw_header("Augmentation - Enter Project Name")
        self.layout.draw_text_box(
            "Project Name (alphanumeric, underscore, hyphen, space)\n"
            "Example: augmentation_001 or test_merge\n"
            "(Max 100 characters)\n\n"
            "Leave blank to cancel\n", 
            4, 2
        )
        project_name = self.layout.get_text_input(12, 2, "Project Name: ", 100)
        
        if project_name is None or project_name.strip() == "":
            self.status_message = "Configuration cancelled"
            return
        
        # Validate project name
        validator = InputValidator()
        is_valid, error_msg = validator.validate_project_name(project_name)
        if not is_valid:
            self.status_message = f"Invalid project name: {error_msg}"
            return
        
        # For attack-only mode, only ask for project name
        if augmentation_type == 'attack':
            success = self.logic.set_augmentation_config(
                project_name=project_name.strip(),
                ip_translation_range=None,
                jitter_max=0.1
            )
            
            if success:
                self.mode = "augmentation_confirm_attack_only"
                self.menu_selected = 0
                self.status_message = "Configuration complete - Confirm to proceed"
            else:
                self.status_message = f"Error: {self.logic.last_error}"
            return
        
        # For merge workflows, ask for IP range and jitter
        # IP range
        self.layout.clear_screen()
        self.layout.draw_header("Augmentation - Enter IP Translation Range")
        self.layout.draw_text_box(
            "IP Translation Range (CIDR notation, optional)\n"
            "Example: 192.168.100.0/24\n"
            "Example: 10.50.0.0/16\n"
            "Subnet size: /8 to /25\n\n"
            "Leave blank to skip IP translation\n",
            4, 2
        )
        ip_range = self.layout.get_text_input(12, 2, "IP Range (optional): ", 50)
        
        if ip_range is None:
            self.status_message = "Configuration cancelled"
            return
        
        # Jitter
        self.layout.clear_screen()
        self.layout.draw_header("Augmentation - Enter Jitter Value")
        self.layout.draw_text_box(
            "Jitter Max (seconds, adds randomness to timestamps)\n"
            "Range: 0 to 10 seconds\n"
            "Examples: 0.1 (100ms), 0.5 (500ms), 1.0 (1 second)\n\n"
            "Press ENTER for default (0.1 seconds)\n",
            4, 2
        )
        jitter_str = self.layout.get_text_input(12, 2, "Jitter (seconds): ", 10)
        
        if jitter_str is None:
            self.status_message = "Configuration cancelled"
            return
        
        # Validate IP range
        if ip_range and ip_range.strip():
            is_valid, error_msg = validator.validate_ip_range(ip_range)
            if not is_valid:
                self.status_message = f"Invalid IP range: {error_msg}"
                return
        
        # Validate jitter
        if jitter_str.strip():
            is_valid, jitter_value, error_msg = validator.validate_jitter(jitter_str)
            if not is_valid:
                self.status_message = f"Invalid jitter value: {error_msg}"
                return
        else:
            jitter_value = 0.1
        
        # Apply configuration
        success = self.logic.set_augmentation_config(
            project_name=project_name.strip(),
            ip_translation_range=ip_range.strip() if ip_range.strip() else None,
            jitter_max=jitter_value
        )
        
        if success:
            # For merge workflows, use standard confirm
            self.mode = "augmentation_confirm"
            self.menu_selected = 0
            self.status_message = "Configuration complete - Confirm to proceed"
        else:
            self.status_message = f"Error: {self.logic.last_error}"
    
    def handle_augmentation_confirm_input(self, key) -> bool:
        """Handle input in augmentation confirmation mode"""
        if key == 27:  # ESC
            self.mode = "augmentation_config"
            self.status_message = "Back to configuration"
        elif key == curses.KEY_DOWN or key == ord('j'):
            if self.menu_selected < 1:  # 2 options
                self.menu_selected += 1
        elif key == curses.KEY_UP or key == ord('k'):
            if self.menu_selected > 0:
                self.menu_selected -= 1
        elif key in (ord('\n'), ord(' ')):  # Enter or Space
            if self.menu_selected == 0:  # Confirm
                # Draw running screen BEFORE starting the merge
                self.mode = "augmentation_running"
                self.draw_current_screen()
                self.stdscr.refresh()
                
                # Run augmentation
                results = self.logic.run_augmentation_merge()
                if results:
                    self.mode = "augmentation_results"
                    self.status_message = "Augmentation completed"
                else:
                    self.mode = "augmentation_results"
                    self.status_message = f"Augmentation error: {self.logic.last_error}"
            elif self.menu_selected == 1:  # Cancel
                self.mode = "augmentation_menu"
                self.menu_selected = 0
                self.status_message = "Augmentation cancelled"
        
        return True
    
    def handle_augmentation_running_input(self, key) -> bool:
        """Handle input in augmentation running mode"""
        # No input allowed while running
        return True
    
    def handle_augmentation_results_input(self, key) -> bool:
        """Handle input in augmentation results mode"""
        if key in (ord('\n'), ord(' ')):  # Enter or Space
            # Exit curses mode to validate the merged PCAP
            results = self.logic.get_augmentation_results()
            if results and results.get('success') and results.get('merged_pcap'):
                # Store the merged PCAP path for validation after exiting curses
                self.merged_pcap_to_validate = results.get('merged_pcap')
                return False  # Exit curses mode
            else:
                self.mode = "pcap_info"
                self.status_message = "Back to PCAP info"
        
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
        
        # After exiting curses mode, check if we need to validate a merged PCAP
        if hasattr(ui, 'merged_pcap_to_validate') and ui.merged_pcap_to_validate:
            print("\n" + "="*80)
            print("Curses UI exited. Starting PCAP validation...")
            print("="*80)
            
            # Import validation functions
            import sys
            import os
            sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
            from validators.basic_validator import (
                validate_pcap_magic, validate_pcap_snaplen,
                validate_pcap_packet_headers, validate_pcap_timestamps
            )
            
            pcap_path = ui.merged_pcap_to_validate
            print(f"\nValidating merged PCAP: {pcap_path}\n")
            
            # Run all validations
            all_passed = True
            
            # 1. Magic number check
            magic_res = validate_pcap_magic(pcap_path)
            print("PCAP Magic Number Check:")
            print(f"  ok: {magic_res.get('ok')}")
            if magic_res.get('ok'):
                print(f"  type: {magic_res.get('type')}")
                print(f"  magic: 0x{magic_res.get('magic', '')}")
            else:
                print(f"  reason: {magic_res.get('reason')}")
                all_passed = False
            print()
            
            # 2. Snaplen check
            snaplen_res = validate_pcap_snaplen(pcap_path)
            print("PCAP Snaplen Check:")
            print(f"  snaplen: {snaplen_res.get('snaplen')} bytes")
            print(f"  max packet size: {snaplen_res.get('max_packet_size')} bytes")
            print(f"  ok: {snaplen_res.get('ok')}")
            if not snaplen_res.get('ok'):
                print(f"  reason: {snaplen_res.get('reason')}")
                all_passed = False
            print()
            
            # 3. Packet header integrity
            header_res = validate_pcap_packet_headers(pcap_path)
            print("PCAP Packet Header Integrity Check:")
            print(f"  total packets scanned: {header_res.get('total_packets')}")
            print(f"  ok: {header_res.get('ok')}")
            if not header_res.get('ok'):
                errors = header_res.get('errors', [])
                if errors:
                    print(f"  errors found: {len(errors)}")
                    for err in errors[:5]:
                        print(f"    packet {err['packet_num']}: {err['issue']} - {err['details']}")
                    if len(errors) > 5:
                        print(f"    ... and {len(errors) - 5} more errors")
                elif 'reason' in header_res:
                    print(f"  reason: {header_res.get('reason')}")
                all_passed = False
            print()
            
            # 4. Timestamp validation
            timestamp_res = validate_pcap_timestamps(pcap_path)
            print("PCAP Timestamp Validation:")
            print(f"  ok: {timestamp_res.get('ok')}")
            summary = timestamp_res.get('summary', {})
            if summary:
                print(f"  total timestamps: {summary.get('total_timestamps')} packets")
                print(f"  span: {summary.get('span_seconds'):.6f} seconds")
            
            consecutive_gaps = timestamp_res.get('consecutive_gaps', [])
            outliers = timestamp_res.get('outliers', [])
            
            if consecutive_gaps:
                print(f"  consecutive gaps detected: {len(consecutive_gaps)}")
                for gap in consecutive_gaps[:3]:
                    print(f"    gap between packet {gap['index_before']} -> {gap['index_after']}: {gap['gap_seconds']:.6f}s")
            
            if outliers:
                print(f"  outlier packets detected: {len(outliers)}")
                for outlier in outliers[:3]:
                    print(f"    packet {outlier['index']}: delta={outlier['delta_seconds']:.6f}s")
            
            if not timestamp_res.get('ok'):
                all_passed = False
            
            print("\n" + "="*80)
            if all_passed:
                print("VALIDATION PASSED: All checks successful!")
            else:
                print("VALIDATION FAILED: Some checks did not pass")
            print("="*80 + "\n")
        
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
