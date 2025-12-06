"""
Loading screen with animation for curses UI initialization.
"""

import curses
import threading
import time


class LoadingScreen:
    """
    Display a loading screen with animated dots and customizable ASCII art/text.
    """
    
    # Default ASCII art (you can change this)
    DEFAULT_ASCII_ART = r"""
    ╔═══════════════════════════════════════════╗
    ║   PCAP Network Augmentation Tool          ║
    ╚═══════════════════════════════════════════╝
    """
    
    # Default loading text (you can change this)
    DEFAULT_LOADING_TEXT = "Initializing Application"
    DEFAULT_LOADING_TEXT_2 = "Please wait..."
    
    def __init__(self, ascii_art=None, loading_text=None, loading_text_2=None):
        """
        Initialize the loading screen.
        
        Args:
            ascii_art: Custom ASCII art to display (multiline string)
            loading_text: Custom loading text to display (main subtitle)
            loading_text_2: Custom loading text to display (secondary subtitle)
        """
        self.ascii_art = ascii_art if ascii_art is not None else self.DEFAULT_ASCII_ART
        self.loading_text = loading_text if loading_text is not None else self.DEFAULT_LOADING_TEXT
        self.loading_text_2 = loading_text_2 if loading_text_2 is not None else self.DEFAULT_LOADING_TEXT_2
        self.running = False
        self.animation_thread = None
        self.stdscr = None
        self.dot_count = 0
        self.max_dots = 3
        
    def _animate_dots(self):
        """Animate the loading dots."""
        while self.running:
            try:
                if self.stdscr is None:
                    break
                    
                # Calculate dot animation for second text
                dots = "." * self.dot_count
                spaces = " " * (self.max_dots - self.dot_count)
                loading_line_2 = f"{self.loading_text_2}{dots}{spaces}"
                
                # Get screen dimensions
                height, width = self.stdscr.getmaxyx()
                
                # Clear and redraw
                self.stdscr.clear()
                
                # Draw ASCII art centered (remove extra whitespace per line)
                ascii_lines = self.ascii_art.strip().split('\n')
                
                # Calculate content width based on longest ASCII line
                max_ascii_width = max(len(line.rstrip()) for line in ascii_lines) if ascii_lines else 0
                max_text_width = max(len(self.loading_text), len(loading_line_2))
                content_width = max(max_ascii_width, max_text_width) + 4  # +4 for padding (2 on each side)
                content_height = len(ascii_lines) + 4  # ASCII + 2 text lines + padding
                
                # Calculate border position
                border_start_y = max(0, (height - content_height - 2) // 2)
                border_start_x = max(0, (width - content_width - 2) // 2)
                
                # Draw top border
                if border_start_y < height - 1:
                    top_border = "┌" + "─" * (content_width) + "┐"
                    try:
                        self.stdscr.addstr(border_start_y, border_start_x, top_border)
                    except curses.error:
                        pass
                
                # Draw padding line after top border
                padding_y = border_start_y + 1
                if padding_y < height - 2:
                    try:
                        self.stdscr.addstr(padding_y, border_start_x, "│" + " " * content_width + "│")
                    except curses.error:
                        pass
                
                # Draw ASCII art inside border (centered)
                start_y = padding_y + 1
                for i, line in enumerate(ascii_lines):
                    y_pos = start_y + i
                    if y_pos < height - 3:
                        # Strip trailing whitespace from each line
                        line = line.rstrip()
                        line_len = len(line)
                        # Center the line within the content area
                        padding_left = (content_width - line_len) // 2
                        centered_line = " " * padding_left + line + " " * (content_width - line_len - padding_left)
                        
                        try:
                            self.stdscr.addstr(y_pos, border_start_x, "│" + centered_line + "│")
                        except curses.error:
                            pass
                
                # Draw first loading text (static, centered)
                loading_y = start_y + len(ascii_lines)
                if loading_y < height - 2:
                    text_len = len(self.loading_text)
                    padding_left = (content_width - text_len) // 2
                    centered_text = " " * padding_left + self.loading_text + " " * (content_width - text_len - padding_left)
                    try:
                        self.stdscr.addstr(loading_y, border_start_x, "│" + centered_text + "│")
                    except curses.error:
                        pass
                
                # Draw secondary loading text with animated dots (centered)
                loading_y_2 = loading_y + 1
                if loading_y_2 < height - 2:
                    text_len_2 = len(loading_line_2)
                    padding_left_2 = (content_width - text_len_2) // 2
                    centered_text_2 = " " * padding_left_2 + loading_line_2 + " " * (content_width - text_len_2 - padding_left_2)
                    try:
                        self.stdscr.addstr(loading_y_2, border_start_x, "│" + centered_text_2 + "│")
                    except curses.error:
                        pass
                
                # Draw padding line before bottom border
                padding_y_2 = loading_y_2 + 1
                if padding_y_2 < height - 1:
                    try:
                        self.stdscr.addstr(padding_y_2, border_start_x, "│" + " " * content_width + "│")
                    except curses.error:
                        pass
                
                # Draw bottom border
                bottom_y = padding_y_2 + 1
                if bottom_y < height - 1:
                    bottom_border = "└" + "─" * (content_width) + "┘"
                    try:
                        self.stdscr.addstr(bottom_y, border_start_x, bottom_border)
                    except curses.error:
                        pass
                
                self.stdscr.refresh()
                
                # Update dot count
                self.dot_count = (self.dot_count + 1) % (self.max_dots + 1)
                
                # Sleep for animation speed
                time.sleep(0.5)
                
            except Exception:
                # Silently handle any errors during animation
                break
    
    def start(self, stdscr):
        """
        Start the loading screen animation.
        
        Args:
            stdscr: The curses screen object
        """
        self.stdscr = stdscr
        self.running = True
        
        # Hide cursor
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        
        # Start animation in a separate thread
        self.animation_thread = threading.Thread(target=self._animate_dots, daemon=True)
        self.animation_thread.start()
    
    def stop(self):
        """Stop the loading screen animation."""
        self.running = False
        if self.animation_thread is not None:
            self.animation_thread.join(timeout=1.0)
        self.stdscr = None


def show_loading_screen(initialization_func, ascii_art=None, loading_text=None, loading_text_2=None):
    """
    Show a loading screen while running an initialization function.
    
    Args:
        initialization_func: Function to run while showing the loading screen
        ascii_art: Custom ASCII art to display
        loading_text: Custom loading text to display (main subtitle)
        loading_text_2: Custom loading text to display (secondary subtitle)
        
    Returns:
        The result of initialization_func
    """
    result = [None]
    exception = [None]
    
    def run_with_loading(stdscr):
        # Create and start loading screen
        loading = LoadingScreen(ascii_art=ascii_art, loading_text=loading_text, loading_text_2=loading_text_2)
        loading.start(stdscr)
        
        # Run initialization in a separate thread
        def init_thread():
            try:
                result[0] = initialization_func()
            except Exception as e:
                exception[0] = e
        
        init = threading.Thread(target=init_thread)
        init.start()
        
        # Wait for initialization to complete
        init.join()
        
        # Stop loading screen
        loading.stop()
        
        # Small delay to ensure clean transition
        time.sleep(0.1)
    
    # Run the loading screen
    curses.wrapper(run_with_loading)
    
    # Raise exception if one occurred
    if exception[0] is not None:
        raise exception[0]
    
    return result[0]
