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
    
    def __init__(self, ascii_art=None, loading_text=None):
        """
        Initialize the loading screen.
        
        Args:
            ascii_art: Custom ASCII art to display (multiline string)
            loading_text: Custom loading text to display
        """
        self.ascii_art = ascii_art if ascii_art is not None else self.DEFAULT_ASCII_ART
        self.loading_text = loading_text if loading_text is not None else self.DEFAULT_LOADING_TEXT
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
                    
                # Calculate dot animation
                dots = "." * self.dot_count
                spaces = " " * (self.max_dots - self.dot_count)
                loading_line = f"{self.loading_text}{dots}{spaces}"
                
                # Get screen dimensions
                height, width = self.stdscr.getmaxyx()
                
                # Clear and redraw
                self.stdscr.clear()
                
                # Draw ASCII art centered
                ascii_lines = self.ascii_art.strip().split('\n')
                start_y = max(0, (height - len(ascii_lines) - 4) // 2)
                
                for i, line in enumerate(ascii_lines):
                    y_pos = start_y + i
                    if y_pos < height - 3:
                        x_pos = max(0, (width - len(line)) // 2)
                        try:
                            self.stdscr.addstr(y_pos, x_pos, line)
                        except curses.error:
                            pass  # Ignore if text doesn't fit
                
                # Draw loading text with dots below ASCII art
                loading_y = start_y + len(ascii_lines) + 2
                if loading_y < height - 1:
                    loading_x = max(0, (width - len(loading_line)) // 2)
                    try:
                        self.stdscr.addstr(loading_y, loading_x, loading_line)
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


def show_loading_screen(initialization_func, ascii_art=None, loading_text=None):
    """
    Show a loading screen while running an initialization function.
    
    Args:
        initialization_func: Function to run while showing the loading screen
        ascii_art: Custom ASCII art to display
        loading_text: Custom loading text to display
        
    Returns:
        The result of initialization_func
    """
    result = [None]
    exception = [None]
    
    def run_with_loading(stdscr):
        # Create and start loading screen
        loading = LoadingScreen(ascii_art=ascii_art, loading_text=loading_text)
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
