import os
import sys
import curses


def main():
    ui_mode = os.getenv("UI_MODE", "curses")

    if ui_mode == "curses":
        # Add src directory to path
        sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
        from user_interfaces import run_curses_ui
        run_curses_ui()
    else:
        # Standard UI - placeholder for now
        print("Standard UI mode not implemented yet.")
        print("Use: UI_MODE=curses python main.py")
        print("Or run directly with curses mode...")
        
        # Ask user if they want to run curses mode instead
        try:
            response = input("Would you like to run the curses interface instead? (y/N): ")
            if response.lower().startswith('y'):
                sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
                from user_interfaces import run_curses_ui
                run_curses_ui()
        except KeyboardInterrupt:
            print("\nExiting...")

if __name__ == "__main__":
    main()