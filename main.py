import os
import sys


def main():

    print("App initializing...")

    ui_mode = os.getenv("UI_MODE", "curses")

    if ui_mode == "curses":
        try:
            # Add src directory to path
            sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
            from user_interfaces import run_curses_ui
            run_curses_ui()
        except ModuleNotFoundError as e:
            if "_curses" in str(e) or "curses" in str(e):
                print("\n" + "="*70)
                print("ERROR: Curses module (_curses) is not available on this system")
                print("="*70)
                print("\nCurses has limited support on Windows.")
                print("\nTo fix this, choose one of the following options:")
                print("\n1. RECOMMENDED: Install windows-curses")
                print("   pip install windows-curses")
                print("   OR")
                print("   pip install -r requirements-windows.txt")
                print("\n2. Use Windows Subsystem for Linux (WSL)")
                print("   wsl python main.py")
                print("\n3. Use a Unix-like system (Linux, macOS)")
                print("\n4. Wait for CLI implementation (non-curses interface)")
                print("\n" + "="*70)
                sys.exit(1)
            else:
                raise
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