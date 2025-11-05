#!/usr/bin/env python3
"""
Test script to verify curses installation on Windows
"""
import sys
import os

def test_curses():
    """Test curses functionality"""
    print("Testing curses installation...")
    
    try:
        import curses
        print("✓ Curses module imported successfully")
        
        # Test basic curses functionality
        if hasattr(curses, 'wrapper'):
            print("✓ Curses wrapper function available")
        else:
            print("✗ Curses wrapper function missing")
            return False
            
        if hasattr(curses, 'has_colors'):
            print("✓ Curses color support available")
        else:
            print("✗ Curses color support missing")
            return False
            
        # Test basic constants
        required_constants = ['KEY_UP', 'KEY_DOWN', 'A_BOLD', 'A_REVERSE']
        for const in required_constants:
            if hasattr(curses, const):
                print(f"✓ Constant {const} available")
            else:
                print(f"✗ Constant {const} missing")
                return False
        
        print("\n✓ All curses tests passed!")
        return True
        
    except ImportError as e:
        print(f"✗ Failed to import curses: {e}")
        print("\nTo fix this on Windows:")
        print("1. pip install windows-curses")
        print("2. Or run: install-windows.bat")
        return False
    except Exception as e:
        print(f"✗ Curses test failed: {e}")
        return False

def test_scapy():
    """Test scapy installation"""
    print("\nTesting scapy installation...")
    
    try:
        import scapy
        from scapy.all import IP, TCP, UDP, ICMP, ARP
        print("✓ Scapy imported successfully")
        print(f"✓ Scapy version: {scapy.VERSION}")
        return True
    except ImportError as e:
        print(f"✗ Failed to import scapy: {e}")
        print("To fix this: pip install scapy")
        return False
    except Exception as e:
        print(f"✗ Scapy test failed: {e}")
        return False

def main():
    """Main test function"""
    print("AAU Network Augmentation Tool - Dependency Test")
    print("=" * 50)
    
    # Check Python version
    print(f"Python version: {sys.version}")
    if sys.version_info < (3, 7):
        print("✗ Python 3.7+ required")
        return False
    else:
        print("✓ Python version OK")
    
    # Test dependencies
    curses_ok = test_curses()
    scapy_ok = test_scapy()
    
    print("\n" + "=" * 50)
    if curses_ok and scapy_ok:
        print("✓ All tests passed! The application should work correctly.")
        
        # Test if sample files exist
        samples_dir = os.path.join(os.path.dirname(__file__), 'samples')
        if os.path.exists(samples_dir):
            pcap_files = [f for f in os.listdir(samples_dir) if f.endswith(('.pcap', '.pcapng'))]
            if pcap_files:
                print(f"✓ Found {len(pcap_files)} PCAP file(s) in samples directory")
            else:
                print("! No PCAP files found in samples directory")
                print("  Add .pcap or .pcapng files to samples/ to test the application")
        else:
            print("! Samples directory not found")
            
        print("\nRun the application with: python main.py")
    else:
        print("✗ Some tests failed. Please install missing dependencies.")
        return False
    
    return True

if __name__ == "__main__":
    success = main()
    
    if not success:
        print("\nPress Enter to exit...")
        input()
        sys.exit(1)