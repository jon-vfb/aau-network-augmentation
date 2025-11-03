# AAU Network Augmentation Tool

A network packet analysis and augmentation tool with NetFlow analysis capabilities.

## Features

- PCAP file parsing and analysis
- NetFlow generation and analysis  
- Interactive curses-based user interface
- Packet detail inspection
- Network traffic visualization

## Installation

### Windows Setup

1. **Install Python dependencies:**
   ```bash
   pip install -r requirements-windows.txt
   ```

2. **Required packages for Windows:**
   - `scapy==2.6.1` - Packet manipulation library
   - `windows-curses==2.3.3` - Curses library for Windows terminal interfaces

### Linux/macOS Setup

1. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

Note: On Linux/macOS, curses is included with Python by default.

## Usage

### Running the Application

```bash
python main.py
```

Or with environment variable:

```bash
UI_MODE=curses python main.py
```

### Navigation

**PCAP File Selection:**
- ↑↓ or j/k: Navigate through files
- Enter: Select PCAP file
- q: Quit

**NetFlow Analysis:**
- ↑↓ or j/k: Navigate through flows
- Enter: View flow details
- ESC: Go back

**Packet Analysis:**
- ↑↓ or j/k: Navigate through packets
- Enter: View packet details
- ESC: Go back
- q: Quit

### Packet Detail View

When viewing individual packets, you'll see:
- Complete packet headers (Ethernet, IP, TCP/UDP/ICMP)
- Detailed protocol information
- Raw payload data in hex dump format
- TCP flags and connection state information

## File Structure

```
├── main.py                 # Application entry point
├── src/
│   ├── classes/
│   │   └── pcapparser.py   # PCAP parsing functionality
│   ├── user_interfaces/
│   │   └── curses/         # Curses-based UI components
│   └── features/           # Network analysis features
├── samples/                # Sample PCAP files
└── requirements-windows.txt # Windows dependencies
```

## Troubleshooting

### Windows Curses Issues

If you encounter curses-related errors on Windows:

1. **Install windows-curses:**
   ```bash
   pip install windows-curses
   ```

2. **Use a compatible terminal:**
   - Windows Terminal (recommended)
   - Command Prompt
   - PowerShell
   - WSL terminal

3. **Avoid:**
   - Git Bash (limited curses support)
   - Some third-party terminals

### Common Issues

**"No PCAP files found":**
- Place `.pcap` or `.pcapng` files in the `samples/` directory
- Check file permissions

**Import errors:**
- Ensure all dependencies are installed
- Check Python version compatibility (3.7+)

## Development

### Adding Sample Files

Place PCAP files in the `samples/` directory. Supported formats:
- `.pcap`
- `.pcapng`

### Extending Functionality

The application is modular:
- `pcapparser.py` - Core packet analysis
- `curses_layout.py` - UI rendering  
- `curses_logic.py` - Business logic
- `curse_mode.py` - UI controller

## Requirements

- Python 3.7+
- Windows: windows-curses package
- Scapy for packet manipulation
- Network capture files (.pcap/.pcapng)