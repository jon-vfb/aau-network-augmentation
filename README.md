# Network Traffic Augmentation System

A system for augmenting network traffic with various attack patterns for security research and IDS/IPS testing.

## Features

- **Multiple Attack Types**: Port scanning, ARP spoofing, Ping of Death, and more
- **Extensible Architecture**: Easy to add new attack generators
- **PCAP Generation**: Creates realistic network traffic in PCAP format
- **Interactive UI**: Curses-based terminal interface
- **Automatic Discovery**: Attacks are automatically registered
- **IP Translation**: Automatic IP range detection and translation with configurable defaults
- **Smart Merging**: Merge benign and malicious traffic with timestamp jitter

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Optional: Configure environment variables
cp .env.example .env
# Edit .env to customize settings (e.g., AUTO_IP_TRANSLATION=true)

# Run the application
python main.py
```

## Configuration

### Environment Variables

The system supports configuration via environment variables. Copy `.env.example` to `.env` and customize:

- **AUTO_IP_TRANSLATION**: When set to `true`, automatically uses the benign file's IP range as the default for malicious traffic translation during merge operations. This simplifies the merge workflow by eliminating manual IP range input when you want to use the benign network's address space.

Example `.env` file:
```bash
AUTO_IP_TRANSLATION=true
```

### IP Range Detection

When merging PCAP files, the system automatically detects and displays the IP ranges from both files:
- **Benign file IP range**: Detected from the benign network traffic
- **Malicious file IP range**: Detected from the malicious network traffic

If `AUTO_IP_TRANSLATION=true`, pressing Enter without specifying an IP range will use the benign file's IP range as the default translation target.

## Developing New Attacks

Want to add a new attack type? We've made it easy!

### Documentation

📖 **[Complete Development Guide](docs/ATTACK_DEVELOPMENT_GUIDE.md)**
- Comprehensive tutorial with step-by-step instructions
- Best practices and design patterns
- Multiple complete examples
- Troubleshooting guide

📋 **[Quick Reference](docs/ATTACK_QUICK_REFERENCE.md)**
- Common code patterns
- Parameter types
- Scapy layer reference
- Testing commands

### Quick Overview

1. Create a file in `src/features/attacks/` (e.g., `my_attack_generator.py`)
2. Inherit from `AttackBase`
3. Define attack metadata and parameters
4. Implement packet generation logic
5. Your attack automatically appears in the UI!

See [`src/features/attacks/README.md`](src/features/attacks/README.md) for more details.

## Project Structure

```
src/
├── features/
│   ├── attacks/           # Attack generators (add new attacks here)
│   │   ├── __init__.py    # Auto-discovery system
│   │   ├── attack_base.py # Base class
│   │   ├── arp_spoofing_generator.py
│   │   ├── scanning_port_generator.py
│   │   └── ping_of_death_generator.py
│   ├── augmentations.py   # Augmentation logic
│   └── merger/            # PCAP merging utilities
├── user_interfaces/       # UI implementations
└── utils/                 # Utility functions

docs/                      # Documentation
├── ATTACK_DEVELOPMENT_GUIDE.md
└── ATTACK_QUICK_REFERENCE.md
```

## Available Attacks

- **ARP Spoofing**: ARP cache poisoning attack
- **Port Scan**: TCP port scanning to discover open ports
- **Ping of Death**: Oversized ICMP packets to crash systems

Each attack is configurable with custom parameters through the UI.

## Contributing

We welcome contributions! To add a new attack:

1. Read the [Attack Development Guide](docs/ATTACK_DEVELOPMENT_GUIDE.md)
2. Create your attack generator
3. Test thoroughly
4. Submit a pull request

## License

[Add your license here]

## Support

For questions or issues:
- Check the documentation in `docs/`
- Review existing attacks in `src/features/attacks/`
- Open an issue on GitHub
