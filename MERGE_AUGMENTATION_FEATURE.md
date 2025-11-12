# Merge Augmentation Feature - Implementation Summary

## Overview
The merge augmentation feature allows users to combine benign and malicious network traffic PCAP files into a single augmented dataset with proper labeling and timestamp handling.

## Components Created

### 1. **MergeAugmentation Orchestrator** (`src/features/augmentations.py`)
The main workflow orchestrator that manages the entire augmentation process:

**Features:**
- **Automatic labeling**: Uses existing `Labeler` to label benign packets as "benign" and malicious packets as "malicious"
- **CSV tracking**: Saves labeled packet information to separate CSV files for audit trail and future analysis
- **PCAP merging**: Combines both labeled PCAP files into a single output file
- **IP translation** (optional): Can translate malicious traffic to a different IP range to avoid conflicts
- **Jitter application** (optional): Adds realistic timing variations to malicious packets
- **Project organization**: Creates folder structure with `csv/` and `pcap/` subdirectories

**Key Methods:**
```python
# Main workflow method
aug = MergeAugmentation(project_name="my_project")
results = aug.run(
    benign_pcap="/path/to/benign.pcapng",
    malicious_pcap="/path/to/malicious.pcapng",
    ip_translation_range="192.168.100.0/24",  # Optional
    jitter_max=0.1  # Optional, in seconds
)

# Convenience function for quick usage
results = merge_augmentation(
    benign_pcap="benign.pcapng",
    malicious_pcap="malicious.pcapng",
    project_name="my_project"
)
```

### 2. **Enhanced Labeler** (`src/features/labeler.py`)
The existing labeler now has a `label_and_export()` method that:
- Reads a PCAP file
- Extracts packet information (IP, ports, protocols, timestamps, etc.)
- Labels each packet with a specified label ("benign" or "malicious")
- Exports to a CSV file with comprehensive packet metadata

### 3. **Example & Testing** (`src/example/merge_augmentation_examples.py`)
Complete example suite demonstrating all features:

**Available modes:**
```bash
# Interactive mode (prompts for user input)
python src/example/merge_augmentation_examples.py interactive

# Basic merge example
python src/example/merge_augmentation_examples.py example1

# Merge with IP translation
python src/example/merge_augmentation_examples.py example2

# Merge with custom jitter
python src/example/merge_augmentation_examples.py example3

# Using custom output directory
python src/example/merge_augmentation_examples.py example4

# Advanced class-based usage
python src/example/merge_augmentation_examples.py example5
```

### 4. **Integration Guide** (`AUGMENTATION_INTEGRATION_GUIDE.md`)
Detailed instructions for integrating the merge augmentation into the curses UI, including:
- Code templates for `curses_logic.py` integration
- UI screen flow design for `curse_mode.py`
- Workflow overview
- Testing instructions

## Workflow Overview

```
User selects "Merge Augmentations (Option 1)"
    ↓
Select benign PCAP file
    ↓
Select malicious PCAP file
    ↓
Enter project name & options
    ↓
Confirmation screen
    ↓
[EXECUTION]
├─ Label benign PCAP → benign_labeled.csv
├─ Label malicious PCAP → malicious_labeled.csv
└─ Merge both PCAP files → merged_output.pcapng
    ↓
Display results with paths and statistics
```

## Output Structure

```
project_folder/
├── csv/
│   ├── benign_labeled.csv       (packet index, label, timestamp, protocol, IP info, etc.)
│   └── malicious_labeled.csv    (packet index, label, timestamp, protocol, IP info, etc.)
└── pcap/
    └── project_name_merged.pcapng    (merged PCAP with all packets)
```

## Key Features

### 1. **Packet Labeling & Audit Trail**
- Each packet in the CSV contains:
  - Packet index (no.)
  - Label (benign/malicious)
  - Timestamp
  - Protocol type
  - Packet length
  - IP addresses (src/dst)
  - Port information (for TCP/UDP)
  - TCP flags (for TCP)
  - Protocol-specific fields (ICMP, ARP, etc.)

### 2. **Timeline Mapping**
- Malicious packets are intelligently mapped into the benign timeline
- Relative positions are preserved
- Optional jitter can be applied for realistic blending
- Timestamp conflicts are automatically resolved

### 3. **IP Translation**
- Optional IP address translation for malicious traffic
- Prevents IP conflicts between benign and malicious datasets
- Configurable via CIDR range (e.g., "192.168.100.0/24")

### 4. **Merge Statistics**
Results include:
- Benign packet count
- Malicious packet count
- Total packets in merged output
- Netflow counts
- Configuration summary

## Configuration Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `project_name` | str | required | Project folder name |
| `benign_pcap` | str | required | Path to benign PCAP |
| `malicious_pcap` | str | required | Path to malicious PCAP |
| `ip_translation_range` | str | None | CIDR range for IP translation |
| `jitter_max` | float | 0.1 | Max jitter in seconds (malicious traffic only) |
| `output_base_dir` | str | src/features/augmentations | Base output directory |

## Example Usage

### Quick Start (Convenience Function)
```python
from src.features.augmentations import merge_augmentation

results = merge_augmentation(
    benign_pcap="benign.pcapng",
    malicious_pcap="malicious.pcapng",
    project_name="my_first_augmentation"
)

if results['success']:
    print(f"✓ Merged PCAP: {results['merged_pcap']}")
    print(f"✓ Project: {results['project_dir']}")
```

### Advanced (Class-Based)
```python
from src.features.augmentations import MergeAugmentation

aug = MergeAugmentation(project_name="advanced_project")
results = aug.run(
    benign_pcap="benign.pcapng",
    malicious_pcap="malicious.pcapng",
    ip_translation_range="192.168.100.0/24",
    jitter_max=0.5
)
aug.print_results(results)
```

## Next Steps for UI Integration

1. **Update `curses_logic.py`**:
   - Add `start_augmentation_merge()` method
   - Add PCAP selection and configuration methods
   - Add `run_augmentation_merge()` execution method

2. **Update `curse_mode.py`**:
   - Create UI screens for each step (file selection, configuration, confirmation)
   - Hook into main menu with "Augmentation" option
   - Display results screen

3. **See `AUGMENTATION_INTEGRATION_GUIDE.md`** for detailed code templates and workflow design

## Error Handling

All methods include comprehensive error handling:
- File validation (checks file existence)
- Graceful failure on PCAP load/merge errors
- Detailed error messages in results
- Last error tracking in logic layer

## Testing

```bash
# Test with sample files
cd /Users/nanadavidsen/Desktop/aau-network-augmentation
python src/example/merge_augmentation_examples.py example1

# Interactive testing
python src/example/merge_augmentation_examples.py interactive
```

## Notes

- The merger preserves packet order and handles timestamp conflicts automatically
- IP translation is optional and only applied if a range is specified
- Jitter is only applied to malicious traffic (benign traffic keeps original timing)
- CSV files include comprehensive packet metadata for analysis and machine learning
- All operations are reversible (original files are never modified)
