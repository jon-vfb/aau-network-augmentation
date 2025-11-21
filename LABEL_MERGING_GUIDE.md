# PCAP Merger with Label Support

## Overview

The updated `PcapMerger` class now supports optional input and output label CSV files. When you merge two PCAP files, you can provide label CSVs for each input file, and the merger will generate a merged label CSV that tracks:

- **Original labels** from the input PCAP files
- **IP address changes** (for malicious traffic with IP translation)
- **Timestamp changes** (packets are remapped to the benign timeline)
- **Packet source** (identifies if packet came from left/benign or right/malicious PCAP)

## Simple Usage

### Basic Merge with Labels

```python
from src.features.merger.pcap_merger import PcapMerger

# Initialize the merger
merger = PcapMerger(jitter_max=0.05)

# Set IP translation range for malicious traffic
merger.set_ip_translation_range("192.168.100.0/24")

# Merge with label tracking
success = merger.merge_pcaps(
    left_pcap="benign.pcapng",
    right_pcap="malicious.pcapng",
    output_file="merged.pcapng",
    left_labels="benign_labels.csv",      # Optional: labels for benign PCAP
    right_labels="malicious_labels.csv",  # Optional: labels for malicious PCAP
    output_labels="merged_labels.csv"     # Optional: output merged labels
)
```

### Without Labels (Original Behavior)

```python
# Still works as before - labels are optional
success = merger.merge_pcaps(
    left_pcap="benign.pcapng",
    right_pcap="malicious.pcapng",
    output_file="merged.pcapng"
)
```

## Input Label Format

Label CSV files should have the following format (created by `Labeler` class):

```csv
index,label,timestamp,length,protocol,source_ip,destination_ip,...
0,benign,1759919617.346387,342,Ethernet,0.0.0.0,255.255.255.255,...
1,benign,1759919620.926995,342,Ethernet,192.168.137.1,192.168.137.45,...
```

**Minimum required columns:**
- `index`: Packet index in original PCAP
- `label`: Label for the packet (e.g., "benign", "malicious", attack type)
- `timestamp`: Original packet timestamp
- `source_ip` (optional): Source IP address
- `destination_ip` (optional): Destination IP address

**Additional columns** are preserved and passed through to the output.

## Output Label Format

The merged label CSV includes all input columns plus:

- `index`: New index in merged PCAP
- `timestamp`: **Updated timestamp** (remapped to benign timeline)
- `source_ip`: **Updated IP** (if IP translation was applied)
- `destination_ip`: **Updated IP** (if IP translation was applied)
- `source`: Identifies source PCAP ("left" for benign, "right" for malicious)

Example output:

```csv
index,label,timestamp,source_ip,destination_ip,source
0,benign,1759919617.346387,0.0.0.0,255.255.255.255,left
1,benign,1759919620.926995,192.168.137.1,192.168.137.45,left
2,malicious,1759919620.941234,192.168.100.1,192.168.100.10,right
```

## Key Features

### 1. **Automatic IP Translation Tracking**
- When malicious traffic is IP-translated, the output labels reflect the **new IP addresses**
- Original labels for benign traffic remain unchanged

### 2. **Timestamp Remapping**
- Malicious packets are remapped from their original timeline to the benign timeline
- Output labels show the **new timestamps**
- Jitter offsets are accounted for

### 3. **Packet Provenance**
- The `source` column indicates whether each packet came from:
  - `"left"`: Benign PCAP
  - `"right"`: Malicious PCAP
- Useful for analysis and validation

### 4. **Backward Compatible**
- Labels are completely optional
- If no labels are provided, the merger works exactly as before
- You can merge PCAP files and only generate labels later if needed

## Advanced Usage

### Full Control Over Label Processing

```python
from src.features.merger.pcap_merger import PcapMerger

merger = PcapMerger(jitter_max=0.1)
merger.set_ip_translation_range("10.0.0.0/8")

# Load both PCAPs and labels
merger.load_pcaps(
    left_pcap="benign.pcapng",
    right_pcap="attack.pcapng",
    left_labels="benign_labels.csv",
    right_labels="attack_labels.csv"
)

# Perform merge and generate labels
success = merger.merge(
    output_path="merged.pcapng",
    output_labels_path="merged_labels.csv"
)

# Get statistics
stats = merger.get_merge_statistics()
print(f"Merged {stats['total_expected_packets']} packets total")
```

### Accessing Merged Labels Programmatically

```python
# Labels are stored in merger object after merge
merged_labels_df = merger._adjust_labels_for_merged_packets(resolved_packets)

# Use pandas for analysis
import pandas as pd
benign_packets = merged_labels_df[merged_labels_df['source'] == 'left']
malicious_packets = merged_labels_df[merged_labels_df['source'] == 'right']

print(f"Benign packets: {len(benign_packets)}")
print(f"Malicious packets: {len(malicious_packets)}")
```

## Implementation Details

### Packet Matching Algorithm

The merger identifies packets in the merged PCAP by:
1. **Identity check** for left (benign) packets - direct object reference
2. **Content matching** for right (malicious) packets - compares packet structure and layers

This ensures accurate label mapping even after packet copying and modification.

### IP and Timestamp Correlation

- **Timestamps**: Each packet's original position in its capture is preserved as a ratio, then remapped to the benign timeline
- **IPs**: If IP translation is enabled and successful, labels are updated with new IPs; otherwise, original IPs are preserved

### Data Integrity

- Empty/missing label fields are preserved in output
- All input columns are carried forward to output
- Packets without labels get new labels generated with source information

## Error Handling

The merger gracefully handles:
- Missing label files (silently skips if not found)
- Incomplete labels (fills in available fields, adds source/timestamp/IP info)
- Non-matching packet counts (labels are matched by index, extras are ignored)
- IP translation failures (keeps original IPs and notes warning)

## Examples

See `src/example/merge_with_labels_example.py` for complete working examples:

```bash
cd src
python example/merge_with_labels_example.py
```

## Performance Considerations

- Label processing adds minimal overhead (primarily DataFrame operations)
- Pandas is used for efficient CSV handling
- IP matching is O(n) where n is number of packets

## Troubleshooting

### No Output Labels Generated
- Check that input label files exist and are readable
- Verify CSV format matches expected schema
- Check console output for warnings/errors

### IP Addresses Not Updated
- Ensure `set_ip_translation_range()` was called before merge
- Check that malicious PCAP packets have IP layers
- Verify translation range doesn't conflict with existing IPs

### Timestamp Discrepancies
- Output timestamps should be within benign PCAP's time range
- If jitter is enabled, expect minor variations
- Timestamp ordering is always preserved

## See Also

- `Labeler` class in `src/features/labeler.py` - for creating label CSVs
- `PcapMerger` class in `src/features/merger/pcap_merger.py` - main implementation
- PROTOCOL_INTEGRATION_GUIDE.md - for general protocol handling
