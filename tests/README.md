# Tests Directory

This directory contains test suites for validating merged PCAP files and their labels.

## Overview

The test suite verifies that merged PCAP files are correctly labeled by checking:

1. **Packet Count** - Number of packets matches number of label entries
2. **Timestamps** - Packet timestamps match label timestamps
3. **IP Addresses** - IP addresses in packets match those in labels
4. **IP Translations** - Translated IPs are correctly applied and documented
5. **Label Integrity** - Label values are valid and consistent
6. **Chronological Order** - Packets are properly ordered by timestamp

## Files

- `test_merged_pcap_labels.py` - Main test suite for merged PCAP validation
- `test_examples.py` - Examples showing how to use the test suite
- `__init__.py` - Package initialization

## Quick Start

### Standalone Validation

Validate a merged PCAP file directly from the command line:

```bash
python tests/test_merged_pcap_labels.py merged.pcap merged_labels.csv
```

With IP translation report:

```bash
python tests/test_merged_pcap_labels.py merged.pcap merged_labels.csv ip_translation_report.csv
```

### Using unittest

Run all tests:

```bash
python -m unittest tests.test_merged_pcap_labels
```

Run with verbose output:

```bash
python -m unittest -v tests.test_merged_pcap_labels
```

### Programmatic Usage

```python
from tests.test_merged_pcap_labels import TestMergedPcapLabels

# Create test instance
test = TestMergedPcapLabels()

# Validate merged files
results = test.verify_merged_pcap_labels(
    merged_pcap_path="path/to/merged.pcap",
    labels_csv_path="path/to/labels.csv",
    ip_translation_csv_path="path/to/ip_translation.csv",  # Optional
    verbose=True
)

# Check results
if results['valid']:
    print("✅ Validation passed!")
else:
    print("❌ Validation failed:")
    for error in results['errors']:
        print(f"  - {error}")
```

## Integration with Merge Workflow

You can integrate validation into your merge workflow:

```python
from src.features.merger.pcap_merger import PcapMerger
from tests.test_merged_pcap_labels import TestMergedPcapLabels

# Merge PCAPs
merger = PcapMerger(jitter_max=0.05)
merger.set_ip_translation_range("192.168.100.0/24")

success = merger.merge_pcaps(
    left_pcap="benign.pcap",
    right_pcap="malicious.pcap",
    output_file="output/merged.pcap",
    left_labels="benign_labels.csv",
    right_labels="malicious_labels.csv",
    output_labels="output/merged_labels.csv"
)

# Validate immediately after merge
if success:
    test = TestMergedPcapLabels()
    results = test.verify_merged_pcap_labels(
        merged_pcap_path="output/merged.pcap",
        labels_csv_path="output/merged_labels.csv",
        ip_translation_csv_path="output/merged_ip_translation_report.csv",
        verbose=True
    )
    
    if not results['valid']:
        print("⚠ Validation found issues!")
        for error in results['errors']:
            print(f"  {error}")
```

## Required Files

To run validation, you need:

1. **Merged PCAP file** - The output PCAP file from merging
2. **Labels CSV file** - The merged labels CSV file
3. **IP Translation CSV** (optional) - The IP translation report

### Label CSV Format

The labels CSV should contain at minimum:

- `index` - Packet index
- `timestamp` - Packet timestamp
- `source_ip` - Source IP address (for IP packets)
- `destination_ip` - Destination IP address (for IP packets)
- `label` - Packet label (e.g., "benign", "malicious")

Example:
```csv
index,timestamp,source_ip,destination_ip,label,protocol
0,1759919617.346387,192.168.1.1,192.168.1.2,benign,TCP
1,1759919617.346388,192.168.1.2,192.168.1.1,benign,TCP
```

### IP Translation CSV Format

The IP translation report should contain:

- `original_ip` - Original IP address
- `translated_ip` - Translated IP address

Example:
```csv
original_ip,translated_ip
10.0.0.1,192.168.100.1
10.0.0.2,192.168.100.2
```

## Validation Checks

### 1. Packet Count Validation

Ensures that the number of packets in the PCAP file matches the number of entries in the labels CSV.

```python
# Passes if:
len(packets) == len(labels_df)
```

### 2. Timestamp Validation

Verifies that timestamps in the labels CSV match the packet timestamps in the PCAP file (within microsecond precision).

```python
# Passes if for each packet:
abs(pkt.time - label_timestamp) < 0.000001  # 1 microsecond tolerance
```

### 3. IP Address Validation

Checks that IP addresses in the labels match the actual packet IP addresses.

```python
# Passes if for each IP packet:
pkt[IP].src == label['source_ip']
pkt[IP].dst == label['destination_ip']
```

### 4. IP Translation Validation

If an IP translation report is provided, verifies that:
- All translated IPs are documented
- Translations are correctly applied in both PCAP and labels

### 5. Label Integrity

Validates that:
- Required columns exist in the labels CSV
- Label values are valid (if expected values are defined)
- No missing or corrupt data

### 6. Chronological Order

Ensures packets are in chronological order by timestamp:

```python
# Passes if:
for i in range(1, len(packets)):
    packets[i].time >= packets[i-1].time
```

## Test Results

The `verify_merged_pcap_labels()` method returns a results dictionary:

```python
{
    'valid': True/False,           # Overall validation status
    'errors': [...],                # List of error messages
    'warnings': [...],              # List of warning messages
    'stats': {
        'packet_count': 1000,       # Number of packets validated
        'label_count': 1000,        # Number of labels validated
        'translations': 10          # Number of IP translations (if applicable)
    }
}
```

## Examples

See `test_examples.py` for comprehensive examples:

```bash
python tests/test_examples.py
```

This will show:
- How to validate existing merged files
- How to integrate validation into merge workflows
- How to run as unittest
- How to use as standalone script

## Troubleshooting

### "PCAP file not found"
Ensure the path to the merged PCAP file is correct and the file exists.

### "Labels CSV file not found"
Ensure you generated labels when merging. Use the `output_labels` parameter in `merge_pcaps()`.

### "Timestamp mismatches"
This may indicate issues with the merge process. Check that:
- Jitter settings are appropriate
- Time offset calculations are correct
- Packets weren't modified after label generation

### "IP address mismatches"
This may indicate:
- Labels were generated before IP translation was applied
- IP translation didn't work correctly
- Labels and PCAP files are from different merge operations

## Adding Custom Tests

You can extend `TestMergedPcapLabels` with custom validation logic:

```python
class CustomPcapTests(TestMergedPcapLabels):
    
    def test_custom_validation(self):
        """Custom validation logic."""
        packets, labels_df, _ = self.load_test_data(
            "path/to/merged.pcap",
            "path/to/labels.csv"
        )
        
        # Your custom validation logic here
        # Use self.assertEqual(), self.assertTrue(), etc.
```

## Contributing

When adding new validation tests:

1. Follow the existing test structure
2. Add docstrings explaining what the test validates
3. Include example usage in the docstring
4. Update this README with new test descriptions

## License

Part of the AAU Network Augmentation project.
