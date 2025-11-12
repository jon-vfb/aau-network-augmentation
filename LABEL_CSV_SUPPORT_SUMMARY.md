# Label CSV Support for PCAP Merger - Summary

## What Changed

The `PcapMerger` class now accepts **optional** input label CSV files and generates corresponding **output** label CSV files that track packet transformations.

## Quick Start

```python
from src.features.merger.pcap_merger import PcapMerger

merger = PcapMerger(jitter_max=0.05)
merger.set_ip_translation_range("192.168.100.0/24")

# Merge with labels (all optional)
merger.merge_pcaps(
    left_pcap="benign.pcapng",
    right_pcap="malicious.pcapng",
    output_file="merged.pcapng",
    left_labels="benign_labels.csv",      # Optional
    right_labels="malicious_labels.csv",  # Optional
    output_labels="merged_labels.csv"     # Optional
)
```

## Output Label Features

The merged CSV contains:
- ✅ Original labels preserved from input files
- ✅ Updated **IP addresses** (reflects IP translation)
- ✅ Updated **timestamps** (remapped to benign timeline)
- ✅ **Source** column ("left" or "right")
- ✅ New sequential **index** for merged PCAP

## Example Output

```csv
index,label,timestamp,source_ip,destination_ip,source
0,benign,1759919617.35,0.0.0.0,255.255.255.255,left
1,benign,1759919620.93,192.168.137.1,192.168.137.45,left
2,malicious,1759919620.94,192.168.100.1,192.168.100.10,right
3,malicious,1759919620.95,192.168.100.2,192.168.100.20,right
```

## Key Points

1. **Labels are optional** - Full backward compatibility
2. **Simple format** - Works with standard CSV files
3. **Automatic transformation** - IPs and timestamps adjusted automatically
4. **Traceable** - Source column shows where each packet originated
5. **Complete** - All input columns preserved in output

## Methods Updated

### `load_pcaps()` 
Now accepts optional `left_labels` and `right_labels` parameters:
```python
merger.load_pcaps(
    left_pcap="benign.pcapng",
    right_pcap="malicious.pcapng",
    left_labels="optional_benign_labels.csv",
    right_labels="optional_malicious_labels.csv"
)
```

### `merge()`
Now accepts optional `output_labels_path` parameter:
```python
merger.merge(
    output_path="merged.pcapng",
    output_labels_path="optional_merged_labels.csv"
)
```

### `merge_pcaps()`
Convenience method combines load + merge with label support:
```python
merger.merge_pcaps(
    left_pcap="benign.pcapng",
    right_pcap="malicious.pcapng",
    output_file="merged.pcapng",
    left_labels="benign_labels.csv",
    right_labels="malicious_labels.csv",
    output_labels="merged_labels.csv"
)
```

## New Internal Methods

- **`_adjust_labels_for_merged_packets()`** - Main label transformation logic
- **`_packets_match()`** - Matches packets after transformations

## Files Modified

- `src/features/merger/pcap_merger.py` - Main implementation
- Created: `src/example/merge_with_labels_example.py` - Usage examples
- Created: `LABEL_MERGING_GUIDE.md` - Detailed documentation

## Dependencies

- `pandas` - For CSV handling (already used in project)
- All existing dependencies unchanged

## Backward Compatibility

✅ **100% backward compatible**
- Existing code works without changes
- Labels are completely optional
- If no labels provided, behaves exactly as before

## Testing Recommendation

```python
from src.features.labeler import Labeler
from src.features.merger.pcap_merger import PcapMerger

# Create labels for your PCAPs
labeler = Labeler()
labeler.label_and_export("benign.pcapng", "benign_labels.csv", "benign")
labeler.label_and_export("malicious.pcapng", "malicious_labels.csv", "malicious")

# Merge with labels
merger = PcapMerger()
merger.set_ip_translation_range("192.168.100.0/24")
merger.merge_pcaps(
    left_pcap="benign.pcapng",
    right_pcap="malicious.pcapng",
    output_file="merged.pcapng",
    left_labels="benign_labels.csv",
    right_labels="malicious_labels.csv",
    output_labels="merged_labels.csv"
)

# Verify output
import pandas as pd
df = pd.read_csv("merged_labels.csv")
print(f"Total packets: {len(df)}")
print(f"Benign: {len(df[df['source']=='left'])}")
print(f"Malicious: {len(df[df['source']=='right'])}")
```

---

For detailed documentation, see `LABEL_MERGING_GUIDE.md`
