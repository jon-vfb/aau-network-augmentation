import os, sys, argparse, statistics, struct
from datetime import datetime
from typing import List, Dict, Tuple, Union, Optional

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

try:
    from src.classes.pcapparser import pcapparser
except ImportError:
    from classes.pcapparser import pcapparser

def _extract_timestamps(packets) -> List[Tuple[int, float]]:
    return [(i, float(pkt.time)) for i, pkt in enumerate(packets) if hasattr(pkt, "time")]

def _load_packets(source: Union[str, "pcapparser", List]) -> List:
    if isinstance(source, str):
        return pcapparser(source).get_packets()          
    if isinstance(source, pcapparser):
        return source.get_packets()
    return list(source)

def validate_pcap_magic(path: str) -> Dict:
    try:
        with open(path, "rb") as fh:
            hdr = fh.read(4)
    except Exception as e:
        return {"ok": False, "reason": f"cannot open file: {e}"}

    magic_map = {
        b"\xd4\xc3\xb2\xa1": "pcap (microsecond, little-endian)",
        b"\xa1\xb2\xc3\xd4": "pcap (microsecond, big-endian)",
        b"\x4d\x3c\xb2\xa1": "pcap (nanosecond, little-endian)",
        b"\xa1\xb2\x3c\x4d": "pcap (nanosecond, big-endian)",
        b"\x0a\x0d\x0d\x0a": "pcapng",
    }

    t = magic_map.get(hdr)
    if t:
        return {"ok": True, "type": t, "magic": hdr.hex()}
    else:
        return {"ok": False, "reason": "unknown or unsupported magic", "magic": hdr.hex()}

def validate_pcap_snaplen(source: Union[str, pcapparser, List]) -> Dict:
    try:
        packets = _load_packets(source)
    except Exception as e:
        return {"ok": False, "reason": f"failed to load packets: {e}"}
    
    # Extract snaplen from global header if source is a file path
    snaplen = None
    if isinstance(source, str):
        try:
            with open(source, "rb") as fh:
                # Read first 4 bytes (magic), then skip to snaplen at offset 16
                magic = fh.read(4)
                fh.seek(16)
                snaplen_bytes = fh.read(4)
                # Check endianness from magic
                if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
                    # little-endian
                    snaplen = struct.unpack("<I", snaplen_bytes)[0]
                elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                    # big-endian
                    snaplen = struct.unpack(">I", snaplen_bytes)[0]
        except Exception as e:
            return {"ok": False, "reason": f"failed to read snaplen: {e}"}
    
    if snaplen is None:
        return {"ok": False, "reason": "could not determine snaplen"}
    
    max_packet_size = 0
    for pkt in packets:
        try:
            pkt_len = len(pkt)
            max_packet_size = max(max_packet_size, pkt_len)
        except:
            pass
    
    exceeds = max_packet_size > snaplen
    
    result = {
        "ok": not exceeds,
        "snaplen": snaplen,
        "max_packet_size": max_packet_size,
        "exceeds": exceeds,
    }
    
    if exceeds:
        result["reason"] = f"max packet size ({max_packet_size}) exceeds snaplen ({snaplen})"
    
    return result


def validate_pcap_packet_headers(path: str) -> Dict:
    errors = []
    packet_num = 0
    
    try:
        file_size = os.path.getsize(path)
        with open(path, "rb") as f:
            # Read magic to determine endianness
            magic = f.read(4)
            if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
                endian = "<"  # little-endian
            elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                endian = ">"  # big-endian
            else:
                return {"ok": False, "reason": "unknown magic, cannot parse headers"}
            
            # Read snaplen from global header (offset 16, 4 bytes)
            f.seek(16)
            snaplen = struct.unpack(f"{endian}I", f.read(4))[0]
            
            # Skip rest of global header (24 bytes total)
            f.seek(24)
            
            # Read packet headers sequentially
            while f.tell() < file_size:
                packet_num += 1
                start_pos = f.tell()
                
                # Read 16-byte packet header
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    if len(pkt_hdr) > 0:
                        errors.append({
                            "packet_num": packet_num,
                            "issue": "incomplete_header",
                            "details": f"only {len(pkt_hdr)} bytes available, need 16"
                        })
                    break
                
                # Parse packet header fields
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkt_hdr)
                
                # Validation 1: incl_len should not exceed orig_len
                if incl_len > orig_len:
                    errors.append({
                        "packet_num": packet_num,
                        "issue": "incl_len_exceeds_orig_len",
                        "details": f"incl_len={incl_len}, orig_len={orig_len}"
                    })
                
                # Validation 2: incl_len should not exceed snaplen
                if incl_len > snaplen:
                    errors.append({
                        "packet_num": packet_num,
                        "issue": "incl_len_exceeds_snaplen",
                        "details": f"incl_len={incl_len}, snapleincomplete_headern={snaplen}"
                    })
                
                # Validation 3: enough bytes should remain for packet data
                bytes_remaining = file_size - f.tell()
                if incl_len > bytes_remaining:
                    errors.append({
                        "packet_num": packet_num,
                        "issue": "truncated_packet_data",
                        "details": f"need {incl_len} bytes, only {bytes_remaining} remain"
                    })
                    break  # Can't continue, file is truncated
                
                # Validation 4: check for unreasonably large packets (likely corruption)
                if incl_len > 65535:
                    errors.append({
                        "packet_num": packet_num,
                        "issue": "unreasonably_large_packet",
                        "details": f"incl_len={incl_len} exceeds 65535 bytes"
                    })
                
                # Skip packet data
                f.seek(incl_len, 1)
    
    except Exception as e:
        return {"ok": False, "reason": f"error reading file: {e}"}
    
    return {
        "ok": len(errors) == 0,
        "total_packets": packet_num,
        "errors": errors
    }

def validate_pcap_timestamps(source: Union[str, pcapparser, List],
                              max_consecutive_gap_seconds: float = 3600.0,
                              max_deviation_from_median_seconds: float = 14400.0,
                              max_consecutive_gap_microseconds: Optional[float] = None,
                              max_deviation_from_median_microseconds: Optional[float] = None
                              ) -> Dict:
    packets = _load_packets(source)
    timestamps = _extract_timestamps(packets)

    if not timestamps:
        return {"ok": False, "reason": "no packet timestamps found"}

    indices, ts_values = zip(*sorted(timestamps, key=lambda x: x[0]))
    min_ts, max_ts = min(ts_values), max(ts_values)
    span_seconds = max_ts - min_ts
    median_ts = statistics.median(ts_values)

    consec_thresh_sec = (
        max_consecutive_gap_microseconds / 1e6
        if max_consecutive_gap_microseconds is not None
        else max_consecutive_gap_seconds
    )

    dev_thresh_sec = (
        max_deviation_from_median_microseconds / 1e6
        if max_deviation_from_median_microseconds is not None
        else max_deviation_from_median_seconds
    )

    consecutive_gaps = [
        {
            "index_before": indices[i],
            "index_after": indices[i + 1],
            "gap_seconds": ts_values[i + 1] - ts_values[i],
        }
        for i in range(len(ts_values) - 1)
        if (ts_values[i + 1] - ts_values[i]) > consec_thresh_sec
    ]

    outliers = [
        {"index": i, "ts": ts, "delta_seconds": abs(ts - median_ts)}
        for i, ts in zip(indices, ts_values)
        if abs(ts - median_ts) > dev_thresh_sec
    ]

    result = {
        "ok": not (consecutive_gaps or outliers),
        "summary": {
            "total_timestamps": len(ts_values),
            "min_ts": min_ts,
            "max_ts": max_ts,
            "span_seconds": span_seconds,
        },
        "consecutive_gaps": consecutive_gaps,
        "outliers": outliers,
    }
    return result

def _print_result(res: Dict) -> None:
    print("Validation result:")
    print(f"  ok: {res.get('ok')}")
    if "reason" in res:
        print(f"  reason: {res['reason']}")

    summary = res.get("summary", {})
    if summary:
        print(f"  timestamps: {summary.get('total_timestamps')} packets")
        print(f"  min_ts: {datetime.fromtimestamp(summary['min_ts'])}")
        print(f"  max_ts: {datetime.fromtimestamp(summary['max_ts'])}")
    span = summary["span_seconds"]
    print(f"  span: {span:.6f} seconds ({span*1e6:.0f}µs)")

    for gaps, label in [(res.get("consecutive_gaps"), "Consecutive large gaps detected"),
                        (res.get("outliers"), "Outlier packets (far from median)")]:
        if gaps:
            print(f"\n{label}:")
            for item in gaps:
                if "gap_seconds" in item:
                    gap = item["gap_seconds"]
                    print(f"  gap between packet {item['index_before']} -> {item['index_after']}: {gap:.6f}s ({gap*1e6:.0f}µs)")
                else:
                    delta = item["delta_seconds"]
                    print(f"  index {item['index']}: ts={datetime.fromtimestamp(item['ts'])}, delta={delta:.6f}s ({delta*1e6:.0f}µs)")

def _cli(argv=None):
    parser = argparse.ArgumentParser(description="Validate PCAP timestamps for large gaps/outliers")
    parser.add_argument("file", help="PCAP/PCAPNG file to validate")
    parser.add_argument("--max-gap-seconds", type=float, default=3600.0)
    parser.add_argument("--max-dev-seconds", type=float, default=14400.0)
    args = parser.parse_args(argv)

    # First validate the magic number
    magic_res = validate_pcap_magic(args.file)
    print("\nPCAP Magic Number Check:")
    print(f"  ok: {magic_res.get('ok')}")
    if magic_res.get('ok'):
        print(f"  type: {magic_res.get('type')}")
    else:
        print(f"  reason: {magic_res.get('reason')}")
    print(f"  magic: 0x{magic_res.get('magic', '')}")
    print()

    if not magic_res.get('ok'):
        sys.exit(2)

    # Check snaplen against actual packet sizes
    snaplen_res = validate_pcap_snaplen(args.file)
    print("PCAP Snaplen Check:")
    print(f"  snaplen: {snaplen_res.get('snaplen')} bytes")
    print(f"  max packet size: {snaplen_res.get('max_packet_size')} bytes")
    print(f"  ok: {snaplen_res.get('ok')}")
    if not snaplen_res.get('ok'):
        print(f"  reason: {snaplen_res.get('reason')}")
    print()

    if not snaplen_res.get('ok'):
        sys.exit(2)

    # Check packet header integrity
    header_res = validate_pcap_packet_headers(args.file)
    print("PCAP Packet Header Integrity Check:")
    print(f"  total packets scanned: {header_res.get('total_packets')}")
    print(f"  ok: {header_res.get('ok')}")
    if not header_res.get('ok'):
        errors = header_res.get('errors', [])
        if errors:
            print(f"  errors found: {len(errors)}")
            # Show first few errors
            for err in errors[:5]:
                print(f"    packet {err['packet_num']}: {err['issue']} - {err['details']}")
            if len(errors) > 5:
                print(f"    ... and {len(errors) - 5} more errors")
        elif 'reason' in header_res:
            print(f"  reason: {header_res.get('reason')}")
    print()

    if not header_res.get('ok'):
        sys.exit(2)

    # Proceed with timestamp validation
    res = validate_pcap_timestamps(
        args.file,
        args.max_gap_seconds,
        args.max_dev_seconds
    )
    _print_result(res)
    if not res.get("ok"):
        sys.exit(2)

if __name__ == "__main__":
    _cli()