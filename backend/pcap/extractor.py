"""
pcap/extractor.py
Extract HTTP requests, URLs, and IP pairs from a PCAP file using Scapy.

Security invariants:
  - Scapy runs in read-only mode (rdpcap/sniff with offline=True).
  - No packet content is executed, eval'd, or passed to a shell.
  - URL extraction uses regex + urlparse — no exec, no subprocess.
  - Maximum packets processed is capped to prevent DoS via giant captures.
  - All extracted URLs are validated by the central URL validator before analysis.
  - Extracted strings are truncated to safe lengths before storing.
  - No DNS resolution is performed (no outbound network calls).

Output schema per record:
  {
    "source_ip":      str,
    "destination_ip": str,
    "port":           int,
    "method":         str,
    "host":           str,
    "url":            str,       # full reconstructed URL
    "user_agent":     str,
    "timestamp":      float,     # Unix epoch from packet
  }
"""

from __future__ import annotations

import logging
import re
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Hard caps — protect against adversarially crafted captures
MAX_PACKETS     = 100_000   # max packets to read from file
MAX_URL_LENGTH  = 2048
MAX_HOST_LENGTH = 253
MAX_UA_LENGTH   = 512

# HTTP methods we extract (allowlist)
HTTP_METHODS = {b'GET', b'POST', b'PUT', b'DELETE', b'PATCH', b'HEAD', b'OPTIONS'}

# Regex to detect HTTP request line at the start of a TCP payload
_HTTP_REQUEST_RE = re.compile(
    rb'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/[\d.]+\r?\n',
    re.IGNORECASE,
)
_HOST_RE       = re.compile(rb'Host:\s*([^\r\n]+)', re.IGNORECASE)
_UA_RE         = re.compile(rb'User-Agent:\s*([^\r\n]+)', re.IGNORECASE)


def extract_records(pcap_path: str) -> tuple[list[dict], dict]:
    """
    Parse a validated PCAP file and extract HTTP request records.

    Parameters
    ----------
    pcap_path : Absolute path to a validated PCAP/PCAPng file.

    Returns
    -------
    records   : list of HTTP request dicts (see module docstring)
    stats     : dict with packets_seen, http_found, urls_extracted, unique_ips
    """
    # Import Scapy lazily — it's slow to import and has deprecation warnings
    try:
        from scapy.all import rdpcap, TCP, IP, IPv6
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
    except ImportError:
        raise RuntimeError(
            "Scapy is not installed. Run: pip install scapy"
        )

    records: list[dict] = []
    unique_ips: set[str] = set()
    packets_seen  = 0
    http_found    = 0
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            packets = rdpcap(str(pcap_path), count=MAX_PACKETS)
        except Exception as e:
            raise RuntimeError(f"Scapy could not read PCAP: {e}")

    for pkt in packets:
        packets_seen += 1

        # Only process TCP packets with an IP layer
        if not (pkt.haslayer(TCP) and (pkt.haslayer(IP) or pkt.haslayer(IPv6))):
            continue

        try:
            tcp = pkt[TCP]
            payload = bytes(tcp.payload)
            if not payload:
                continue

            # Quick pre-filter: must start with an HTTP method
            first_word = payload[:8].split(b' ')[0]
            if first_word not in HTTP_METHODS:
                continue

            match = _HTTP_REQUEST_RE.match(payload)
            if not match:
                continue

            http_found += 1
            method  = match.group(1).decode('ascii', errors='replace')
            path    = match.group(2).decode('ascii', errors='replace')[:MAX_URL_LENGTH]

            # Extract Host header
            host_m  = _HOST_RE.search(payload)
            host    = (host_m.group(1).decode('ascii', errors='replace').strip()
                       if host_m else '')[:MAX_HOST_LENGTH]

            # Extract User-Agent (stored truncated — never logged)
            ua_m    = _UA_RE.search(payload)
            ua      = (ua_m.group(1).decode('ascii', errors='replace').strip()
                       if ua_m else '')[:MAX_UA_LENGTH]

            # Reconstruct full URL
            scheme  = 'https' if tcp.dport == 443 else 'http'
            if host:
                full_url = f"{scheme}://{host}{path}"
            else:
                full_url = path  # bare path — validator will handle

            # Truncate to safe length
            full_url = full_url[:MAX_URL_LENGTH]

            # IP extraction
            if pkt.haslayer(IP):
                src_ip  = str(pkt[IP].src)
                dst_ip  = str(pkt[IP].dst)
            else:
                src_ip  = str(pkt[IPv6].src)
                dst_ip  = str(pkt[IPv6].dst)

            unique_ips.add(src_ip)
            unique_ips.add(dst_ip)

            records.append({
                'source_ip':      src_ip,
                'destination_ip': dst_ip,
                'port':           int(tcp.dport),
                'method':         method,
                'host':           host,
                'url':            full_url,
                'user_agent':     ua,
                'timestamp':      float(pkt.time),
            })

        except Exception as e:
            # Log and skip malformed packets — never fail the whole parse
            logger.debug("Skipping malformed packet: %s", type(e).__name__)
            continue

    stats = {
        'packets_seen':   packets_seen,
        'http_found':     http_found,
        'urls_extracted': len(records),
        'unique_ips':     len(unique_ips),
    }
    logger.info(
        "PCAP extraction: %d packets -> %d HTTP requests, %d unique IPs",
        packets_seen, http_found, len(unique_ips),
    )
    return records, stats
