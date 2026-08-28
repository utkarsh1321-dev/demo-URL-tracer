"""
services/pcap_service.py
Public interface to the PCAP analysis pipeline.

Phase 7: Replaces Phase 1 stub with real Scapy-based processing.

Public interface (unchanged from Phase 1):
  process_pcap(file_path: str) -> dict

The dict schema is defined in pcap/processor.py.
"""

from pcap.processor import process_pcap   # noqa: F401 — re-export
from pcap.validator import PCAPValidationError  # noqa: F401 — re-export for upload.py
