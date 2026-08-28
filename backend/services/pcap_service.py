"""
services/pcap_service.py
PCAP module interface.

Phase 1: Synthetic data generation has been removed.
Phase 7: This stub will be replaced with real Scapy-based PCAP parsing
         using the pcap/ module (pcap.processor.process_pcap).

Public interface: process_pcap(file_path: str) -> list[dict]
"""

import os


def process_pcap(file_path: str) -> list[dict]:
    """
    Parse a PCAP file and return normalized HTTP records.

    Phase 1 stub: Validates the file and returns an empty record list.
    Real PCAP parsing (using the pcap/ Scapy module) will be integrated
    in Phase 7.

    Parameters
    ----------
    file_path : str
        Absolute path to the uploaded PCAP file.

    Returns
    -------
    list[dict]
        Empty list until Phase 7 integration is complete.

    Raises
    ------
    FileNotFoundError
        If the PCAP file does not exist at the given path.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"PCAP file not found: {file_path}")

    # Phase 7 will replace this return with:
    #   from pcap.processor import process_pcap as _real_process
    #   result = _real_process(file_path)
    #   return result["records"]
    return []
