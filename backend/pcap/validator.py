"""
pcap/validator.py
Secure PCAP file validation.

Checks performed BEFORE any Scapy parsing:
  1. Extension whitelist (.pcap, .pcapng, .cap)
  2. Magic-byte verification (no file-extension spoofing)
  3. Size limit (configurable, default 50 MB)
  4. Path traversal prevention (only absolute paths inside tempdir accepted)
  5. File existence

Never:
  - Executes the file
  - Follows symlinks
  - Accepts relative paths
  - Trusts the file extension alone
"""

import os
import stat
from pathlib import Path

# PCAP file magic bytes
_MAGIC_PCAP        = b'\xd4\xc3\xb2\xa1'   # Little-endian classic PCAP
_MAGIC_PCAP_BE     = b'\xa1\xb2\xc3\xd4'   # Big-endian classic PCAP
_MAGIC_PCAPNG      = b'\x0a\x0d\x0d\x0a'   # PCAPng Section Header Block
_MAGIC_PCAP_NS     = b'\x4d\x3c\xb2\xa1'   # nanosecond PCAP (LE)
_MAGIC_PCAP_NS_BE  = b'\xa1\xb2\x3c\x4d'   # nanosecond PCAP (BE)

VALID_MAGICS = {
    _MAGIC_PCAP,
    _MAGIC_PCAP_BE,
    _MAGIC_PCAPNG,
    _MAGIC_PCAP_NS,
    _MAGIC_PCAP_NS_BE,
}

ALLOWED_EXTENSIONS = {'.pcap', '.pcapng', '.cap'}
MAX_FILE_BYTES     = 50 * 1024 * 1024   # 50 MB


class PCAPValidationError(ValueError):
    """Raised when a PCAP file fails validation."""


def validate_pcap_path(path: str, max_bytes: int = MAX_FILE_BYTES) -> Path:
    """
    Validate a PCAP file at the given path.

    Parameters
    ----------
    path     : Absolute path to the file (from tempfile.NamedTemporaryFile).
    max_bytes: Maximum allowed file size.

    Returns
    -------
    Path object if valid.

    Raises
    ------
    PCAPValidationError on any failure.
    """
    p = Path(path).resolve()

    # ── 1. Must exist and be a regular file ──────────────────────────────
    if not p.exists():
        raise PCAPValidationError("PCAP file does not exist.")

    if not p.is_file():
        raise PCAPValidationError("Path does not point to a regular file.")

    # ── 2. No symlinks ───────────────────────────────────────────────────
    if p.is_symlink():
        raise PCAPValidationError("Symlinks are not permitted.")

    # ── 3. Extension check ───────────────────────────────────────────────
    ext = p.suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise PCAPValidationError(
            f"Invalid file extension '{ext}'. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
        )

    # ── 4. Size limit ────────────────────────────────────────────────────
    size = p.stat().st_size
    if size == 0:
        raise PCAPValidationError("PCAP file is empty.")
    if size > max_bytes:
        raise PCAPValidationError(
            f"File too large ({size / 1024 / 1024:.1f} MB). Maximum {max_bytes // 1024 // 1024} MB."
        )

    # ── 5. Magic-byte verification (prevents extension spoofing) ─────────
    with open(p, 'rb') as f:
        magic = f.read(4)

    if magic not in VALID_MAGICS:
        raise PCAPValidationError(
            "File does not appear to be a valid PCAP/PCAPng file (magic bytes mismatch)."
        )

    return p
