"""
analysis/__init__.py
Public API for the URL analysis engine.

Usage:
    from analysis.engine import analyze_url
    result = analyze_url("https://suspicious-paypal.xyz/login")
"""

from analysis.engine import analyze_url, URLAnalysisResult

__all__ = ["analyze_url", "URLAnalysisResult"]
