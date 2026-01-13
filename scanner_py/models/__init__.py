"""Data models for the scanner package."""

from .scan_result import (
    ScanResult,
    CVEDetails,
    ImageMetadata,
    AttestationType,
    ScanSummary,
    CVESeverity,
)

__all__ = [
    "ScanResult",
    "CVEDetails",
    "ImageMetadata",
    "AttestationType",
    "ScanSummary",
    "CVESeverity",
]

