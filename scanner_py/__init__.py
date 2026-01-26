"""
Aleph Alpha - Image Scanner Package

A Python implementation of the Cosign-based container image scanning tools.
Provides functionality for:
- Kubernetes namespace image scanning
- SBOM extraction and vulnerability scanning
- Cosign signature verification
- Chainguard base image verification
"""

__version__ = "1.0.0"
__author__ = "Aleph Alpha"

from .core.scanner import ImageScanner
from .core.verification import CosignVerifier
from .core.attestation import AttestationExtractor
from .core.chainguard import ChainguardVerifier

__all__ = [
    "ImageScanner",
    "CosignVerifier",
    "AttestationExtractor",
    "ChainguardVerifier",
]
