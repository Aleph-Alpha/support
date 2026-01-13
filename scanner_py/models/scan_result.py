"""Data models for scan results."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
import json


class AttestationType(Enum):
    """Types of attestations found on an image."""
    COSIGN_SBOM_TRIAGE = "cosign-sbom-triage"
    COSIGN_SBOM = "cosign-sbom"
    COSIGN_NO_SBOM = "cosign-no-sbom"
    UNSIGNED = "unsigned"


class CVESeverity(Enum):
    """CVE severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_string(cls, value: str) -> "CVESeverity":
        """Convert string to CVESeverity."""
        try:
            return cls(value.upper())
        except ValueError:
            return cls.UNKNOWN

    def __lt__(self, other: "CVESeverity") -> bool:
        """Compare severity levels."""
        order = {
            CVESeverity.LOW: 1,
            CVESeverity.MEDIUM: 2,
            CVESeverity.HIGH: 3,
            CVESeverity.CRITICAL: 4,
            CVESeverity.UNKNOWN: 0,
        }
        return order[self] < order[other]


@dataclass
class CVEDetails:
    """Details about a single CVE."""
    cve_id: str
    severity: CVESeverity
    package: str
    installed_version: str
    fixed_version: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "cve_id": self.cve_id,
            "severity": self.severity.value,
            "package": self.package,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "title": self.title,
            "description": self.description,
        }


@dataclass
class ImageMetadata:
    """Metadata about a scanned image."""
    image: str
    attestation_type: AttestationType
    sbom_downloaded: bool = False
    sbom_type: str = "cyclonedx"
    triage_downloaded: bool = False
    scan_timestamp: datetime = field(default_factory=datetime.utcnow)
    scan_format: str = "table"
    severity_filter: str = "HIGH,CRITICAL"
    scan_method: str = "sbom"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "image": self.image,
            "attestation_type": self.attestation_type.value,
            "sbom_downloaded": self.sbom_downloaded,
            "sbom_type": self.sbom_type,
            "triage_downloaded": self.triage_downloaded,
            "scan_timestamp": self.scan_timestamp.isoformat() + "Z",
            "scan_format": self.scan_format,
            "severity_filter": self.severity_filter,
            "scan_method": self.scan_method,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class ScanResult:
    """Result of scanning a single image."""
    image: str
    success: bool
    skipped: bool = False
    skip_reason: Optional[str] = None
    error: Optional[str] = None
    metadata: Optional[ImageMetadata] = None
    
    # CVE counts
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    triaged_count: int = 0
    
    # CVE lists
    unaddressed_cves: List[str] = field(default_factory=list)
    addressed_cves: List[str] = field(default_factory=list)
    irrelevant_cves: List[str] = field(default_factory=list)
    cve_details: List[CVEDetails] = field(default_factory=list)
    
    # Chainguard info
    is_chainguard: bool = False
    base_image: str = "unknown"
    signature_verified: bool = False
    
    # File paths
    output_dir: Optional[str] = None
    sbom_file: Optional[str] = None
    triage_file: Optional[str] = None
    report_file: Optional[str] = None

    @property
    def total_cves(self) -> int:
        """Total number of CVEs found."""
        return self.critical_count + self.high_count + self.medium_count + self.low_count

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "image": self.image,
            "success": self.success,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
            "error": self.error,
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "triaged": self.triaged_count,
            "unaddressed_cves": self.unaddressed_cves,
            "addressed_cves": self.addressed_cves,
            "irrelevant_cves": self.irrelevant_cves,
            "is_chainguard": self.is_chainguard,
            "base_image": self.base_image,
            "signature_verified": self.signature_verified,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class ScanSummary:
    """Summary of a complete scan run."""
    namespace: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    total_images_found: int = 0
    images_skipped: int = 0
    images_processed: int = 0
    successful_scans: int = 0
    failed_scans: int = 0
    skipped_scans: int = 0
    format: str = "table"
    severity_filter: str = "HIGH,CRITICAL"
    
    # Results
    successful_images: List[str] = field(default_factory=list)
    failed_images: List[Dict[str, str]] = field(default_factory=list)
    skipped_images: List[str] = field(default_factory=list)
    cve_analysis: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scan_summary": {
                "timestamp": self.timestamp.isoformat() + "Z",
                "namespace": self.namespace,
                "total_images_found": self.total_images_found,
                "images_skipped": self.images_skipped,
                "images_processed": self.images_processed,
                "successful_scans": self.successful_scans,
                "failed_scans": self.failed_scans,
                "skipped_scans": self.skipped_scans,
                "format": self.format,
                "severity_filter": self.severity_filter,
            },
            "successful_scans": self.successful_images,
            "failed_scans": self.failed_images,
            "skipped_scans": self.skipped_images,
            "cve_analysis": self.cve_analysis,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    def save(self, filepath: str) -> None:
        """Save summary to file."""
        with open(filepath, "w") as f:
            f.write(self.to_json())

