"""Vulnerability scanning module.

Equivalent to cosign-scan-image.sh and the Trivy scanning parts of k8s-image-scanner.sh
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Dict, Any

from ..models.scan_result import (
    ScanResult,
    CVEDetails,
    CVESeverity,
    ImageMetadata,
    AttestationType,
)
from ..utils.subprocess import run_command
from ..utils.logging import get_logger, is_verbose
from .attestation import AttestationExtractor, AttestationTypeEnum
from .verification import CosignVerifier
from .cache import get_digest_cache

logger = get_logger(__name__)


@dataclass
class SeverityConfig:
    """Configuration for severity filtering."""
    level: str = "HIGH"

    @property
    def trivy_filter(self) -> str:
        """Get Trivy severity filter string."""
        level_map = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH,CRITICAL",
            "MEDIUM": "MEDIUM,HIGH,CRITICAL",
            "LOW": "LOW,MEDIUM,HIGH,CRITICAL",
        }
        return level_map.get(self.level.upper(), "HIGH,CRITICAL")


class TrivyScanner:
    """Trivy vulnerability scanner for SBOMs."""

    def __init__(
        self,
        config_file: Optional[str] = None,
        timeout: int = 300,
        verbose: bool = False,
    ):
        """
        Initialize scanner.

        Args:
            config_file: Path to Trivy config file
            timeout: Timeout for scan operations
            verbose: Whether to show verbose output
        """
        self.config_file = config_file
        self.timeout = timeout
        self.verbose = verbose

    def scan_sbom(
        self,
        sbom_file: str,
        output_file: str,
        format: str = "table",
        severity: str = "HIGH,CRITICAL",
        ignore_file: Optional[str] = None,
    ) -> bool:
        """
        Scan an SBOM file for vulnerabilities.

        Args:
            sbom_file: Path to SBOM file
            output_file: Path for output report
            format: Output format (table, json, sarif)
            severity: Severity filter
            ignore_file: Path to trivyignore file

        Returns:
            True if scan completed successfully
        """
        args = [
            "trivy",
            "sbom",
            "--format", format,
            "--severity", severity,
            "--output", output_file,
        ]

        # Only suppress output when not in verbose mode
        if not self.verbose:
            args.insert(2, "--quiet")

        if ignore_file and Path(ignore_file).exists():
            args.extend(["--ignorefile", ignore_file])

        if self.config_file and Path(self.config_file).exists():
            args.extend(["--config", self.config_file])

        args.extend(["--timeout", f"{self.timeout}s"])
        args.append(sbom_file)

        logger.debug(f"Running Trivy: {' '.join(args)}")

        result = run_command(args, timeout=self.timeout + 30)

        if result.success:
            logger.debug("Trivy scan completed successfully")
            return True
        else:
            # Only show error in verbose mode
            if is_verbose():
                logger.error(f"Trivy scan failed: {result.stderr}")
            else:
                logger.debug(f"Trivy scan failed: {result.stderr}")
            return False

    def parse_json_report(self, report_file: str) -> Dict[str, Any]:
        """
        Parse a Trivy JSON report.

        Args:
            report_file: Path to JSON report

        Returns:
            Parsed report data
        """
        try:
            with open(report_file) as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            if is_verbose():
                logger.error(f"Failed to parse report: {e}")
            return {}

    def count_vulnerabilities(
        self, report_file: str
    ) -> Dict[str, int]:
        """
        Count vulnerabilities by severity.

        Args:
            report_file: Path to JSON report

        Returns:
            Dictionary with counts by severity
        """
        report = self.parse_json_report(report_file)
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        results = report.get("Results", [])
        for result in results:
            vulns = result.get("Vulnerabilities", [])
            for vuln in vulns:
                severity = vuln.get("Severity", "").upper()
                if severity in counts:
                    counts[severity] += 1

        return counts

    def extract_cve_details(self, report_file: str) -> List[CVEDetails]:
        """
        Extract CVE details from report.

        Args:
            report_file: Path to JSON report

        Returns:
            List of CVE details
        """
        report = self.parse_json_report(report_file)
        cves = []

        results = report.get("Results", [])
        for result in results:
            vulns = result.get("Vulnerabilities", [])
            for vuln in vulns:
                cves.append(CVEDetails(
                    cve_id=vuln.get("VulnerabilityID", ""),
                    severity=CVESeverity.from_string(vuln.get("Severity", "")),
                    package=vuln.get("PkgName", ""),
                    installed_version=vuln.get("InstalledVersion", ""),
                    fixed_version=vuln.get("FixedVersion"),
                    title=vuln.get("Title"),
                    description=vuln.get("Description"),
                ))

        return cves


class ImageScanner:
    """
    Complete image scanner combining attestation extraction and Trivy scanning.
    
    Main scanning logic equivalent to cosign-scan-image.sh
    """

    def __init__(
        self,
        output_dir: str = "./scan-results",
        format: str = "table",
        severity_level: str = "HIGH",
        min_cve_level: str = "HIGH",
        sbom_type: str = "cyclonedx",
        no_triage: bool = False,
        timeout: int = 300,
        certificate_oidc_issuer: Optional[str] = None,
        certificate_identity_regexp: Optional[str] = None,
        trivy_config: Optional[str] = None,
        verbose: bool = False,
    ):
        """
        Initialize scanner.

        Args:
            output_dir: Directory for scan outputs
            format: Report format (table, json, sarif)
            severity_level: Minimum severity level
            min_cve_level: Minimum CVE level to consider relevant
            sbom_type: SBOM type (cyclonedx or spdx)
            no_triage: Skip triage filtering
            timeout: Timeout for operations
            certificate_oidc_issuer: OIDC issuer for verification
            certificate_identity_regexp: Identity regexp for verification
            trivy_config: Path to Trivy config file
            verbose: Whether to show verbose output
        """
        self.output_dir = Path(output_dir)
        self.format = format
        self.severity_config = SeverityConfig(level=severity_level)
        self.min_cve_level = min_cve_level
        self.sbom_type = sbom_type
        self.no_triage = no_triage
        self.timeout = timeout
        self.verbose = verbose

        # Initialize components
        self.verifier = CosignVerifier(
            certificate_oidc_issuer=(
                certificate_oidc_issuer or CosignVerifier.DEFAULT_OIDC_ISSUER
            ),
            certificate_identity_regexp=(
                certificate_identity_regexp or CosignVerifier.DEFAULT_IDENTITY_REGEXP
            ),
            timeout=timeout,
        )
        self.extractor = AttestationExtractor(
            certificate_oidc_issuer=(
                certificate_oidc_issuer or AttestationExtractor.DEFAULT_OIDC_ISSUER
            ),
            certificate_identity_regexp=(
                certificate_identity_regexp
                or AttestationExtractor.DEFAULT_IDENTITY_REGEXP
            ),
            timeout=timeout,
        )
        self.trivy = TrivyScanner(config_file=trivy_config, timeout=timeout, verbose=verbose)

    def _sanitize_image_name(self, image: str) -> str:
        """Convert image name to safe directory name."""
        return re.sub(r"[^A-Za-z0-9._-]", "_", image)

    def detect_attestation_type(self, image: str) -> AttestationType:
        """
        Detect what attestations are available for an image.

        Optimized to cache attestation info and avoid redundant network calls.

        Args:
            image: Image reference

        Returns:
            AttestationType enum value
        """
        # Pre-warm digest cache to avoid multiple lookups
        digest = get_digest_cache().get_or_fetch(image)
        if not digest:
            logger.debug(f"Failed to resolve digest for {image}")
            return AttestationType.UNSIGNED

        # First verify the image is signed
        verification = self.verifier.verify(image)
        if not verification.success:
            logger.debug(f"Image is not signed: {image}")
            return AttestationType.UNSIGNED

        # List available attestations (already uses cached digest)
        attestations = self.extractor.list_attestations(image)

        has_sbom = attestations.has_sbom()
        has_triage = attestations.has_triage()

        if has_sbom and has_triage:
            return AttestationType.COSIGN_SBOM_TRIAGE
        elif has_sbom:
            return AttestationType.COSIGN_SBOM
        else:
            return AttestationType.COSIGN_NO_SBOM

    def _convert_triage_to_trivyignore(
        self, triage_file: str, output_file: str
    ) -> bool:
        """
        Convert triage attestation to trivyignore format.

        Args:
            triage_file: Path to triage JSON file
            output_file: Path for trivyignore output

        Returns:
            True if successful
        """
        try:
            with open(triage_file) as f:
                triage = json.load(f)

            # Extract CVE IDs from triage
            # Format: {"predicate": {"trivy": {"CVE-ID": {...}, ...}}}
            trivy_data = triage.get("predicate", {}).get("trivy", {})
            cve_ids = list(trivy_data.keys())

            if not cve_ids:
                logger.debug("No CVEs found in triage file")
                return False

            with open(output_file, "w") as f:
                for cve_id in cve_ids:
                    f.write(f"{cve_id}\n")

            logger.debug(f"Created trivyignore with {len(cve_ids)} CVEs")
            return True

        except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
            if is_verbose():
                logger.error(f"Failed to convert triage: {e}")
            return False

    def scan(self, image: str, dry_run: bool = False) -> ScanResult:
        """
        Scan a single image.

        Args:
            image: Image reference
            dry_run: Only show what would be done

        Returns:
            ScanResult with scan details
        """
        logger.debug(f"Scanning image: {image}")

        # Create output directory
        image_safe = self._sanitize_image_name(image)
        image_dir = self.output_dir / image_safe
        image_dir.mkdir(parents=True, exist_ok=True)

        result = ScanResult(image=image, success=False, output_dir=str(image_dir))

        if dry_run:
            logger.info(f"[DRY RUN] Would scan: {image}")
            result.success = True
            return result

        # Detect attestation type
        logger.debug("Verifying image signature")
        attestation_type = self.detect_attestation_type(image)
        logger.debug(f"Attestation type: {attestation_type.value}")

        # Handle based on attestation type
        if attestation_type == AttestationType.UNSIGNED:
            result.skipped = True
            result.skip_reason = "Image is not signed"
            return result

        if attestation_type == AttestationType.COSIGN_NO_SBOM:
            result.skipped = True
            result.skip_reason = "Image has no SBOM attestation"
            return result

        # Download SBOM
        logger.debug("Downloading SBOM attestation")
        sbom_file = image_dir / "sbom.json"
        if not self.extractor.extract_sbom(
            image, str(sbom_file), self.sbom_type
        ):
            result.error = "Failed to download SBOM"
            return result
        result.sbom_file = str(sbom_file)
        logger.debug("SBOM downloaded successfully")

        # Download triage if available
        triage_file = None
        trivyignore_file = None
        if (
            attestation_type == AttestationType.COSIGN_SBOM_TRIAGE
            and not self.no_triage
        ):
            logger.debug("Downloading triage attestation")
            triage_file = image_dir / "triage.json"
            if self.extractor.extract_triage(image, str(triage_file)):
                result.triage_file = str(triage_file)
                logger.debug("Triage downloaded successfully")

                # Convert to trivyignore
                trivyignore_file = image_dir / "triage.trivyignore"
                self._convert_triage_to_trivyignore(
                    str(triage_file), str(trivyignore_file)
                )

        # Run Trivy scan
        logger.debug("Running vulnerability scan")

        # Always generate JSON for analysis
        json_report = image_dir / "trivy-report.json"
        if not self.trivy.scan_sbom(
            str(sbom_file),
            str(json_report),
            format="json",
            severity=self.severity_config.trivy_filter,
            ignore_file=str(trivyignore_file) if trivyignore_file else None,
        ):
            result.error = "Trivy scan failed"
            return result

        # Generate requested format if not JSON
        if self.format != "json":
            report_file = image_dir / f"trivy-report.{self.format}"
            self.trivy.scan_sbom(
                str(sbom_file),
                str(report_file),
                format=self.format,
                severity=self.severity_config.trivy_filter,
                ignore_file=str(trivyignore_file) if trivyignore_file else None,
            )
            result.report_file = str(report_file)
        else:
            result.report_file = str(json_report)

        # Count vulnerabilities
        counts = self.trivy.count_vulnerabilities(str(json_report))
        result.critical_count = counts["CRITICAL"]
        result.high_count = counts["HIGH"]
        result.medium_count = counts["MEDIUM"]
        result.low_count = counts["LOW"]

        # Extract CVE details
        result.cve_details = self.trivy.extract_cve_details(str(json_report))

        # Count triaged CVEs
        if triage_file and triage_file.exists():
            try:
                with open(triage_file) as f:
                    triage = json.load(f)
                trivy_data = triage.get("predicate", {}).get("trivy", {})
                result.triaged_count = len(trivy_data)
            except (json.JSONDecodeError, FileNotFoundError):
                pass

        # Save metadata
        metadata = ImageMetadata(
            image=image,
            attestation_type=attestation_type,
            sbom_downloaded=True,
            sbom_type=self.sbom_type,
            triage_downloaded=triage_file is not None,
            scan_format=self.format,
            severity_filter=self.severity_config.trivy_filter,
        )
        result.metadata = metadata

        metadata_file = image_dir / "metadata.json"
        with open(metadata_file, "w") as f:
            f.write(metadata.to_json())

        # Save CVE details
        cve_details_file = image_dir / "cve_details.json"
        with open(cve_details_file, "w") as f:
            json.dump(result.to_dict(), f, indent=2)

        result.success = True
        logger.debug("Scan completed successfully")

        return result

    def print_summary(self, result: ScanResult) -> None:
        """
        Print scan summary to console.

        Args:
            result: Scan result to summarize
        """
        print()
        print("━" * 66)
        print("📊 SCAN SUMMARY")
        print("━" * 66)
        print()

        print(f"{'Image:':<20} {result.image}")
        print()

        if result.skipped:
            print(f"{'Status:':<20} ⏭️  Skipped - {result.skip_reason}")
            return

        if not result.success:
            print(f"{'Status:':<20} ❌ Failed")
            if self.verbose:
                print(f"{'Error:':<20} {result.error}")
            return

        # Signature status
        if result.metadata:
            at = result.metadata.attestation_type
            if at == AttestationType.COSIGN_SBOM_TRIAGE:
                print(f"{'Signature:':<20} ✅ Verified")
                print(f"{'SBOM:':<20} ✅ Downloaded")
                print(f"{'Triage:':<20} ✅ Applied")
            elif at == AttestationType.COSIGN_SBOM:
                print(f"{'Signature:':<20} ✅ Verified")
                print(f"{'SBOM:':<20} ✅ Downloaded")
                print(f"{'Triage:':<20} ⚠️  Not available")

        print(f"{'Scan Method:':<20} SBOM-based")
        print()

        # Vulnerability counts
        print("Vulnerabilities:")
        print(f"  🔴 Critical: {result.critical_count}")
        print(f"  🟠 High:     {result.high_count}")
        print(f"  🟡 Medium:   {result.medium_count}")
        print(f"  🟢 Low:      {result.low_count}")
        if result.triaged_count > 0:
            print(f"  📋 Triaged:  {result.triaged_count} (filtered out)")

        print()
        print(f"Output: {result.output_dir}")
        print()
        print("━" * 66)
