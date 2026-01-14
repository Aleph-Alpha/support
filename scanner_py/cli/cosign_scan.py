"""CLI for single image scanning.

Equivalent to cosign-scan-image.sh
"""

import argparse
import sys
from typing import Any

from ..core.scanner import ImageScanner
from ..utils.logging import setup_logging, LogLevel, is_verbose
from ..utils.subprocess import check_prerequisites
from ..utils.progress import Spinner


def create_scan_image_parser(subparsers: Any) -> argparse.ArgumentParser:
    """Create the scan-image subparser."""
    parser = subparsers.add_parser(
        "scan-image",
        help="Scan a single container image",
        description="""
Scan a single container image by downloading its SBOM attestation and
scanning it with Trivy. Automatically applies triage attestations to
filter out known and addressed vulnerabilities.

This scanner requires images to have SBOM attestations (CycloneDX or SPDX).
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a specific image (default: HIGH and CRITICAL)
  scanner-py scan-image --image harbor.example.com/library/myapp:v1.0.0

  # Scan with MEDIUM severity and above
  scanner-py scan-image --image myregistry.io/app:latest --severity MEDIUM

  # Scan with JSON output format
  scanner-py scan-image --image myimage:tag --format json --output-dir ./reports

  # Scan without triage filtering to see all CVEs
  scanner-py scan-image --image myimage:tag --no-triage

  # Dry run to see what would be scanned
  scanner-py scan-image --image harbor.example.com/prod/api:1.2.3 --dry-run
""",
    )

    parser.add_argument(
        "--image",
        required=True,
        help="Container image to scan",
    )
    parser.add_argument(
        "--output-dir",
        default="./scan-results",
        help="Output directory for reports (default: ./scan-results)",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default="table",
        help="Report format (default: table)",
    )
    parser.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="HIGH",
        help="Minimum severity level (default: HIGH)",
    )
    parser.add_argument(
        "--min-cve-level",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="HIGH",
        help="Minimum CVE level to consider relevant (default: HIGH)",
    )
    parser.add_argument(
        "--sbom-type",
        choices=["cyclonedx", "spdx"],
        default="cyclonedx",
        help="SBOM type to extract (default: cyclonedx)",
    )
    parser.add_argument(
        "--no-triage",
        action="store_true",
        help="Skip triage filtering and show all CVEs",
    )
    parser.add_argument(
        "--trivy-config",
        help="Custom Trivy configuration file",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Timeout for operations in seconds (default: 600)",
    )
    parser.add_argument(
        "--certificate-oidc-issuer",
        help="OIDC issuer for cosign verification",
    )
    parser.add_argument(
        "--certificate-identity-regexp",
        help="Identity regexp for cosign verification",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging (shows errors and debug info)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be scanned without executing",
    )
    parser.add_argument(
        "--show-cves",
        action="store_true",
        default=True,
        help="Display detailed CVE list (default: true)",
    )
    parser.add_argument(
        "--max-cves",
        type=int,
        default=20,
        help="Maximum CVEs to display (default: 20, 0 = all)",
    )

    return parser


def run_scan_image(args: argparse.Namespace) -> int:
    """
    Run single image scan.

    Args:
        args: Parsed command line arguments

    Returns:
        Exit code
    """
    # Setup logging - errors only shown in verbose mode
    log_level = LogLevel.VERBOSE if args.verbose else LogLevel.INFO
    setup_logging(log_level, show_errors=args.verbose)

    # Check prerequisites
    missing = check_prerequisites(["trivy", "jq", "cosign", "docker", "crane"])
    if missing:
        print(f"❌ Missing required tools: {', '.join(missing)}", file=sys.stderr)
        return 1

    # Print header
    print("━" * 66)
    print("🔍 Aleph Alpha - Single Image Scanner")
    print("━" * 66)
    print()

    print("⚙️  Configuration:")
    print(f"   • Image: {args.image}")
    print(f"   • Output: {args.output_dir}")
    print(f"   • Format: {args.format}")
    print(f"   • Severity: {args.severity} and above")
    if args.no_triage:
        print("   • Triage: DISABLED")
    if args.dry_run:
        print("   • Mode: DRY RUN")
    if args.verbose:
        print("   • Verbose: Enabled (showing errors)")
    print()

    # Create scanner
    scanner = ImageScanner(
        output_dir=args.output_dir,
        format=args.format,
        severity_level=args.severity,
        min_cve_level=args.min_cve_level,
        sbom_type=args.sbom_type,
        no_triage=args.no_triage,
        timeout=args.timeout,
        certificate_oidc_issuer=args.certificate_oidc_issuer,
        certificate_identity_regexp=args.certificate_identity_regexp,
        trivy_config=args.trivy_config,
        verbose=args.verbose,
    )

    # Run scan with spinner
    if not args.dry_run:
        spinner = Spinner("Verifying image signature...")
        spinner.spin()
        
        result = scanner.scan(args.image, dry_run=args.dry_run)
        
        if result.success:
            spinner.finish("Scan completed", success=True)
        elif result.skipped:
            spinner.finish(f"Skipped: {result.skip_reason}", success=True)
        else:
            spinner.finish("Scan failed", success=False)
    else:
        result = scanner.scan(args.image, dry_run=args.dry_run)
        print(f"[DRY RUN] Would scan: {args.image}")

    # Print summary
    if not args.dry_run:
        scanner.print_summary(result)

    # Return appropriate exit code
    if result.success:
        print()
        print("✅ Scan completed successfully")
        return 0
    elif result.skipped:
        print()
        print(f"⏭️  Scan skipped: {result.skip_reason}")
        return 0
    else:
        print()
        if is_verbose():
            print(f"❌ Scan failed: {result.error}")
        else:
            print("❌ Scan failed (use --verbose for details)")
        return 1
