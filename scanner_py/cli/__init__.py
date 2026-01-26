"""CLI entry points for the scanner package."""

import sys
import argparse
from typing import List, Optional

from .k8s_scanner import create_k8s_scanner_parser, run_cosign_scanner
from .cosign_scan import create_scan_image_parser, run_scan_image
from .verify_image import create_verify_parser, run_verify
from .extract import create_extract_parser, run_extract
from .verify_chainguard import create_chainguard_parser, run_chainguard
from .generate_report import create_generate_report_parser, run_generate_report
from .oras_scan import create_oras_scan_parser, run_oras_scan


def create_main_parser() -> argparse.ArgumentParser:
    """Create the main argument parser."""
    parser = argparse.ArgumentParser(
        prog="scanner-py",
        description="Aleph Alpha - Container Image Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  cosign-scan          Scan images with signature verification and SBOM attestations
  oras-scan       Simple scan with triage.toml support (no signature verification)
  scan-image        Scan a single container image
  verify            Verify image signature with cosign
  extract           Extract attestations from an image
  verify-chainguard Check if image uses Chainguard base image
  generate-report   Generate reports from existing scan results

Examples:
  # Simple triage scan (direct Trivy scan, triage.toml support)
  scanner-py oras-scan --namespace production -o report.md

  # Triage scan with filters
  scanner-py oras-scan -n prod --filter-unaddressed --filter-missing-triage

  # Full scan with signature verification (SBOM-based)
  scanner-py cosign-scan --namespace production

  # Generate report from existing scan results
  scanner-py generate-report --input-dir ./scan-results -o report.md

  # Scan a single image
  scanner-py scan-image --image registry.io/app:v1.0

  # Verify image signature
  scanner-py verify --image registry.io/app:v1.0

  # Extract SBOM attestation
  scanner-py extract --image registry.io/app:v1.0 --type cyclonedx
""",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Add subparsers for each command
    create_k8s_scanner_parser(subparsers)
    create_oras_scan_parser(subparsers)
    create_scan_image_parser(subparsers)
    create_verify_parser(subparsers)
    create_extract_parser(subparsers)
    create_chainguard_parser(subparsers)
    create_generate_report_parser(subparsers)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """
    Main entry point for the CLI.

    Args:
        argv: Command line arguments (defaults to sys.argv[1:])

    Returns:
        Exit code
    """
    parser = create_main_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    # Route to appropriate command handler
    command_handlers = {
        "cosign-scan": run_cosign_scanner,
        "oras-scan": run_oras_scan,
        "scan-image": run_scan_image,
        "verify": run_verify,
        "extract": run_extract,
        "verify-chainguard": run_chainguard,
        "generate-report": run_generate_report,
    }

    handler = command_handlers.get(args.command)
    if handler:
        try:
            return handler(args)
        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user", file=sys.stderr)
            return 130
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
    else:
        parser.print_help()
        return 1


__all__ = ["main", "create_main_parser"]
