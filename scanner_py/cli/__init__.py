"""CLI entry points for the scanner package."""

import sys
import argparse
from typing import List, Optional

from .k8s_scanner import create_k8s_scanner_parser, run_k8s_scanner
from .scan_image import create_scan_image_parser, run_scan_image
from .verify_image import create_verify_parser, run_verify
from .extract import create_extract_parser, run_extract
from .verify_chainguard import create_chainguard_parser, run_chainguard


def create_main_parser() -> argparse.ArgumentParser:
    """Create the main argument parser."""
    parser = argparse.ArgumentParser(
        prog="scanner-py",
        description="Aleph Alpha - Container Image Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  k8s-scan          Scan images from a Kubernetes namespace
  scan-image        Scan a single container image
  verify            Verify image signature with cosign
  extract           Extract attestations from an image
  verify-chainguard Check if image uses Chainguard base image

Examples:
  # Scan all images in a Kubernetes namespace
  scanner-py k8s-scan --namespace production

  # Scan a single image
  scanner-py scan-image --image registry.io/app:v1.0

  # Verify image signature
  scanner-py verify --image registry.io/app:v1.0

  # Extract SBOM attestation
  scanner-py extract --image registry.io/app:v1.0 --type cyclonedx

  # Check Chainguard base image
  scanner-py verify-chainguard --image registry.io/app:v1.0
""",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Add subparsers for each command
    create_k8s_scanner_parser(subparsers)
    create_scan_image_parser(subparsers)
    create_verify_parser(subparsers)
    create_extract_parser(subparsers)
    create_chainguard_parser(subparsers)

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
        "k8s-scan": run_k8s_scanner,
        "scan-image": run_scan_image,
        "verify": run_verify,
        "extract": run_extract,
        "verify-chainguard": run_chainguard,
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

