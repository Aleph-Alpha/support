"""CLI for attestation extraction.

Equivalent to cosign-extract.sh
"""

import argparse
import json
import sys
from typing import Any

from ..core.attestation import AttestationExtractor, AttestationTypeEnum, PREDICATE_TYPE_MAP
from ..utils.logging import setup_logging, LogLevel, is_verbose
from ..utils.subprocess import check_prerequisites
from ..utils.progress import Spinner


def create_extract_parser(subparsers: Any) -> argparse.ArgumentParser:
    """Create the extract subparser."""
    parser = subparsers.add_parser(
        "extract",
        help="Extract attestations from an image",
        description="""
Extract attestations (SBOM, triage, SLSA provenance, etc.) from container images.

Supports listing available attestations and extracting specific types.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List available attestations
  scanner-py extract --image registry.io/app:v1.0 --list

  # Extract SBOM (CycloneDX)
  scanner-py extract --image registry.io/app:v1.0 --type cyclonedx --output sbom.json

  # Extract triage attestation with verification
  scanner-py extract --image registry.io/app:v1.0 --type triage --verify --output triage.json

  # Extract only the predicate content (not full attestation)
  scanner-py extract --image registry.io/app:v1.0 --type cyclonedx --predicate-only --output sbom.json

Attestation Types:
  slsa        - SLSA provenance (https://slsa.dev/provenance/v1)
  cyclonedx   - CycloneDX SBOM (https://cyclonedx.org/bom)
  spdx        - SPDX SBOM (https://spdx.dev/Document)
  vuln        - Vulnerability attestation
  license     - License attestation
  triage      - Triage attestation (Aleph Alpha)
  custom      - Custom attestation
""",
    )

    parser.add_argument(
        "--image",
        required=True,
        help="Image reference",
    )
    parser.add_argument(
        "--type",
        dest="attestation_type",
        choices=["slsa", "cyclonedx", "spdx", "vuln", "license", "triage", "custom"],
        help="Attestation type to extract",
    )
    parser.add_argument(
        "--output",
        help="Output file path",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available attestations",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify attestation before extraction",
    )
    parser.add_argument(
        "--predicate-only",
        action="store_true",
        help="Extract only predicate content (not full envelope)",
    )
    parser.add_argument(
        "--last",
        action="store_true",
        default=True,
        help="Use most recent attestation if multiple exist (default)",
    )
    parser.add_argument(
        "--certificate-oidc-issuer",
        default=AttestationExtractor.DEFAULT_OIDC_ISSUER,
        help="OIDC issuer for verification",
    )
    parser.add_argument(
        "--certificate-identity-regexp",
        default=AttestationExtractor.DEFAULT_IDENTITY_REGEXP,
        help="Identity regexp for verification",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Timeout in seconds (default: 60)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output (shows errors)",
    )

    return parser


def run_extract(args: argparse.Namespace) -> int:
    """
    Run attestation extraction.

    Args:
        args: Parsed command line arguments

    Returns:
        Exit code
    """
    # Setup logging - errors only shown in verbose mode
    log_level = LogLevel.VERBOSE if args.verbose else LogLevel.INFO
    setup_logging(log_level, show_errors=args.verbose)

    # Check prerequisites
    missing = check_prerequisites(["crane", "oras", "jq"])
    if missing:
        print(f"❌ Missing required tools: {', '.join(missing)}", file=sys.stderr)
        return 1

    # Print header
    print("📦 Attestation Extractor")
    print()
    print("⚙️  Configuration:")
    print(f"   • Image: {args.image}")
    if args.attestation_type:
        print(f"   • Type: {args.attestation_type}")
    if args.verbose:
        print("   • Verbose: Enabled (showing errors)")
    print()

    # Create extractor
    extractor = AttestationExtractor(
        certificate_oidc_issuer=args.certificate_oidc_issuer,
        certificate_identity_regexp=args.certificate_identity_regexp,
        timeout=args.timeout,
    )

    # Handle list mode
    if args.list:
        spinner = Spinner("Discovering attestations...")
        spinner.spin()
        
        attestations = extractor.list_attestations(args.image)
        
        if not attestations.attestations:
            spinner.finish("No attestations found", success=False)
            return 1
        
        spinner.finish(f"Found {len(attestations.attestations)} attestation type(s)")
        print()
        print("━" * 50)
        print("📋 AVAILABLE ATTESTATIONS")
        print("━" * 50)
        print()
        print(f"  {'Count':>5}  {'Type':<12}  URI")
        print("  " + "─" * 45)
        
        for pred_type, count in sorted(attestations.attestations.items()):
            # Get friendly name
            friendly_name = "unknown"
            for atype, ptype in PREDICATE_TYPE_MAP.items():
                if ptype == pred_type:
                    friendly_name = atype.value
                    break
            print(f"  {count:>5}  {friendly_name:<12}  {pred_type}")

        return 0

    # Require type for extraction
    if not args.attestation_type:
        print("❌ Must specify --type or use --list", file=sys.stderr)
        return 1

    # Map string type to enum
    type_map = {
        "slsa": AttestationTypeEnum.SLSA,
        "cyclonedx": AttestationTypeEnum.CYCLONEDX,
        "spdx": AttestationTypeEnum.SPDX,
        "vuln": AttestationTypeEnum.VULN,
        "license": AttestationTypeEnum.LICENSE,
        "triage": AttestationTypeEnum.TRIAGE,
        "custom": AttestationTypeEnum.CUSTOM,
    }
    atype = type_map[args.attestation_type]

    # Extract attestation with spinner
    spinner = Spinner(f"Extracting {args.attestation_type} attestation...")
    spinner.spin()

    content = extractor.extract(
        args.image,
        atype,
        output_file=args.output,
        predicate_only=args.predicate_only,
        verify=args.verify,
        use_last=args.last,
    )

    if content is None:
        spinner.finish("Extraction failed", success=False)
        
        if is_verbose():
            print()
            print("ℹ️  Available attestations for this image:")
            attestations = extractor.list_attestations(args.image)
            for pred_type, count in sorted(attestations.attestations.items()):
                print(f"   {count:3d} {pred_type}")
        else:
            print()
            print("💡 Use --verbose for more details, or --list to see available attestations")

        return 1

    spinner.finish("Extraction successful")

    # Output
    print()
    if args.output:
        print(f"💾 Attestation written to: {args.output}")
    else:
        print("━" * 50)
        print("📄 ATTESTATION CONTENT")
        print("━" * 50)
        print(json.dumps(content, indent=2))

    return 0
