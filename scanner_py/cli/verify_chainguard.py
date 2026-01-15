"""CLI for Chainguard base image verification.

Equivalent to verify-chainguard-base-image.sh
"""

import argparse
import sys
from typing import Any

from ..core.chainguard import ChainguardVerifier
from ..utils.logging import setup_logging, LogLevel, is_verbose
from ..utils.subprocess import check_prerequisites
from ..utils.progress import Spinner


def create_chainguard_parser(subparsers: Any) -> argparse.ArgumentParser:
    """Create the verify-chainguard subparser."""
    parser = subparsers.add_parser(
        "verify-chainguard",
        help="Check if image uses Chainguard base image",
        description="""
Verify if a Docker image was built using a Chainguard base image.

Checks the image's base layer and verifies its Chainguard signature.
Supports both public Chainguard images (cgr.dev/chainguard/*) and
Aleph Alpha production images (cgr.dev/aleph-alpha.com/*).
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check if image uses Chainguard base
  scanner-py verify-chainguard --image registry.example.com/myapp:latest

  # Silent mode for automation
  scanner-py verify-chainguard --image myapp:latest --output-level none

  # Check without failing on mismatch
  scanner-py verify-chainguard --image myapp:latest --no-error

Verification Modes:
  The script automatically selects verification based on the base image:
  - Public Chainguard (cgr.dev/chainguard/*) -> GitHub Actions verification
  - Aleph Alpha (cgr.dev/aleph-alpha.com/*) -> Production verification
""",
    )

    parser.add_argument(
        "--image",
        required=True,
        help="Docker image to check",
    )
    parser.add_argument(
        "--fail-on-mismatch",
        action="store_true",
        default=True,
        help="Fail if base image doesn't match Chainguard (default)",
    )
    parser.add_argument(
        "--no-fail-on-mismatch",
        action="store_true",
        help="Don't fail if base image doesn't match",
    )
    parser.add_argument(
        "--output-level",
        choices=["none", "info", "verbose"],
        default="info",
        help="Output verbosity level (default: info)",
    )
    parser.add_argument(
        "--no-error",
        action="store_true",
        help="Return exit code 0 even on verification failure",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Timeout in seconds (default: 60)",
    )

    return parser


def run_chainguard(args: argparse.Namespace) -> int:
    """
    Run Chainguard verification.

    Args:
        args: Parsed command line arguments

    Returns:
        Exit code
    """
    # Setup logging - errors only shown in verbose mode
    log_level = {
        "none": LogLevel.NONE,
        "info": LogLevel.INFO,
        "verbose": LogLevel.VERBOSE,
    }[args.output_level]
    setup_logging(log_level, show_errors=(args.output_level == "verbose"))

    # Check prerequisites
    missing = check_prerequisites(["docker", "crane", "cosign", "jq"])
    if missing:
        print(f"❌ Missing required tools: {', '.join(missing)}", file=sys.stderr)
        return 1

    # Determine fail behavior
    fail_on_mismatch = args.fail_on_mismatch and not args.no_fail_on_mismatch

    # Print header
    if args.output_level != "none":
        print("🔍 Chainguard Base Image Checker")
        print()
        print("⚙️  Configuration:")
        print(f"   • Image: {args.image}")
        print(f"   • Fail on Mismatch: {fail_on_mismatch}")
        if args.output_level == "verbose":
            print("   • Verbose: Enabled (showing errors)")
        print()

    # Create verifier
    verifier = ChainguardVerifier(timeout=args.timeout)

    # Run verification with spinner
    spinner = None
    if args.output_level != "none":
        spinner = Spinner("Checking base image...")
        spinner.spin()

    result = verifier.verify(args.image, fail_on_mismatch=fail_on_mismatch)

    if spinner:
        if result.is_chainguard and result.signature_verified:
            spinner.finish("Chainguard base image verified", success=True)
        elif result.is_chainguard:
            spinner.finish("Chainguard detected (signature not verified)", success=False)
        else:
            spinner.finish("Not a Chainguard base image", success=False)

    # Print results
    if args.output_level != "none":
        print()
        print("━" * 50)
        print("📋 RESULTS")
        print("━" * 50)
        print()
        
        base_display = result.base_image or "unknown"
        if len(base_display) > 45:
            base_display = "..." + base_display[-42:]
        
        print(f"  Base Image:         {base_display}")
        
        cg_status = "✅ Yes" if result.is_chainguard else "❌ No"
        print(f"  Is Chainguard:      {cg_status}")
        
        sig_status = "✅ Verified" if result.signature_verified else "❌ Not verified"
        print(f"  Signature:          {sig_status}")
        print()
        
        if result.is_chainguard and result.signature_verified:
            print("🎉 Image is built on a verified Chainguard base!")
        elif result.is_chainguard:
            if args.output_level == "verbose":
                print("⚠️  Chainguard base detected but signature verification failed")
            else:
                print("⚠️  Chainguard base detected but not verified")
                print("   Use --output-level verbose for details")
        else:
            print("ℹ️  Image does not use a Chainguard base")
    
    elif args.output_level == "none":
        # Machine-readable output for automation
        print(f"IS_CHAINGUARD={str(result.is_chainguard).lower()}")
        print(f'BASE_IMAGE="{result.base_image}"')
        print(f"SIGNATURE_VERIFIED={str(result.signature_verified).lower()}")

    # Determine exit code
    if result.is_chainguard and result.signature_verified:
        return 0
    elif args.no_error:
        return 0
    elif fail_on_mismatch:
        return 1
    else:
        return 0
