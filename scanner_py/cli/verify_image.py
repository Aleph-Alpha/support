"""CLI for image signature verification.

Equivalent to cosign-verify-image.sh
"""

import argparse
import sys
from typing import Any

from ..core.verification import CosignVerifier
from ..utils.logging import setup_logging, LogLevel, is_verbose
from ..utils.subprocess import check_prerequisites
from ..utils.progress import Spinner


def create_verify_parser(subparsers: Any) -> argparse.ArgumentParser:
    """Create the verify subparser."""
    parser = subparsers.add_parser(
        "verify",
        help="Verify image signature with cosign",
        description="""
Verify container image signatures using cosign.

Supports both keyless (OIDC-based) and key-based verification modes.
Default mode uses keyless verification with GitHub Actions as OIDC issuer.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Verify with default Aleph Alpha settings (keyless)
  scanner-py verify --image registry.example.com/myapp:latest

  # Verify with custom GitHub organization
  scanner-py verify --image registry.example.com/myapp:latest \\
    --certificate-identity-regexp "https://github.com/myorg/.*/.github/workflows/.*"

  # Verify with public key
  scanner-py verify --image registry.example.com/myapp:latest --key cosign.pub

  # Silent mode for automation (only exit code)
  scanner-py verify --image registry.example.com/myapp:latest --output-level none
""",
    )

    parser.add_argument(
        "--image",
        required=True,
        help="Image reference to verify",
    )
    parser.add_argument(
        "--certificate-oidc-issuer",
        default=CosignVerifier.DEFAULT_OIDC_ISSUER,
        help=f"OIDC issuer for keyless verification (default: {CosignVerifier.DEFAULT_OIDC_ISSUER})",
    )
    parser.add_argument(
        "--certificate-identity-regexp",
        default=CosignVerifier.DEFAULT_IDENTITY_REGEXP,
        help="Identity regexp for keyless verification",
    )
    parser.add_argument(
        "--certificate-identity",
        help="Exact certificate identity for keyless verification",
    )
    parser.add_argument(
        "--key",
        dest="key_file",
        help="Path to public key file for key-based verification",
    )
    parser.add_argument(
        "--keyless",
        action="store_true",
        default=True,
        help="Use keyless verification (default)",
    )
    parser.add_argument(
        "--rekor-url",
        default=CosignVerifier.DEFAULT_REKOR_URL,
        help=f"Rekor transparency log URL (default: {CosignVerifier.DEFAULT_REKOR_URL})",
    )
    parser.add_argument(
        "--output-signature",
        help="Save signature to file",
    )
    parser.add_argument(
        "--output-certificate",
        help="Save certificate to file",
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


def run_verify(args: argparse.Namespace) -> int:
    """
    Run image verification.

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
    missing = check_prerequisites(["cosign", "crane"])
    if missing:
        print(f"❌ Missing required tools: {', '.join(missing)}", file=sys.stderr)
        return 1

    # Handle mutually exclusive options
    if args.certificate_identity and args.certificate_identity_regexp:
        print("❌ Cannot use both --certificate-identity and --certificate-identity-regexp", file=sys.stderr)
        return 1

    # Show helpful info
    if args.output_level != "none":
        print("🔐 Image Signature Verification")
        print()
        print("⚙️  Configuration:")
        print(f"   • Image: {args.image}")
        mode = "Key-based" if args.key_file else "Keyless (OIDC)"
        print(f"   • Mode: {mode}")
        if args.output_level == "verbose":
            print("   • Verbose: Enabled (showing errors)")
        print()

    # Create verifier
    verifier = CosignVerifier(
        certificate_oidc_issuer=args.certificate_oidc_issuer,
        certificate_identity_regexp=(
            args.certificate_identity_regexp if not args.certificate_identity else None
        ),
        certificate_identity=args.certificate_identity,
        key_file=args.key_file,
        rekor_url=args.rekor_url,
        timeout=args.timeout,
    )

    # Run verification with spinner
    spinner = None
    if args.output_level != "none":
        spinner = Spinner("Verifying signature...")
        spinner.spin()

    result = verifier.verify(
        args.image,
        output_signature=args.output_signature,
        output_certificate=args.output_certificate,
    )

    if spinner:
        if result.success:
            spinner.finish("Signature verified", success=True)
        else:
            spinner.finish("Verification failed", success=False)

    # Print result
    if args.output_level != "none":
        print()
        if result.success:
            print("━" * 50)
            print("✅ VERIFICATION SUCCESSFUL")
            print("━" * 50)
            print()
            print("🛡️  Image is cryptographically signed and verified!")
            if result.signature_file:
                print(f"💾 Signature saved to: {result.signature_file}")
            if result.certificate_file:
                print(f"💾 Certificate saved to: {result.certificate_file}")
        else:
            print("━" * 50)
            print("❌ VERIFICATION FAILED")
            print("━" * 50)
            print()
            if args.output_level == "verbose":
                print(f"📋 Error: {result.message}")
                print()
            print("💡 Possible reasons:")
            print("   • Image is not signed")
            print("   • Wrong verification parameters")
            print("   • Network issues accessing transparency log")
            if args.output_level != "verbose":
                print()
                print("   Use --output-level verbose for more details")

    # Determine exit code
    if result.success:
        return 0
    elif args.no_error:
        return 0
    else:
        return 1
