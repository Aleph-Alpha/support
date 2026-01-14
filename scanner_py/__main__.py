"""
Main entry point for the scanner package.

Usage:
    python -m scanner_py cosign-scan [OPTIONS]
    python -m scanner_py scan-image [OPTIONS]
    python -m scanner_py verify [OPTIONS]
    python -m scanner_py extract [OPTIONS]
    python -m scanner_py verify-chainguard [OPTIONS]
"""

import sys


def main() -> int:
    """Main entry point."""
    from .cli import main as cli_main
    return cli_main()


if __name__ == "__main__":
    sys.exit(main())

