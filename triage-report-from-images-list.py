#!/usr/bin/env python3
"""
Generate a triage report from a list of images (e.g. scanned-images.txt from CVE workflow).

For use by external customers: given a text file with one image reference per line
(e.g. alephalpha.jfrog.io/container-images/etl-workflow:v0.77.3), this script fetches
triage data from the registry for each image and produces a Markdown report with
CVE, score, date, and acceptance per image.

Requires local machine access to the images (registry auth) and: oras, cosign, jq, crane.

Usage:
  python triage-report-from-images-list.py scanned-images.txt -o triage-files -r triage-report.md
  scanner-py retrieve-triage -i scanned-images.txt -o triage-files -r triage-report.md
"""

import argparse
import os
import sys


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fetch triage for images from a list file and generate a Markdown report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "images_file",
        help="Text file with one image reference per line (e.g. scanned-images.txt)",
    )
    parser.add_argument(
        "-o", "--output-dir",
        default="./triage-files",
        help="Output directory for fetched triage files (default: ./triage-files)",
    )
    parser.add_argument(
        "-r", "--report",
        default="./triage-report.md",
        help="Output path for Markdown report (default: ./triage-report.md)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Timeout in seconds for fetching each image (default: 180)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.images_file):
        print(f"Error: File not found: {args.images_file}", file=sys.stderr)
        return 1

    root = os.path.dirname(os.path.abspath(__file__))
    if root not in sys.path:
        sys.path.insert(0, root)

    sys.argv = [
        "scanner-py",
        "retrieve-triage",
        "--images-file", args.images_file,
        "-o", args.output_dir,
        "-r", args.report,
        "--timeout", str(args.timeout),
    ]
    if args.verbose:
        sys.argv.append("--verbose")

    from scanner_py.cli import main as cli_main
    return cli_main()


if __name__ == "__main__":
    sys.exit(main())
