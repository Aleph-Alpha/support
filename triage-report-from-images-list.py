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

    # First, delegate to scanner-py to generate triage files and the initial report.
    sys.argv = [
        "scanner-py",
        "retrieve-triage",
        "--images-file",
        args.images_file,
        "-o",
        args.output_dir,
        "-r",
        args.report,
        "--timeout",
        str(args.timeout),
    ]
    if args.verbose:
        sys.argv.append("--verbose")

    from scanner_py.cli import main as cli_main

    exit_code = cli_main()

    # If scanner-py failed, propagate the exit code without post-processing.
    if exit_code != 0:
        return exit_code

    # Post-process the generated report so that image headers use the original
    # registry references from the input list (e.g. JFrog) instead of the
    # internal Harbor references stored in the triage data.
    try:
        remap_report_image_headers(args.images_file, args.report)
    except Exception as exc:  # pragma: no cover - best-effort post-processing
        print(f"Warning: failed to remap image headers in report: {exc}", file=sys.stderr)

    return exit_code


def remap_report_image_headers(images_file: str, report_path: str) -> None:
    """
    Rewrite image references in report headers from the internal registry
    (e.g. Harbor) back to the original image references used in the input list
    (e.g. JFrog).

    This keeps the triage content untouched but makes the report easier to
    correlate with the images-file the user provided.
    """

    if not os.path.isfile(report_path):
        return

    # Build a mapping from "name:tag" → full image reference from the input list.
    image_map = {}
    with open(images_file, "r", encoding="utf-8") as f:
        for line in f:
            ref = line.strip()
            if not ref:
                continue
            name_tag = ref.split("/")[-1]
            image_map[name_tag] = ref

    changed = False
    new_lines = []
    keep_current_section = True

    with open(report_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("## "):
                original_ref = line[3:].strip()
                name_tag = original_ref.split("/")[-1]
                jfrog_ref = image_map.get(name_tag)

                if jfrog_ref is None:
                    # This section does not correspond to any image in the input
                    # list (e.g. old Harbor-only entries) – drop the whole
                    # section until the next header.
                    keep_current_section = False
                    changed = True
                    continue

                # We want to keep this section and (potentially) remap the header.
                keep_current_section = True
                if jfrog_ref != original_ref:
                    new_lines.append(f"## {jfrog_ref}\n")
                    changed = True
                else:
                    new_lines.append(line)
                continue

            if keep_current_section:
                new_lines.append(line)

    if changed:
        with open(report_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)


if __name__ == "__main__":
    sys.exit(main())
