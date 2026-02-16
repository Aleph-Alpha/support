"""CLI for retrieving triage files from CVE scan results and generating reports.

Collects triage files (Cosign triage.json/triage.trivyignore, ORAS triage.toml)
from Cosign and/or ORAS scan output directories. Can generate a Markdown report
with CVE, score, date, and acceptance per image.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any, List

from ..utils.logging import setup_logging, LogLevel, get_logger
from ..utils.progress import ProgressBar, ProgressStyle
from ..core.attestation import AttestationExtractor

logger = get_logger(__name__)


def load_images_from_file(path: Path) -> List[str]:
    """Load image references from a text file (one per line). Skip empty lines and # comments."""
    images: List[str] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            images.append(line)
    return images


def fetch_triage_for_image(
    image: str,
    output_dir: Path,
    timeout: int,
    extractor: AttestationExtractor,
    verbose: bool = False,
) -> bool:
    """
    Fetch triage for one image from the registry (Cosign attestation or ORAS triage.toml).
    Writes triage.json or triage.toml into output_dir / sanitized_image /.
    Returns True if triage was fetched and saved.
    """
    from .oras_scan import find_triage_reference, fetch_triage_toml, get_image_name

    dir_name = sanitize_image_dir(image)
    image_dir = output_dir / dir_name
    image_dir.mkdir(parents=True, exist_ok=True)

    # Try Cosign triage attestation first
    triage_json = image_dir / "triage.json"
    if extractor.extract_triage(image, str(triage_json), verify=False):
        if verbose:
            logger.info(f"Fetched Cosign triage for {image}")
        return True

    # Fallback: ORAS triage.toml
    triage_ref = find_triage_reference(image, timeout=timeout, verbose=verbose)
    if triage_ref:
        triage_toml = image_dir / "triage.toml"
        manifest_file = image_dir / "manifest.json"
        if fetch_triage_toml(image, triage_ref, str(triage_toml), str(manifest_file), timeout=timeout):
            if verbose:
                logger.info(f"Fetched ORAS triage for {image}")
            return True

    if verbose:
        logger.debug(f"No triage found for {image}")
    return False


def sanitize_image_dir(name: str) -> str:
    """Sanitize image reference for use as directory name."""
    return name.replace("/", "_").replace(":", "_").replace("@", "_")


def collect_from_cosign_dir(
    cosign_dir: Path,
    output_dir: Path | None,
    include_trivyignore: bool,
) -> List[dict]:
    """Collect triage files from a Cosign scan output directory."""
    results: List[dict] = []
    cosign_dir = cosign_dir.resolve()
    summary_path = cosign_dir / "scan-summary.json"

    def copy_triage_entry(
        image: str,
        subdir: Path,
        dir_name: str,
    ) -> dict | None:
        triage_json = subdir / "triage.json"
        if not triage_json.is_file():
            return None
        entry = {"image": image, "source": "cosign", "dir": dir_name, "files": ["triage.json"]}
        trivyignore = subdir / "triage.trivyignore"
        if trivyignore.exists():
            entry["files"].append("triage.trivyignore")
        if output_dir:
            dest = output_dir / dir_name
            dest.mkdir(parents=True, exist_ok=True)
            shutil.copy2(triage_json, dest / "triage.json")
            if include_trivyignore and trivyignore.exists():
                shutil.copy2(trivyignore, dest / "triage.trivyignore")
        return entry

    if not summary_path.exists():
        for sub in cosign_dir.iterdir():
            if not sub.is_dir():
                continue
            entry = copy_triage_entry(sub.name, sub, sub.name)
            if entry:
                results.append(entry)
        return results

    with open(summary_path) as f:
        data = json.load(f)

    cve_analysis = data.get("cve_analysis", [])
    if not cve_analysis:
        return results

    for analysis in cve_analysis:
        image = analysis.get("image")
        if not image:
            continue
        if not analysis.get("has_triage_file", True) and not analysis.get("triage_file"):
            continue
        triage_file = analysis.get("triage_file")
        subdir_name = sanitize_image_dir(image)
        src_path: Path | None = None

        if triage_file:
            src_path = Path(triage_file)
            if not src_path.is_absolute():
                if triage_file.startswith(cosign_dir.name + "/"):
                    src_path = cosign_dir.parent / triage_file
                else:
                    src_path = cosign_dir / triage_file
                parts = Path(triage_file).parts
                if len(parts) >= 2 and not src_path.exists():
                    src_path = cosign_dir / parts[-2] / parts[-1]
            if src_path.exists():
                subdir = src_path.parent
                subdir_name = subdir.name if subdir.parent == cosign_dir else subdir_name
            else:
                src_path = None
        if not src_path or not src_path.exists():
            src_path = cosign_dir / subdir_name / "triage.json"
        if not src_path.exists():
            continue
        subdir = src_path.parent
        if subdir.parent == cosign_dir:
            subdir_name = subdir.name
        entry = copy_triage_entry(image, subdir, subdir_name)
        if entry:
            results.append(entry)
    return results


def _parse_triage_json(path: Path) -> tuple[List[dict] | None, str | None]:
    """
    Parse Cosign triage.json.
    Returns (list of {cve, score, date, acceptance, ...}, image_name from subject or None).
    """
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None, None
    trivy = data.get("predicate", {}).get("trivy", {})
    if not trivy or not isinstance(trivy, dict):
        return None, None
    subject = data.get("subject") or []
    image_from_subject = subject[0].get("name") if subject and isinstance(subject[0], dict) else None
    rows: List[dict] = []
    for cve_id, info in trivy.items():
        if not isinstance(info, dict):
            continue
        rows.append({
            "cve": cve_id,
            "score": info.get("base_score", ""),
            "date": info.get("date", ""),
            "acceptance": info.get("acceptance", ""),
            "description": info.get("description", ""),
            "triaged_by": info.get("triaged_by", ""),
        })
    return (rows if rows else None, image_from_subject)


def generate_triage_report_md(triage_dir: Path, image_from_dir: bool = True) -> str:
    """
    Generate a Markdown report from collected triage files.

    Walks triage_dir (subdirs per image, each with triage.json or triage.toml).
    For each image with triage data, outputs a section with a table:
    CVE | Score | Date | Acceptance.
    """
    triage_dir = triage_dir.resolve()
    if not triage_dir.is_dir():
        return ""
    lines = [
        "# CVE Triage Report",
        "",
        "Report generated from triage files. For each image, triaged CVEs are listed with score, date, and acceptance rationale.",
        "",
    ]

    def dir_to_image_ref(dir_name: str) -> str:
        parts = dir_name.split("_")
        if len(parts) <= 1:
            return dir_name
        tag = parts[-1]
        rest = "_".join(parts[:-1])
        return rest.replace("_", "/") + ":" + tag

    subdirs = sorted(d for d in triage_dir.iterdir() if d.is_dir())
    for subdir in subdirs:
        triage_json = subdir / "triage.json"
        triage_toml = subdir / "triage.toml"
        image_name = dir_to_image_ref(subdir.name) if image_from_dir else subdir.name
        if triage_json.exists():
            rows, subject_name = _parse_triage_json(triage_json)
            if subject_name:
                image_name = subject_name
                if ":" not in subject_name and "_" in subdir.name:
                    tag = subdir.name.split("_")[-1]
                    image_name = subject_name + ":" + tag
            if rows:
                lines.append(f"## {image_name}")
                lines.append("")
                lines.append("| CVE | Score | Date | Acceptance |")
                lines.append("|-----|-------|------|------------|")
                for r in rows:
                    acc = (r.get("acceptance") or "").replace("|", "\\|").replace("\n", " ")
                    score = (r.get("score") or "").strip()
                    date = (r.get("date") or "").strip()
                    lines.append(f"| {r.get('cve', '')} | {score} | {date} | {acc} |")
                lines.append("")
                continue
        if triage_toml.exists():
            lines.append(f"## {image_name}")
            lines.append("")
            lines.append("*Triage file: triage.toml (CVE list only; no score/date/acceptance in file)*")
            lines.append("")
            try:
                content = triage_toml.read_text()
                cves = []
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("#"):
                        continue
                    for part in re.findall(r"trivy\.(CVE-[A-Z0-9\-]+)", line):
                        cves.append(part)
                if cves:
                    lines.append("| CVE | Score | Date | Acceptance |")
                    lines.append("|-----|-------|------|------------|")
                    for cve in sorted(set(cves)):
                        lines.append(f"| {cve} | — | — | *(see triage.toml)* |")
                    lines.append("")
            except OSError:
                lines.append("*(Could not read triage.toml)*")
                lines.append("")
    if len(subdirs) == 0:
        lines.append("*No triage data found.*")
        lines.append("")
    return "\n".join(lines)


def collect_from_oras_dir(oras_dir: Path, output_dir: Path | None) -> List[dict]:
    """Collect triage files from an ORAS scan output directory."""
    results: List[dict] = []
    oras_dir = oras_dir.resolve()
    for sub in oras_dir.iterdir():
        if not sub.is_dir():
            continue
        triage_toml = sub / "triage.toml"
        if not triage_toml.is_file() or triage_toml.stat().st_size == 0:
            continue
        image_ref = sub.name.replace("_", "/", 1)
        image_txt = sub / "image.txt"
        if image_txt.exists():
            image_ref = image_txt.read_text().strip()
        entry = {"image": image_ref, "source": "oras", "dir": sub.name, "files": ["triage.toml"]}
        if output_dir:
            dest = output_dir / sub.name
            dest.mkdir(parents=True, exist_ok=True)
            shutil.copy2(triage_toml, dest / "triage.toml")
        results.append(entry)
    return results


def create_retrieve_triage_parser(subparsers: Any) -> argparse.ArgumentParser:
    """Create the retrieve-triage subparser."""
    parser = subparsers.add_parser(
        "retrieve-triage",
        help="Retrieve triage files from CVE scan results and generate reports",
        description="""
Retrieve all triage files for images from CVE scan results (Cosign and/or ORAS).

Collects triage files produced by the CVE Scans workflow into a single output
directory. Optionally generates a Markdown report with CVE, score, date, and
acceptance per image.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # From Cosign scan output
  scanner-py retrieve-triage --cosign-dir scan-results -o triage-files

  # From ORAS scan output
  scanner-py retrieve-triage --oras-dir cve-triage -o triage-files

  # Generate Markdown report from triage files
  scanner-py retrieve-triage --report triage-report.md --report-from triage-files

  # Collect and generate report in one run
  scanner-py retrieve-triage --cosign-dir scan-results -o triage-files --report triage-report.md

  # From scanned-images.txt (customer list): fetch triage from registry and generate report
  scanner-py retrieve-triage -i scanned-images.txt -o triage-files -r triage-report.md
""",
    )
    parser.add_argument(
        "--cosign-dir",
        metavar="PATH",
        help="Cosign scan output directory (scan-summary.json and per-image subdirs with triage.json)",
    )
    parser.add_argument(
        "--oras-dir",
        metavar="PATH",
        help="ORAS scan output directory (per-image subdirs with triage.toml)",
    )
    parser.add_argument(
        "-o", "--output-dir",
        metavar="PATH",
        default="./triage-files",
        help="Output directory for collected triage files (default: ./triage-files)",
    )
    parser.add_argument(
        "--include-trivyignore",
        action="store_true",
        default=True,
        help="Include triage.trivyignore when copying from Cosign scan (default: True)",
    )
    parser.add_argument(
        "--no-trivyignore",
        action="store_true",
        help="Do not copy triage.trivyignore from Cosign scan",
    )
    parser.add_argument(
        "--manifest",
        metavar="FILE",
        help="Write manifest JSON to FILE (image -> list of triage files)",
    )
    parser.add_argument(
        "--manifest-only",
        action="store_true",
        help="Only build and print manifest; do not copy files",
    )
    parser.add_argument(
        "--report", "-r",
        metavar="FILE",
        help="Generate Markdown report from triage files (CVE, score, date, acceptance per image)",
    )
    parser.add_argument(
        "--report-from",
        metavar="DIR",
        help="Directory containing triage files for report (default: output dir after collection)",
    )
    parser.add_argument(
        "--images-file", "-i",
        metavar="FILE",
        help="Text file with one image reference per line (e.g. scanned-images.txt from CVE workflow). Fetches triage from registry for each image; requires local access to the images (oras, cosign).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Timeout in seconds for fetching triage from registry (default: 180)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging",
    )
    return parser


def run_retrieve_triage(args: Any) -> int:
    """Run retrieve-triage command."""
    log_level = LogLevel.VERBOSE if args.verbose else LogLevel.INFO
    setup_logging(log_level, show_errors=args.verbose)

    report_only = bool(args.report and args.report_from)
    images_file_mode = bool(args.images_file)
    if not args.cosign_dir and not args.oras_dir and not report_only and not images_file_mode:
        print(
            "Error: Specify at least one of: --cosign-dir, --oras-dir, --images-file, or (--report with --report-from)",
            file=sys.stderr,
        )
        return 1

    output_dir = Path(args.output_dir).resolve() if not args.manifest_only and not report_only else None
    if output_dir and not args.manifest_only:
        output_dir.mkdir(parents=True, exist_ok=True)

    include_trivyignore = args.include_trivyignore and not args.no_trivyignore
    all_entries: List[dict] = []

    if not report_only and args.images_file:
        images_path = Path(args.images_file)
        if not images_path.exists():
            print(f"Error: Images file not found: {images_path}", file=sys.stderr)
            return 1
        images = load_images_from_file(images_path)
        if not images:
            print("Error: No images found in file (empty or only comments)", file=sys.stderr)
            return 1
        from ..utils.subprocess import check_prerequisites
        missing = check_prerequisites(["oras", "cosign", "jq", "crane"])
        if missing:
            print(f"Error: Missing required tools for registry fetch: {', '.join(missing)}", file=sys.stderr)
            return 1
        extractor = AttestationExtractor(timeout=args.timeout)
        timeout = getattr(args, "timeout", 180)
        fetched = 0
        print(f"Fetching triage for {len(images)} image(s) from registry...")
        progress = ProgressBar(len(images), "Fetching triage", ProgressStyle(width=30))
        for image in images:
            got = fetch_triage_for_image(image, output_dir, timeout, extractor, verbose=args.verbose)
            if got:
                fetched += 1
                d = sanitize_image_dir(image)
                all_entries.append({"image": image, "source": "registry", "dir": d, "files": ["triage.json", "triage.toml"]})
                progress.update(status="success", current_item=image.split("/")[-1])
            else:
                progress.update(status="skipped", current_item=image.split("/")[-1])
        progress.finish()
        print(f"Fetched triage for {fetched}/{len(images)} images -> {output_dir}")
        if args.verbose and fetched < len(images):
            logger.info(f"Images with no triage: {len(images) - fetched}")
    elif not report_only and args.cosign_dir:
        cosign_path = Path(args.cosign_dir)
        if not cosign_path.exists():
            print(f"Error: Cosign directory not found: {cosign_path}", file=sys.stderr)
            return 1
        cosign_entries = collect_from_cosign_dir(cosign_path, output_dir, include_trivyignore)
        all_entries.extend(cosign_entries)
        if args.verbose:
            logger.info(f"Cosign: collected {len(cosign_entries)} triage entries from {cosign_path}")

    if not report_only and args.oras_dir:
        oras_path = Path(args.oras_dir)
        if not oras_path.exists():
            print(f"Error: ORAS directory not found: {oras_path}", file=sys.stderr)
            return 1
        oras_entries = collect_from_oras_dir(oras_path, output_dir)
        all_entries.extend(oras_entries)
        if args.verbose:
            logger.info(f"ORAS: collected {len(oras_entries)} triage entries from {oras_path}")

    manifest = {"images": all_entries, "total": len(all_entries)}

    if args.manifest:
        with open(args.manifest, "w") as f:
            json.dump(manifest, f, indent=2)
        print(f"Manifest written to {args.manifest}")

    if args.manifest_only:
        print(json.dumps(manifest, indent=2))
    elif not report_only and not images_file_mode:
        print(f"Collected {len(all_entries)} triage file set(s) -> {output_dir}")

    if args.report:
        report_dir = Path(args.report_from).resolve() if args.report_from else output_dir
        if not report_dir or not report_dir.is_dir():
            print(f"Error: Report source directory not found: {report_dir}", file=sys.stderr)
            return 1
        md = generate_triage_report_md(report_dir, image_from_dir=True)
        Path(args.report).write_text(md, encoding="utf-8")
        print(f"Report written to {args.report}")

    return 0
