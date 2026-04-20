"""
ORAS Scan CLI - Python port of oras-scan bash scripts.

This is a direct port of the oras-scan bash scripts:
- 1-make-list.sh: Extract images from Kubernetes
- 2-oras-scan.sh: Scan images with Trivy, fetch triage.toml
- 3-gen-report.sh: Generate vulnerability report

Key differences from cosign-scan:
- NO signature verification (no cosign)
- Direct image scanning with Trivy (NOT SBOM-based)
- Simple ORAS referrer lookup for triage.toml
- TOML format triage files
"""

import argparse
import atexit
import json
import os
import re
import shutil
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from ..utils.subprocess import run_command
from ..utils.logging import setup_logging, LogLevel, get_logger
from ..utils.progress import ProgressBar, ProgressStyle, Spinner

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Per-worker Trivy cache pool.
#
# Trivy's default `fs` cache backend uses BoltDB and holds an exclusive lock
# on `<cache-dir>/fanal/cache.db` for the duration of every scan. Pointing all
# parallel workers at the same cache dir therefore serialises them - the
# unlucky ones time out with:
#
#     unable to initialize fs cache: cache may be in use by another process
#
# We avoid the contention by giving every worker thread its own cache dir,
# pre-populated by copying the immutable vuln-DB files (`db/trivy.db`,
# `db/metadata.json`, optional `java-db/`) that `prepare_trivy_db()` has
# already downloaded into the shared default cache. Combined with
# `--skip-db-update`, this means: no DB redownloads, no lock contention.
#
# The pool is bounded by `args.parallel` workers (typically 5-15), so peak
# disk usage is ~N x DB-size (~30-50 MB per copy) which is comfortable on a
# CI runner.
# ---------------------------------------------------------------------------

_TRIVY_DB_SRC: Optional[Path] = None
_THREAD_CACHE = threading.local()
_CACHE_DIRS_LOCK = threading.Lock()
_CACHE_DIRS: List[Path] = []


def _trivy_default_cache_dir() -> Path:
    """
    Return the cache directory Trivy would use by default.

    Honors $TRIVY_CACHE_DIR, then $XDG_CACHE_HOME/trivy, then ~/.cache/trivy
    (matches Trivy's own resolution order).
    """
    env_dir = os.environ.get("TRIVY_CACHE_DIR")
    if env_dir:
        return Path(env_dir)
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "trivy"
    return Path.home() / ".cache" / "trivy"


def _get_worker_cache_dir() -> Path:
    """
    Return a per-thread Trivy cache dir, populated lazily on first call.

    Each worker thread gets its own writable cache directory containing a
    copy of the vuln DB so that Trivy's fanal/cache.db lock cannot collide
    across workers.
    """
    if _TRIVY_DB_SRC is None:
        raise RuntimeError(
            "prepare_trivy_db() must be called before run_trivy_scan()"
        )

    cache_dir: Optional[Path] = getattr(_THREAD_CACHE, "cache_dir", None)
    if cache_dir is not None:
        return cache_dir

    cache_dir = Path(tempfile.mkdtemp(prefix="trivy-cache-"))

    src_db = _TRIVY_DB_SRC / "db"
    if src_db.is_dir():
        shutil.copytree(src_db, cache_dir / "db")

    src_java = _TRIVY_DB_SRC / "java-db"
    if src_java.is_dir():
        shutil.copytree(src_java, cache_dir / "java-db")

    with _CACHE_DIRS_LOCK:
        _CACHE_DIRS.append(cache_dir)
    _THREAD_CACHE.cache_dir = cache_dir
    return cache_dir


def _cleanup_trivy_cache_dirs() -> None:
    """Remove every per-worker Trivy cache dir at process exit."""
    with _CACHE_DIRS_LOCK:
        for cache_dir in _CACHE_DIRS:
            shutil.rmtree(cache_dir, ignore_errors=True)
        _CACHE_DIRS.clear()


atexit.register(_cleanup_trivy_cache_dirs)


@dataclass
class ImageScanResult:
    """Result of scanning a single image."""
    image: str
    image_ref: str  # Image without registry prefix
    success: bool = False
    error: Optional[str] = None

    # CVE data
    high_critical_cves: Set[str] = field(default_factory=set)
    triaged_cves: Set[str] = field(default_factory=set)

    # Triage file status
    has_triage: bool = False
    triage_file: Optional[str] = None

    # Output directory
    output_dir: Optional[str] = None

    @property
    def unaddressed_cves(self) -> Set[str]:
        """CVEs found but not triaged."""
        return self.high_critical_cves - self.triaged_cves

    @property
    def addressed_cves(self) -> Set[str]:
        """CVEs that are both found and triaged."""
        return self.high_critical_cves & self.triaged_cves

    @property
    def irrelevant_cves(self) -> Set[str]:
        """Triaged CVEs not found in scan (may have been fixed)."""
        return self.triaged_cves - self.high_critical_cves


def create_oras_scan_parser(subparsers: Any) -> argparse.ArgumentParser:
    """Create the oras-scan subparser."""
    parser = subparsers.add_parser(
        "oras-scan",
        help="Simple vulnerability scan with triage support (port of oras-scan bash scripts)",
        description="""
Scan container images for vulnerabilities and check against triage files.

This is a direct Python port of the oras-scan bash scripts. It:
1. Extracts images from Kubernetes pods
2. Scans each image directly with Trivy (not SBOM-based)
3. Fetches triage.toml files via ORAS referrers
4. Generates a vulnerability report

Unlike cosign-scan, this does NOT verify signatures or use SBOM attestations.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan images in default namespace
  scanner-py oras-scan

  # Scan specific namespace with ignore file
  scanner-py oras-scan --namespace production --ignore-file ./ignore.txt

  # Generate report with filters
  scanner-py oras-scan --filter-unaddressed --output report.md

  # Scan with parallel workers
  scanner-py oras-scan --parallel 10
""",
    )

    # Kubernetes options
    parser.add_argument(
        "--namespace", "-n",
        default="pharia-ai",
        help="Kubernetes namespace to scan (default: pharia-ai)",
    )
    parser.add_argument(
        "--kubeconfig",
        help="Path to kubeconfig file",
    )
    parser.add_argument(
        "--context",
        help="Kubernetes context to use",
    )

    # Input/Output options
    parser.add_argument(
        "--ignore-file", "-i",
        help="""File containing image patterns to ignore (one per line).
Lines starting with # are treated as comments.
Example content:
  stakater/reloader
  bitnami/kubectl
  # This is a comment
  temporalio/
""",
    )
    parser.add_argument(
        "--output-dir",
        default="./cve-triage",
        help="Output directory for scan results (default: ./cve-triage)",
    )
    parser.add_argument(
        "--output", "-o",
        help="Path to write Markdown report (default: stdout)",
    )

    # Filter options (matching 3-gen-report.sh)
    parser.add_argument(
        "--filter-unaddressed", "-u",
        action="store_true",
        help="Only show images with unaddressed CVEs",
    )
    parser.add_argument(
        "--filter-missing-triage", "-t",
        action="store_true",
        help="Only show images with missing triage files",
    )

    # Scanning options
    parser.add_argument(
        "--parallel", "-p",
        type=int,
        default=10,
        help="Number of parallel scans (default: 10)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Timeout for Trivy scan in seconds (default: 600)",
    )
    parser.add_argument(
        "--min-cve-level",
        default="MEDIUM",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Minimum CVE level to consider relevant (default: MEDIUM)",
    )

    # Mode options
    parser.add_argument(
        "--scan-only",
        action="store_true",
        help="Only run scans, don't generate report",
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Only generate report from existing scan results",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging (shows Trivy errors, ORAS details, etc.)",
    )

    return parser


def get_images_from_kubernetes(
    namespace: str,
    kubeconfig: Optional[str] = None,
    context: Optional[str] = None,
) -> List[str]:
    """
    Get unique container images from Kubernetes pods.

    Equivalent to: kubectl get pods -o json | jq -r '.items[] | (.spec.containers[].image)'
    """
    args = ["kubectl", "get", "pods", "-o", "json"]

    if namespace:
        args.extend(["-n", namespace])
    if kubeconfig:
        args.extend(["--kubeconfig", kubeconfig])
    if context:
        args.extend(["--context", context])

    result = run_command(args, timeout=60)
    if not result.success:
        logger.error(f"Failed to get pods: {result.stderr}")
        return []

    try:
        data = json.loads(result.stdout)
        images = set()

        for item in data.get("items", []):
            spec = item.get("spec", {})

            # Get images from containers
            for container in spec.get("containers", []):
                if image := container.get("image"):
                    images.add(image)

            # Get images from init containers
            for container in spec.get("initContainers", []):
                if image := container.get("image"):
                    images.add(image)

        return sorted(images)

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse kubectl output: {e}")
        return []


def load_ignore_patterns(ignore_file: str) -> List[str]:
    """Load ignore patterns from file (one pattern per line)."""
    patterns = []
    try:
        with open(ignore_file) as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith("#"):
                    patterns.append(line)
    except FileNotFoundError:
        logger.warning(f"Ignore file not found: {ignore_file}")
    return patterns


def filter_images(images: List[str], ignore_patterns: List[str]) -> List[str]:
    """Filter out images matching ignore patterns."""
    filtered = []
    for image in images:
        should_ignore = any(pattern in image for pattern in ignore_patterns)
        if not should_ignore:
            filtered.append(image)
    return filtered


def get_image_name(full_image: str) -> str:
    """Get image name without version/digest (for blob fetching)."""
    if "@" in full_image:
        return full_image.split("@")[0]
    if ":" in full_image:
        # Handle case like registry.io/image:tag
        parts = full_image.rsplit(":", 1)
        return parts[0]
    return full_image


def get_image_ref(full_image: str) -> str:
    """Get image reference without registry prefix."""
    parts = full_image.split("/")
    if len(parts) > 1:
        return "/".join(parts[1:])
    return full_image


def sanitize_filename(image: str) -> str:
    """Convert image name to safe filename."""
    return image.replace("/", "_").replace(":", "_").replace("@", "_")


def prepare_trivy_db(verbose: bool = False) -> bool:
    """
    Prepare Trivy database by cleaning and downloading a fresh DB into
    Trivy's default cache directory.

    The fresh DB is later copied into per-worker cache directories by
    `_get_worker_cache_dir()`, so all parallel workers reuse the same
    DB version without redownloading and without sharing a lock.

    Steps:
    1. trivy clean --all (clean existing db)
    2. trivy image --download-db-only (download fresh db)
    3. record the cache location so workers can copy from it

    Returns:
        True if successful
    """
    global _TRIVY_DB_SRC

    if verbose:
        logger.info("Cleaning existing Trivy database...")

    clean_args = ["trivy", "clean", "--all"]
    if not verbose:
        clean_args.append("--quiet")

    clean_result = run_command(clean_args, timeout=60)
    if not clean_result.success:
        if verbose:
            logger.warning(f"Failed to clean Trivy cache (may not exist): {clean_result.stderr}")
        # Continue anyway - might be first run

    if verbose:
        logger.info("Downloading Trivy vulnerability database...")

    download_args = ["trivy", "image", "--download-db-only"]
    if not verbose:
        download_args.append("--quiet")

    download_result = run_command(
        download_args,
        timeout=300,  # DB download can take a while
    )

    if not download_result.success:
        logger.error(f"Failed to download Trivy database: {download_result.stderr}")
        return False

    src = _trivy_default_cache_dir()
    if not (src / "db" / "trivy.db").is_file():
        logger.error(
            f"Trivy DB download succeeded but trivy.db not found under {src}/db; "
            "per-worker cache pool cannot be primed."
        )
        return False
    _TRIVY_DB_SRC = src

    if verbose:
        logger.info(f"Trivy database ready (source cache: {src})")

    return True


def run_trivy_scan(
    image: str,
    output_file: str,
    timeout: int = 600,
    verbose: bool = False,
) -> tuple[bool, Optional[str]]:
    """
    Run Trivy vulnerability scan on an image.

    Equivalent to: trivy image --scanners vuln --format json "$image"

    Uses a per-worker `--cache-dir` (lazy-initialized via
    `_get_worker_cache_dir()`) that has been pre-populated by copying the
    vuln DB downloaded once by `prepare_trivy_db()`. Combined with
    `--skip-db-update`, this gives us:

      * No DB redownloads (the previous per-image `--cache-dir` without any
        seeding made every worker redownload the entire vuln DB - the
        dominant wall-clock cost on larger image sets).
      * No BoltDB lock contention (sharing the default cache across workers
        made Trivy fail with "fs cache may be in use by another process").

    Returns:
        Tuple of (success, error_message)
    """
    cache_dir = _get_worker_cache_dir()

    args = [
        "trivy", "image",
        "--cache-dir", str(cache_dir),
        "--skip-db-update",
        "--scanners", "vuln",
        "--format", "json",
        "--output", output_file,
        "--timeout", f"{timeout}s",
        image,
    ]

    # Only suppress output when not in verbose mode
    if not verbose:
        args.insert(2, "--quiet")

    result = run_command(args, timeout=timeout + 30)

    if not result.success:
        error_msg = result.stderr.strip() if result.stderr else "Unknown error"
        if verbose:
            logger.error(f"Trivy scan failed for {image}:")
            logger.error(f"  Command: {' '.join(args)}")
            logger.error(f"  Exit code: {result.returncode}")
            if result.stderr:
                for line in result.stderr.strip().split('\n')[:10]:
                    logger.error(f"  {line}")
        return False, error_msg

    return True, None


def extract_relevant_cves(trivy_json_file: str, min_cve_level: str = "MEDIUM") -> Set[str]:
    """
    Extract CVE IDs from Trivy JSON output based on minimum severity level.

    Args:
        trivy_json_file: Path to Trivy JSON output file
        min_cve_level: Minimum CVE level to include (LOW, MEDIUM, HIGH, CRITICAL)

    Returns:
        Set of CVE IDs matching the severity threshold
    """
    cves = set()
    min_level = min_cve_level.upper()

    # Define severity hierarchy
    severity_levels = {
        "CRITICAL": ["CRITICAL"],
        "HIGH": ["HIGH", "CRITICAL"],
        "MEDIUM": ["MEDIUM", "HIGH", "CRITICAL"],
        "LOW": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    }

    # Get list of severities to include
    included_severities = severity_levels.get(min_level, ["HIGH", "CRITICAL"])

    try:
        with open(trivy_json_file) as f:
            data = json.load(f)

        for result in data.get("Results", []):
            vulns = result.get("Vulnerabilities") or []
            for vuln in vulns:
                severity = vuln.get("Severity", "").upper()
                if severity in included_severities:
                    cve_id = vuln.get("VulnerabilityID")
                    if cve_id:
                        cves.add(cve_id)

    except (json.JSONDecodeError, FileNotFoundError) as e:
        logger.debug(f"Failed to parse Trivy output: {e}")

    return cves


# Keep old function name for backward compatibility
def extract_high_critical_cves(trivy_json_file: str) -> Set[str]:
    """Legacy function - use extract_relevant_cves instead."""
    return extract_relevant_cves(trivy_json_file, min_cve_level="HIGH")


def find_triage_reference(
    image: str,
    timeout: int = 180,
    verbose: bool = False,
) -> Optional[str]:
    """
    Find ORAS referrer containing triage.toml.

    Equivalent to bash: jq -r '.referrers[] | [.reference, (.annotations.content // "")] | @tsv'
                        then checking if content contains "triage.toml"
    """
    # Try oras discover
    result = run_command(
        ["oras", "discover", image, "--format", "json"],
        timeout=timeout,
    )

    if not result.success:
        # Fallback with --plain-http
        result = run_command(
            ["oras", "discover", image, "--format", "json", "--plain-http"],
            timeout=timeout,
        )
        if not result.success:
            if verbose:
                logger.debug(f"No ORAS referrers found for {image}: {result.stderr}")
            return None

    try:
        data = json.loads(result.stdout)
        referrers = data.get("referrers", [])

        for ref in referrers:
            reference = ref.get("reference")
            annotations = ref.get("annotations", {})
            content = annotations.get("content", "")

            if "triage.toml" in content:
                return reference

    except json.JSONDecodeError:
        pass

    return None


def fetch_triage_toml(
    image: str,
    triage_reference: str,
    output_file: str,
    manifest_file: str,
    timeout: int = 180,
) -> bool:
    """
    Fetch triage.toml blob from ORAS.

    Equivalent to:
        oras manifest fetch $triage_reference > manifest.json
        manifest_digest=$(jq -r '.layers[0].digest' manifest.json)
        oras blob fetch --output triage.toml "$image_name@$manifest_digest"
    """
    # Fetch manifest
    result = run_command(
        ["oras", "manifest", "fetch", triage_reference],
        timeout=timeout,
    )

    if not result.success:
        return False

    # Save manifest
    try:
        manifest = json.loads(result.stdout)
        with open(manifest_file, "w") as f:
            json.dump(manifest, f, indent=2)

        # Get layer digest
        layers = manifest.get("layers", [])
        if not layers:
            return False

        layer_digest = layers[0].get("digest")
        if not layer_digest:
            return False

    except (json.JSONDecodeError, KeyError, IndexError):
        return False

    # Fetch blob
    image_name = get_image_name(image)
    result = run_command(
        ["oras", "blob", "fetch", f"{image_name}@{layer_digest}",
         "--output", output_file],
        timeout=timeout,
    )

    if not result.success:
        return False

    # Verify file is not empty
    if not Path(output_file).exists() or Path(output_file).stat().st_size == 0:
        Path(output_file).unlink(missing_ok=True)
        return False

    return True


def parse_triage_toml(triage_file: str) -> Set[str]:
    """
    Parse CVE IDs from triage.toml file.

    Equivalent to bash:
        grep -v '^[[:space:]]*#' "$triage_file" |
        grep -o '\\(only: \\)?\\[trivy\\.[A-Z0-9\\-]*\\]' |
        grep -o 'trivy\\.[A-Z0-9\\-]*' |
        sed 's/trivy\\.//'
    """
    cves = set()

    try:
        with open(triage_file) as f:
            content = f.read()

        # Remove comment lines
        lines = [line for line in content.split("\n")
                 if not line.strip().startswith("#")]
        content = "\n".join(lines)

        # Pattern: [trivy.CVE-XXXX-XXXX] or only: [trivy.CVE-XXXX-XXXX]
        pattern = r'\[trivy\.(CVE-[A-Z0-9\-]+)\]'

        for match in re.finditer(pattern, content):
            cves.add(match.group(1))

    except FileNotFoundError:
        pass

    return cves


def scan_image(
    image: str,
    output_dir: Path,
    timeout: int = 300,
    verbose: bool = False,
    min_cve_level: str = "MEDIUM",
) -> ImageScanResult:
    """
    Scan a single image - equivalent to one iteration of 2-oras-scan.sh loop.
    """
    result = ImageScanResult(
        image=image,
        image_ref=get_image_ref(image),
    )

    # Create output directory
    image_filename = sanitize_filename(image)
    image_dir = output_dir / image_filename
    image_dir.mkdir(parents=True, exist_ok=True)
    result.output_dir = str(image_dir)

    # Save image reference
    (image_dir / "image.txt").write_text(result.image_ref)

    # Run Trivy scan
    trivy_output = image_dir / "cosign-scan.json"
    success, error_msg = run_trivy_scan(image, str(trivy_output), timeout, verbose)
    if not success:
        result.error = f"Trivy scan failed: {error_msg}" if error_msg else "Trivy scan failed"
        # Create empty files
        (image_dir / "cosign-scan.json").write_text("[]")
        (image_dir / "high-critical-cves.txt").write_text("")
        # Save error to file for debugging
        (image_dir / "error.txt").write_text(result.error)
        return result

    # Extract relevant CVEs based on min_cve_level
    result.high_critical_cves = extract_relevant_cves(str(trivy_output), min_cve_level)
    (image_dir / "high-critical-cves.txt").write_text(
        "\n".join(sorted(result.high_critical_cves))
    )

    # Find and fetch triage.toml
    triage_ref = find_triage_reference(image, verbose=verbose)

    if triage_ref:
        triage_file = image_dir / "triage.toml"
        manifest_file = image_dir / "manifest.json"

        if fetch_triage_toml(
            image, triage_ref, str(triage_file), str(manifest_file)
        ):
            result.has_triage = True
            result.triage_file = str(triage_file)
            result.triaged_cves = parse_triage_toml(str(triage_file))
            (image_dir / "triaged-cves.txt").write_text(
                "\n".join(sorted(result.triaged_cves))
            )

    result.success = True
    return result


def generate_markdown_report(
    results: List[ImageScanResult],
    filter_unaddressed: bool = False,
    filter_missing_triage: bool = False,
    namespace: str = "N/A",
    min_cve_level: str = "MEDIUM",
) -> str:
    """
    Generate beautiful Markdown vulnerability report.

    Equivalent to 3-gen-report.sh but with enhanced formatting.
    """
    lines = []
    # Sort alphabetically by image basename so the rendered order matches the
    # displayed `<image>:<tag>` cells (the project prefix is stripped at render
    # time). Sorting is stable across runs regardless of scan-completion order.
    results = sorted(results, key=lambda r: r.image.rsplit("/", 1)[-1].lower())
    successful = [r for r in results if r.success]
    failed = [r for r in results if not r.success]

    # Calculate totals first for summary
    total_unaddressed_cves = sum(len(r.unaddressed_cves) for r in successful)
    total_addressed_cves = sum(len(r.addressed_cves) for r in successful)
    total_irrelevant_cves = sum(len(r.irrelevant_cves) for r in successful)
    images_with_unaddressed = sum(1 for r in successful if r.unaddressed_cves)
    images_with_missing_triage = sum(1 for r in successful if not r.has_triage)
    images_with_triage = sum(1 for r in successful if r.has_triage)

    # Header with status badge
    lines.append("# 🔍 ORAS SCAN CVE Analysis Summary")
    lines.append("")

    if total_unaddressed_cves == 0:
        lines.append(f"> 🎉 **All {min_cve_level} and above CVEs have been addressed!**")
    else:
        lines.append(f"> ⚠️ **{total_unaddressed_cves} unaddressed CVEs (≥{min_cve_level}) across {images_with_unaddressed} images need attention**")
    lines.append("")

    # Scan info table
    lines.append("## 📊 Scan Overview")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|------:|")
    lines.append(f"| **Image source** | `{namespace}` |")
    lines.append(f"| **Scan Date** | {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC |")
    lines.append(f"| **Minimum CVE Level** | `{min_cve_level}` |")
    lines.append(f"| **Total Images** | {len(successful)} |")
    lines.append(f"| **Failed Scans** | {len(failed)} |")
    lines.append(f"| **Images with Triage** | {images_with_triage} |")
    lines.append(f"| **Images Missing Triage** | {images_with_missing_triage} |")
    lines.append("")

    # CVE Statistics
    lines.append("## 📈 CVE Statistics")
    lines.append("")
    lines.append("| Category | Count | Description |")
    lines.append("|----------|------:|-------------|")
    lines.append(f"| 🔴 **Unaddressed** | **{total_unaddressed_cves}** | {min_cve_level}+ CVEs not in triage |")
    lines.append(f"| ✅ **Addressed** | {total_addressed_cves} | {min_cve_level}+ CVEs covered by triage |")
    lines.append(f"| ⚪ **Irrelevant** | {total_irrelevant_cves} | Triaged CVEs not detected or below {min_cve_level} |")
    lines.append("")

    # Main vulnerability table
    lines.append("## 🛡️ Image Analysis")
    lines.append("")

    # Filter info
    if filter_unaddressed and filter_missing_triage:
        lines.append("> **Filter:** Showing images with unaddressed CVEs OR missing triage files")
    elif filter_unaddressed:
        lines.append("> **Filter:** Showing only images with unaddressed CVEs")
    elif filter_missing_triage:
        lines.append("> **Filter:** Showing only images with missing triage files")
    lines.append("")

    # Table header
    lines.append("| Image | Status | Unaddressed | Addressed | Triage |")
    lines.append("|-------|:------:|:-----------:|:---------:|:------:|")

    displayed_count = 0
    hidden_clean_count = 0  # Images with no triage AND no CVEs

    for result in successful:
        has_unaddressed = len(result.unaddressed_cves) > 0
        has_any_cves = len(result.high_critical_cves) > 0

        # Hide images with no triage AND no vulnerabilities (nothing to report)
        if not result.has_triage and not has_any_cves:
            hidden_clean_count += 1
            continue

        # Apply user filters
        show_entry = True
        if filter_unaddressed or filter_missing_triage:
            show_entry = False
            if filter_unaddressed and has_unaddressed:
                show_entry = True
            if filter_missing_triage and not result.has_triage:
                show_entry = True

        if not show_entry:
            continue

        displayed_count += 1

        # Show only the image basename (`<image>:<tag>`); strip the project
        # segment from result.image_ref. Reports list 30-40 images at a time
        # and the project prefix is the same for almost all of them, so it
        # adds noise without signal. Truncate very long refs (> 45 chars).
        image_name = result.image_ref.rsplit("/", 1)[-1]
        if len(image_name) > 45:
            image_name = image_name[:42] + "..."

        # Status icon: 🔴 = has unaddressed CVEs, ✅ = all clear
        status = "🔴" if has_unaddressed else "✅"

        # CVE counts with formatting
        unaddressed_count = len(result.unaddressed_cves)
        addressed_count = len(result.addressed_cves)

        if unaddressed_count > 0:
            unaddressed_str = f"**{unaddressed_count}**"
        else:
            unaddressed_str = "0"

        triage_str = "✅" if result.has_triage else "❌"

        lines.append(f"| `{image_name}` | {status} | {unaddressed_str} | {addressed_count} | {triage_str} |")

    lines.append("")
    if hidden_clean_count > 0:
        lines.append(f"*Showing {displayed_count} of {len(successful)} images ({hidden_clean_count} clean images without triage hidden)*")
    else:
        lines.append(f"*Showing {displayed_count} of {len(successful)} images*")
    lines.append("")

    # Detailed CVE breakdown (if there are unaddressed CVEs)
    if total_unaddressed_cves > 0:
        lines.append("## 🔴 Unaddressed CVEs Detail")
        lines.append("")
        lines.append("<details>")
        lines.append("<summary>Click to expand CVE details</summary>")
        lines.append("")

        for result in successful:
            if result.unaddressed_cves:
                lines.append(f"### `{result.image_ref}`")
                lines.append("")
                for cve in sorted(result.unaddressed_cves):
                    lines.append(f"- {cve}")
                lines.append("")

        lines.append("</details>")
        lines.append("")

    # Failed scans section
    if failed:
        lines.append("## ❌ Failed Scans")
        lines.append("")
        lines.append("<details>")
        lines.append("<summary>Click to expand failed scan details</summary>")
        lines.append("")
        for result in failed:
            lines.append(f"- `{result.image}`: {result.error or 'Unknown error'}")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append("*Generated by `scanner-py oras-scan`*")

    return "\n".join(lines)


def print_cli_summary(
    results: List[ImageScanResult],
    namespace: str = "N/A",
    filter_unaddressed: bool = False,
    filter_missing_triage: bool = False,
    min_cve_level: str = "MEDIUM",
) -> None:
    """Print beautiful summary to CLI matching the markdown report format."""
    results = sorted(results, key=lambda r: r.image.rsplit("/", 1)[-1].lower())
    successful = [r for r in results if r.success]
    failed = [r for r in results if not r.success]

    total_unaddressed = sum(len(r.unaddressed_cves) for r in successful)
    total_addressed = sum(len(r.addressed_cves) for r in successful)
    total_irrelevant = sum(len(r.irrelevant_cves) for r in successful)
    images_with_triage = sum(1 for r in successful if r.has_triage)
    images_with_missing_triage = sum(1 for r in successful if not r.has_triage)
    images_with_unaddressed = sum(1 for r in successful if r.unaddressed_cves)

    print()
    print("━" * 100)
    print("🔍 VULNERABILITY TRIAGE REPORT")
    print("━" * 100)
    print()

    # Status banner
    if total_unaddressed == 0:
        print(f"  🎉 All {min_cve_level} and above CVEs have been addressed!")
    else:
        print(f"  ⚠️  {total_unaddressed} unaddressed CVEs (≥{min_cve_level}) across {images_with_unaddressed} images need attention")
    print()

    # Scan Overview
    print("┌─────────────────────────────────────────────────────────────────────────────┐")
    print("│ 📊 SCAN OVERVIEW                                                            │")
    print("├─────────────────────────────────────────────────────────────────────────────┤")
    print(f"│  Namespace:              {namespace:<50} │")
    print(f"│  Minimum CVE Level:      {min_cve_level:<50} │")
    print(f"│  Total Images:           {len(successful):<50} │")
    print(f"│  Failed Scans:           {len(failed):<50} │")
    print(f"│  Images with Triage:     {images_with_triage:<50} │")
    print(f"│  Images Missing Triage:  {images_with_missing_triage:<50} │")
    print("└─────────────────────────────────────────────────────────────────────────────┘")
    print()

    # CVE Statistics
    print("┌─────────────────────────────────────────────────────────────────────────────┐")
    print("│ 📈 CVE STATISTICS                                                           │")
    print("├─────────────────────────────────────────────────────────────────────────────┤")
    print(f"│  🔴 Unaddressed:  {total_unaddressed:<8} {min_cve_level}+ CVEs not in triage                      │")
    print(f"│  ✅ Addressed:    {total_addressed:<8} {min_cve_level}+ CVEs covered by triage                     │")
    print(f"│  ⚪ Irrelevant:   {total_irrelevant:<8} Triaged CVEs not detected or below {min_cve_level:<10} │")
    print("└─────────────────────────────────────────────────────────────────────────────┘")
    print()

    # Image Analysis Table
    print("┌─────────────────────────────────────────────────────────────────────────────────────────────────┐")
    print("│ 🛡️  IMAGE ANALYSIS                                                                              │")
    print("├─────────────────────────────────────────────────────────────────────────────────────────────────┤")

    # Filter info
    if filter_unaddressed and filter_missing_triage:
        print("│  Filter: Showing images with unaddressed CVEs OR missing triage files                         │")
    elif filter_unaddressed:
        print("│  Filter: Showing only images with unaddressed CVEs                                            │")
    elif filter_missing_triage:
        print("│  Filter: Showing only images with missing triage files                                        │")

    print("├─────────────────────────────────────────────────────────────────────────────────────────────────┤")

    # Table header
    print(f"│ {'Image':<105} {'Status':^8} {'Unaddr':^8} {'Addr':^8} {'Triage':^8} │")
    print("├─────────────────────────────────────────────────────────────────────────────────────────────────┤")

    displayed = 0
    hidden_clean = 0
    for result in successful:
        has_unaddressed = len(result.unaddressed_cves) > 0
        has_any_cves = len(result.high_critical_cves) > 0

        # Hide images with no triage AND no vulnerabilities (nothing to report)
        if not result.has_triage and not has_any_cves:
            hidden_clean += 1
            continue

        # Apply user filters
        show_entry = True
        if filter_unaddressed or filter_missing_triage:
            show_entry = False
            if filter_unaddressed and has_unaddressed:
                show_entry = True
            if filter_missing_triage and not result.has_triage:
                show_entry = True

        if not show_entry:
            continue

        displayed += 1

        # Show only the basename (`<image>:<tag>`); strip project segment.
        image_name = result.image_ref.rsplit("/", 1)[-1]
        if len(image_name) > 43:
            image_name = image_name[:40] + "..."

        # Status icon: 🔴 = has unaddressed CVEs, ✅ = all clear
        status = "🔴" if has_unaddressed else "✅"

        unaddressed_count = len(result.unaddressed_cves)
        addressed_count = len(result.addressed_cves)
        triage_str = "✅" if result.has_triage else "❌"

        print(f"│ {image_name:<45} {status:^8} {unaddressed_count:^8} {addressed_count:^8} {triage_str:^8} │")

    print("└─────────────────────────────────────────────────────────────────────────────────────────────────┘")
    if hidden_clean > 0:
        print(f"  Showing {displayed} of {len(successful)} images ({hidden_clean} clean images without triage hidden)")
    else:
        print(f"  Showing {displayed} of {len(successful)} images")
    print()

    # Failed scans details
    if failed:
        print("┌─────────────────────────────────────────────────────────────────────────────┐")
        print("│ ❌ FAILED SCANS                                                             │")
        print("├─────────────────────────────────────────────────────────────────────────────┤")
        for result in failed[:5]:  # Show max 5
            error_msg = (result.error or "Unknown error")[:60]
            print(f"│  • {result.image[:40]:<40}                              │")
            print(f"│    Error: {error_msg:<63} │")
        if len(failed) > 5:
            print(f"│  ... and {len(failed) - 5} more                                                       │")
        print("└─────────────────────────────────────────────────────────────────────────────┘")
        print()

    # Unaddressed CVEs detail (if any)
    if total_unaddressed > 0 and total_unaddressed <= 20:
        print("┌─────────────────────────────────────────────────────────────────────────────┐")
        print("│ 🔴 UNADDRESSED CVEs DETAIL                                                  │")
        print("├─────────────────────────────────────────────────────────────────────────────┤")
        for result in successful:
            if result.unaddressed_cves:
                print(f"│  {result.image_ref[:70]:<71} │")
                for cve in sorted(result.unaddressed_cves)[:5]:
                    print(f"│    • {cve:<67} │")
                if len(result.unaddressed_cves) > 5:
                    print(f"│    ... and {len(result.unaddressed_cves) - 5} more CVEs                                                   │")
        print("└─────────────────────────────────────────────────────────────────────────────┘")
        print()


def load_results_from_dir(output_dir: Path) -> List[ImageScanResult]:
    """Load scan results from existing output directory."""
    results = []

    if not output_dir.exists():
        return results

    for image_dir in output_dir.iterdir():
        if not image_dir.is_dir():
            continue

        # Read image name
        image_file = image_dir / "image.txt"
        if not image_file.exists():
            continue

        image_ref = image_file.read_text().strip()

        result = ImageScanResult(
            image=image_dir.name,  # sanitized name
            image_ref=image_ref,
            output_dir=str(image_dir),
        )

        # Read relevant CVEs (based on min_cve_level)
        cve_file = image_dir / "high-critical-cves.txt"
        if cve_file.exists():
            content = cve_file.read_text().strip()
            if content:
                result.high_critical_cves = set(content.split("\n"))

        # Read triaged CVEs
        triaged_file = image_dir / "triaged-cves.txt"
        if triaged_file.exists():
            content = triaged_file.read_text().strip()
            if content:
                result.triaged_cves = set(content.split("\n"))

        # Check triage file
        triage_file = image_dir / "triage.toml"
        if triage_file.exists() and triage_file.stat().st_size > 0:
            result.has_triage = True
            result.triage_file = str(triage_file)

        result.success = True
        results.append(result)

    return results


def run_oras_scan(args: argparse.Namespace) -> int:
    """
    Run triage scan - main entry point.

    Equivalent to running all three oras-scan bash scripts.
    """
    # Setup logging
    log_level = LogLevel.VERBOSE if args.verbose else LogLevel.INFO
    setup_logging(log_level)

    output_dir = Path(args.output_dir)

    # Report-only mode: just generate report from existing results
    if args.report_only:
        print("📊 Generating report from existing scan results...")
        results = load_results_from_dir(output_dir)

        if not results:
            print(f"❌ No scan results found in {output_dir}", file=sys.stderr)
            return 1

        print_cli_summary(
            results,
            namespace=args.namespace,
            filter_unaddressed=args.filter_unaddressed,
            filter_missing_triage=args.filter_missing_triage,
            min_cve_level=args.min_cve_level,
        )

        report = generate_markdown_report(
            results,
            filter_unaddressed=args.filter_unaddressed,
            filter_missing_triage=args.filter_missing_triage,
            namespace=args.namespace,
            min_cve_level=args.min_cve_level,
        )

        if args.output:
            Path(args.output).write_text(report)
            print(f"📄 Report saved to: {args.output}")

        return 0

    # Check prerequisites
    for tool in ["kubectl", "trivy", "oras", "jq"]:
        result = run_command(["which", tool], timeout=5)
        if not result.success:
            print(f"❌ Missing required tool: {tool}", file=sys.stderr)
            return 1

    # Print header
    print("🔍 ORAS Scan - Vulnerability Scanner")
    print()
    print("⚙️  Configuration:")
    print(f"   • Namespace: {args.namespace}")
    print(f"   • Output: {args.output_dir}")
    print(f"   • Parallel: {args.parallel}")
    print(f"   • Minimum CVE Level: {args.min_cve_level}")
    print()

    # Step 1: Get images from Kubernetes
    spinner = Spinner("Getting images from Kubernetes...")
    spinner.spin()

    images = get_images_from_kubernetes(
        args.namespace,
        kubeconfig=args.kubeconfig,
        context=args.context,
    )

    if not images:
        spinner.finish("No images found", success=False)
        return 1

    spinner.finish(f"Found {len(images)} unique images")

    # Apply ignore patterns
    if args.ignore_file:
        ignore_patterns = load_ignore_patterns(args.ignore_file)
        original_count = len(images)
        images = filter_images(images, ignore_patterns)
        ignored = original_count - len(images)
        print(f"📂 Loaded {len(ignore_patterns)} ignore patterns ({ignored} images filtered)")

    if not images:
        print("⚠️  No images to scan after filtering")
        return 0

    # Prepare output directory
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Prepare Trivy database (clean + download fresh)
    spinner = Spinner("Preparing Trivy vulnerability database...")
    spinner.spin()
    if not prepare_trivy_db(verbose=args.verbose):
        spinner.finish("Failed to prepare Trivy database", success=False)
        return 1
    spinner.finish("Trivy database ready")

    # Step 2: Scan images
    print()
    results: List[ImageScanResult] = []

    progress = ProgressBar(
        len(images),
        "Scanning images",
        ProgressStyle(width=30),
    )

    with ThreadPoolExecutor(max_workers=args.parallel) as executor:
        futures = {
            executor.submit(scan_image, image, output_dir, args.timeout, args.verbose, args.min_cve_level): image
            for image in images
        }

        for future in as_completed(futures):
            image = futures[future]
            try:
                result = future.result()
                results.append(result)

                status = "success" if result.success else "failed"
                progress.update(status=status, current_item=image.split("/")[-1])

            except Exception as e:
                logger.error(f"Error scanning {image}: {e}")
                results.append(ImageScanResult(
                    image=image,
                    image_ref=get_image_ref(image),
                    error=str(e),
                ))
                progress.update(status="failed", current_item=image.split("/")[-1])

    progress.finish()

    # Print CLI summary
    print_cli_summary(
        results,
        namespace=args.namespace,
        filter_unaddressed=args.filter_unaddressed,
        filter_missing_triage=args.filter_missing_triage,
        min_cve_level=args.min_cve_level,
    )

    # Step 3: Generate report (unless scan-only mode)
    if not args.scan_only:
        report = generate_markdown_report(
            results,
            filter_unaddressed=args.filter_unaddressed,
            filter_missing_triage=args.filter_missing_triage,
            namespace=args.namespace,
            min_cve_level=args.min_cve_level,
        )

        if args.output:
            Path(args.output).write_text(report)
            print(f"📄 Report saved to: {args.output}")
        else:
            print()
            print(report)

    print()
    print("✅ ORAS scan completed!")

    return 0
