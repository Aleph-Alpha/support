"""CLI for Kubernetes image scanning.

Equivalent to k8s-image-scanner.sh
"""

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, List, Tuple

from ..core.scanner import ImageScanner
from ..core.kubernetes import KubernetesImageExtractor, KubernetesConfig
from ..core.cache import ScanCache, reset_digest_cache
from ..core.chainguard import ChainguardVerifier
from ..models.scan_result import ScanResult, ScanSummary
from ..utils.logging import setup_logging, LogLevel, get_logger, is_verbose, suppress_logging, restore_logging
from ..utils.subprocess import check_prerequisites, run_command
from ..utils.registry import RegistryChecker
from ..utils.progress import ProgressBar, ProgressStyle, Spinner

logger = get_logger(__name__)


def prepare_trivy_db(verbose: bool = False) -> bool:
    """
    Prepare Trivy database by cleaning and downloading fresh DB.
    
    This should be run once before parallel scans to avoid race conditions
    and ensure all scans use the same database version.
    
    Steps:
    1. trivy clean --all (clean existing db)
    2. trivy image --download-db-only (download fresh db)
    
    Returns:
        True if successful
    """
    # Step 1: Clean existing database
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
    
    # Step 2: Download fresh database
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
    
    if verbose:
        logger.info("Trivy database ready")
    
    return True


def create_k8s_scanner_parser(subparsers: Any) -> argparse.ArgumentParser:
    """Create the cosign-scan subparser."""
    parser = subparsers.add_parser(
        "cosign-scan",
        help="Scan images from a Kubernetes namespace",
        description="""
Scan all container images in a Kubernetes namespace.

Connects to Kubernetes, extracts signed images from a namespace,
downloads SBOM attestations, downloads triage attestations, and runs
Trivy vulnerability scans on the SBOMs with triage filtering applied.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan default namespace with default settings
  scanner-py cosign-scan

  # Scan specific namespace with ignore file
  scanner-py cosign-scan --namespace production --ignore-file ./ignore-images.txt

  # Scan with custom output directory and parallel scans
  scanner-py cosign-scan --namespace staging --output-dir ./reports --parallel-scans 10

  # Dry run to see what would be scanned
  scanner-py cosign-scan --namespace production --dry-run

  # Test flow - only scan first valid image
  scanner-py cosign-scan --namespace production --test-flow
""",
    )

    # Kubernetes options
    parser.add_argument(
        "--namespace",
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

    # Scanning options
    parser.add_argument(
        "--ignore-file",
        help="File containing images to ignore (one per line)",
    )
    parser.add_argument(
        "--output-dir",
        default="./scan-results",
        help="Output directory for reports (default: ./scan-results)",
    )
    parser.add_argument(
        "--parallel-scans",
        type=int,
        default=10,
        help="Number of parallel scans (default: 10)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Timeout for operations in seconds (default: 300)",
    )

    # Verification options
    parser.add_argument(
        "--certificate-oidc-issuer",
        help="OIDC issuer for cosign verification",
    )
    parser.add_argument(
        "--certificate-identity-regexp",
        help="Identity regexp for cosign verification",
    )

    # Output options
    parser.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default="table",
        help="Report format (default: table)",
    )
    parser.add_argument(
        "--severity",
        default="LOW,MEDIUM,HIGH,CRITICAL",
        help="Comma-separated severity levels (default: LOW,MEDIUM,HIGH,CRITICAL)",
    )
    parser.add_argument(
        "--min-cve-level",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="HIGH",
        help="Minimum CVE level to consider relevant (default: HIGH)",
    )
    parser.add_argument(
        "--markdown-output", "-o",
        help="Path for Markdown summary file (default: <output-dir>/cosign-cve-summary.md)",
    )
    parser.add_argument(
        "--summary-json",
        help="Path for JSON summary file (default: <output-dir>/scan-summary.json)",
    )
    parser.add_argument(
        "--append",
        action="store_true",
        help="Append to existing Markdown file (for combining CI step outputs)",
    )

    # Cache options
    parser.add_argument(
        "--cache-dir",
        help="Cache directory",
    )
    parser.add_argument(
        "--cache-ttl",
        type=int,
        default=24,
        help="Cache TTL in hours (default: 24)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable caching",
    )
    parser.add_argument(
        "--clear-cache",
        action="store_true",
        help="Clear cache before running",
    )
    parser.add_argument(
        "--cache-stats",
        action="store_true",
        help="Show cache statistics and exit",
    )

    # Mode options
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging (shows errors and debug info)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be scanned without executing",
    )
    parser.add_argument(
        "--test-flow",
        action="store_true",
        help="Only scan the first valid image (for testing)",
    )
    parser.add_argument(
        "--trivy-config",
        help="Custom Trivy configuration file",
    )

    return parser


def run_cosign_scanner(args: argparse.Namespace) -> int:
    """
    Run Kubernetes namespace scanner.

    Args:
        args: Parsed command line arguments

    Returns:
        Exit code
    """
    import time
    start_time = time.time()
    
    # Setup logging - errors only shown in verbose mode
    log_level = LogLevel.VERBOSE if args.verbose else LogLevel.INFO
    setup_logging(log_level, show_errors=args.verbose)

    # Initialize cache
    cache = ScanCache(
        cache_dir=args.cache_dir,
        ttl_hours=args.cache_ttl,
        enabled=not args.no_cache,
    )

    # Handle cache stats
    if args.cache_stats:
        cache.init()
        cache.print_stats()
        return 0

    # Clear cache if requested
    if args.clear_cache:
        cache.init()
        cache.clear()

    # Check prerequisites
    missing = check_prerequisites([
        "kubectl", "trivy", "jq", "cosign", "docker", "crane", "oras"
    ])
    if missing:
        print(f"❌ Missing required tools: {', '.join(missing)}", file=sys.stderr)
        return 1

    # Print header
    print("🚀 Aleph Alpha - Cosign Image Scanner")
    print()
    print("⚙️  Configuration:")
    print(f"   • Namespace: {args.namespace}")
    print(f"   • Output: {args.output_dir}")

    if args.no_cache:
        print("   • Cache: Disabled")
    else:
        print(f"   • Cache: Enabled (TTL: {args.cache_ttl}h)")

    if args.dry_run:
        print("   • Mode: DRY RUN")
    if args.test_flow:
        print("   • Mode: TEST FLOW")
    if args.verbose:
        print("   • Verbose: Enabled (showing errors)")
    print()

    # Initialize cache
    cache.init()

    # Setup Kubernetes connection
    k8s_config = KubernetesConfig(
        namespace=args.namespace,
        kubeconfig=args.kubeconfig,
        context=args.context,
    )
    k8s_extractor = KubernetesImageExtractor(config=k8s_config)

    # Test connectivity with spinner
    spinner = Spinner("Testing Kubernetes connectivity...")
    spinner.spin()
    if not k8s_extractor.test_connectivity():
        spinner.finish("Failed to connect to Kubernetes cluster", success=False)
        return 1
    spinner.finish(f"Connected to namespace: {args.namespace}", success=True)

    # Load ignore patterns
    ignore_patterns = []
    if args.ignore_file:
        ignore_patterns = k8s_extractor.load_ignore_patterns(args.ignore_file)
        print(f"📂 Loaded {len(ignore_patterns)} ignore patterns")

    # Setup registry checker
    registry_checker = RegistryChecker()

    # Extract images with spinner
    spinner = Spinner("Discovering images...")
    spinner.spin()
    extraction_result = k8s_extractor.extract_images(
        ignore_patterns=ignore_patterns,
        registry_checker=registry_checker.is_registry_accessible,
    )
    spinner.finish(f"Found {len(extraction_result.images)} images to scan", success=True)

    if not extraction_result.images:
        print("⚠️  No images found to scan")
        return 0

    # Show summary of ignored/inaccessible
    if extraction_result.ignored_count > 0:
        print(f"   🚫 {extraction_result.ignored_count} ignored")
    if extraction_result.inaccessible_count > 0:
        print(f"   🚫 {extraction_result.inaccessible_count} from inaccessible registries")

    # Create output directory
    output_dir = Path(args.output_dir)
    if not args.dry_run:
        if output_dir.exists():
            import shutil
            shutil.rmtree(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

    # Dry run - just show images
    if args.dry_run:
        print()
        print(f"[DRY RUN] Would process {len(extraction_result.images)} images:")
        for img in extraction_result.images:
            print(f"     • {img}")
        return 0

    # Pre-download Trivy DB to avoid race conditions in parallel scans
    # This ensures all parallel scans use the same DB version
    spinner = Spinner("Preparing Trivy vulnerability database...")
    spinner.spin()
    if not prepare_trivy_db(verbose=args.verbose):
        spinner.finish("Failed to prepare Trivy database", success=False)
        print("❌ Error: Could not download Trivy vulnerability database")
        return 1
    spinner.finish("Trivy database ready", success=True)

    # Create scanner with skip_db_update=True since we pre-downloaded the DB
    scanner = ImageScanner(
        output_dir=str(output_dir),
        format=args.format,
        severity_level=args.min_cve_level,
        min_cve_level=args.min_cve_level,
        timeout=args.timeout,
        certificate_oidc_issuer=args.certificate_oidc_issuer,
        certificate_identity_regexp=args.certificate_identity_regexp,
        trivy_config=args.trivy_config,
        verbose=args.verbose,
        skip_db_update=True,
    )

    # Process images
    results: List[ScanResult] = []
    images_to_scan = extraction_result.images

    print()

    # Suppress logging during progress bar to prevent interference (only in non-verbose mode)
    prev_log_level = None
    if not args.verbose:
        prev_log_level = suppress_logging()

    try:
        # Test flow - only first valid image
        if args.test_flow:
            if prev_log_level is not None:
                restore_logging(prev_log_level)  # Restore for test flow message
            print("📋 TEST FLOW: Processing only the first valid image")
            if not args.verbose:
                prev_log_level = suppress_logging()
            
            progress = ProgressBar(
                len(images_to_scan),
                "Test scan",
                ProgressStyle(width=25),
            )
            for image in images_to_scan:
                result = scanner.scan(image)
                results.append(result)
                
                status = "success" if result.success else ("skipped" if result.skipped else "failed")
                progress.update(status=status, current_item=image.split("/")[-1])
                
                if result.success and not result.skipped:
                    break
            
            progress.finish()
        else:
            # Parallel scanning with progress bar
            progress = ProgressBar(
                len(images_to_scan),
                "Scanning images",
                ProgressStyle(width=30),
            )

            with ThreadPoolExecutor(max_workers=args.parallel_scans) as executor:
                futures = {
                    executor.submit(scanner.scan, image): image
                    for image in images_to_scan
                }

                for future in as_completed(futures):
                    image = futures[future]
                    try:
                        result = future.result()
                        results.append(result)
                        
                        if result.success:
                            status = "success"
                        elif result.skipped:
                            status = "skipped"
                        else:
                            status = "failed"
                        
                        progress.update(status=status, current_item=image.split("/")[-1])
                        
                    except Exception as e:
                        results.append(ScanResult(
                            image=image,
                            success=False,
                            error=str(e),
                        ))
                        progress.update(status="failed", current_item=image.split("/")[-1])

            progress.finish()
    finally:
        # Always restore logging if it was suppressed
        if prev_log_level is not None:
            restore_logging(prev_log_level)

    # Check Chainguard base images BEFORE generating summary (PARALLEL with spinner)
    successful_results = [r for r in results if r.success and not r.skipped]
    if successful_results:
        # Suppress logging during spinner (only in non-verbose mode)
        prev_log_level = None
        if not args.verbose:
            prev_log_level = suppress_logging()
        
        try:
            spinner = Spinner("Checking Chainguard base images...")
            spinner.spin()
            chainguard_verifier = ChainguardVerifier()
            
            def check_chainguard(result: ScanResult) -> Tuple[ScanResult, Any]:
                """Check Chainguard for a single result."""
                try:
                    cg_result = chainguard_verifier.verify(result.image, fail_on_mismatch=False)
                    return result, cg_result
                except Exception:
                    return result, None
            
            # Run Chainguard checks in parallel
            with ThreadPoolExecutor(max_workers=min(len(successful_results), 5)) as executor:
                futures = {
                    executor.submit(check_chainguard, result): result
                    for result in successful_results
                }
                
                completed = 0
                for future in as_completed(futures):
                    result, cg_result = future.result()
                    completed += 1
                    
                    if cg_result:
                        result.is_chainguard = cg_result.is_chainguard
                        result.base_image = cg_result.base_image
                        result.signature_verified = cg_result.signature_verified
                    else:
                        result.is_chainguard = False
                        result.base_image = "unknown"
                        result.signature_verified = False
                    
                    spinner.update(f"Checked {completed}/{len(successful_results)} images...")
            
            spinner.finish(f"Chainguard verification complete ({len(successful_results)} images)")
        finally:
            if prev_log_level is not None:
                restore_logging(prev_log_level)

    # Generate summary AFTER Chainguard check
    summary = generate_summary(args, results, extraction_result)
    
    # Determine output paths
    json_path = Path(args.summary_json) if args.summary_json else output_dir / "scan-summary.json"
    markdown_path = Path(args.markdown_output) if args.markdown_output else output_dir / "cosign-cve-summary.md"
    
    # Ensure parent directories exist
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    
    summary.save(str(json_path))

    # Generate markdown summary for GitHub Actions
    markdown_content = generate_markdown_summary(summary, args.min_cve_level)
    
    # Handle append mode for combining CI outputs
    if args.append and markdown_path.exists():
        with open(markdown_path, "a") as f:
            f.write("\n\n---\n\n")  # Separator between reports
            f.write(markdown_content)
        print(f"📄 Markdown summary appended to: {markdown_path}")
    else:
        with open(markdown_path, "w") as f:
            f.write(markdown_content)
        print(f"📄 Markdown summary saved to: {markdown_path}")

    # Print summary
    print()
    print_summary(summary, args.min_cve_level, args.verbose)

    # Calculate and display total execution time
    elapsed_time = time.time() - start_time
    if elapsed_time >= 3600:
        time_str = f"{elapsed_time / 3600:.1f} hours"
    elif elapsed_time >= 60:
        minutes = int(elapsed_time // 60)
        seconds = int(elapsed_time % 60)
        time_str = f"{minutes}m {seconds}s"
    else:
        time_str = f"{elapsed_time:.1f}s"

    print()
    print(f"✅ Kubernetes image scanning completed in {time_str}")

    return 0


def generate_summary(
    args: argparse.Namespace,
    results: List[ScanResult],
    extraction_result: Any,
) -> ScanSummary:
    """Generate scan summary."""
    successful = [r for r in results if r.success and not r.skipped]
    failed = [r for r in results if not r.success and not r.skipped]
    skipped = [r for r in results if r.skipped]

    summary = ScanSummary(
        namespace=args.namespace,
        total_images_found=extraction_result.total_found,
        images_skipped=extraction_result.ignored_count + extraction_result.inaccessible_count,
        images_processed=len(results),
        successful_scans=len(successful),
        failed_scans=len(failed),
        skipped_scans=len(skipped),
        format=args.format,
        severity_filter=args.severity,
        successful_images=[r.image for r in successful],
        failed_images=[{"image": r.image, "error": r.error or "Unknown"} for r in failed],
        skipped_images=[r.image for r in skipped],
        cve_analysis=[r.to_dict() for r in successful],
    )

    return summary


def generate_markdown_summary(summary: ScanSummary, min_cve_level: str) -> str:
    """
    Generate CVE analysis summary in Markdown format for GitHub Actions.
    
    This can be used with GITHUB_STEP_SUMMARY to display results in PR/Action summaries.
    
    Args:
        summary: Scan summary data
        min_cve_level: Minimum CVE level considered relevant
        
    Returns:
        Markdown formatted string
    """
    lines = []
    
    # Header
    lines.append("# 🔍 COSIGN SCAN CVE Analysis Summary")
    lines.append("")
    
    # Scan info
    lines.append("## 📊 Scan Information")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| **Namespace** | `{summary.namespace}` |")
    lines.append(f"| **Images Found** | {summary.total_images_found} |")
    lines.append(f"| **Images Processed** | {summary.images_processed} |")
    lines.append(f"| **Successful Scans** | ✅ {summary.successful_scans} |")
    lines.append(f"| **Failed Scans** | ❌ {summary.failed_scans} |")
    lines.append(f"| **Skipped (unsigned)** | 🚫 {summary.skipped_scans} |")
    lines.append(f"| **Minimum CVE Level** | `{min_cve_level}` |")
    lines.append("")
    
    # CVE Analysis table
    if summary.cve_analysis:
        lines.append("## 🛡️ CVE Analysis by Image")
        lines.append("")
        lines.append(f"> Minimum CVE Level: **{min_cve_level}** (levels below this are considered irrelevant)")
        lines.append("")
        
        # Table header
        lines.append("| Image | Unaddressed | Addressed | Irrelevant | Triage | Triage File | Chainguard |")
        lines.append("|-------|:-----------:|:---------:|:----------:|:------:|:-----------:|:----------:|")
        
        total_unaddressed = 0
        total_addressed = 0
        total_irrelevant = 0
        images_with_triage = 0
        images_with_chainguard = 0
        
        for analysis in summary.cve_analysis:
            image_short = analysis["image"].split("/")[-1]
            # Truncate if too long
            if len(image_short) > 40:
                image_short = image_short[:37] + "..."
            
            # Get CVE counts
            critical = analysis.get("critical", 0)
            high = analysis.get("high", 0)
            medium = analysis.get("medium", 0)
            low = analysis.get("low", 0)
            triaged = analysis.get("triaged", 0)
            
            # Calculate categories
            unaddressed = critical + high
            addressed = triaged
            irrelevant = medium + low
            
            # Get status
            has_triage = triaged > 0  # CVEs were actually triaged/addressed
            has_triage_file = analysis.get("triage_file") is not None  # Triage file exists
            is_chainguard = analysis.get("is_chainguard", False)
            
            total_unaddressed += unaddressed
            total_addressed += addressed
            total_irrelevant += irrelevant
            if has_triage_file:
                images_with_triage += 1
            if is_chainguard:
                images_with_chainguard += 1
            
            # Format cells
            unaddr_str = f"✅ {unaddressed}" if unaddressed == 0 else f"🔴 **{unaddressed}**"
            triage_str = "✅" if has_triage else "❌"
            triage_file_str = "✅" if has_triage_file else "❌"
            chainguard_str = "✅" if is_chainguard else "❌"
            
            lines.append(f"| `{image_short}` | {unaddr_str} | {addressed} | {irrelevant} | {triage_str} | {triage_file_str} | {chainguard_str} |")
        
        lines.append("")
        
        # Statistics
        lines.append("## 📈 Statistics")
        lines.append("")
        lines.append("| Metric | Count |")
        lines.append("|--------|------:|")
        lines.append(f"| **Unaddressed CVEs** (≥{min_cve_level}) | {total_unaddressed} |")
        lines.append(f"| **Addressed CVEs** | {total_addressed} |")
        lines.append(f"| **Irrelevant CVEs** (<{min_cve_level}) | {total_irrelevant} |")
        lines.append(f"| **Images with Triage** | {images_with_triage}/{len(summary.cve_analysis)} |")
        lines.append(f"| **Images with Chainguard Base** | {images_with_chainguard}/{len(summary.cve_analysis)} |")
        lines.append("")
        
        # Result badge
        if total_unaddressed == 0:
            lines.append("> 🎉 **All relevant CVEs have been addressed!**")
        else:
            lines.append(f"> ⚠️ **{total_unaddressed} unaddressed CVEs need attention**")
        lines.append("")
    
    # Failed scans section
    if summary.failed_scans > 0:
        lines.append("## ❌ Failed Scans")
        lines.append("")
        lines.append("<details>")
        lines.append("<summary>Click to expand failed scan details</summary>")
        lines.append("")
        for item in summary.failed_images:
            lines.append(f"- `{item['image']}`")
            lines.append(f"  - Error: {item['error']}")
        lines.append("")
        lines.append("</details>")
        lines.append("")
    
    # Skipped scans section
    if summary.skipped_scans > 0:
        lines.append("## 🚫 Skipped Scans (Unsigned Images)")
        lines.append("")
        lines.append("<details>")
        lines.append("<summary>Click to expand skipped images</summary>")
        lines.append("")
        for image in summary.skipped_images:
            lines.append(f"- `{image}`")
        lines.append("")
        lines.append("</details>")
        lines.append("")
    
    # Footer
    lines.append("---")
    lines.append(f"*Generated by scanner-py on {summary.timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC*")
    
    return "\n".join(lines)


def print_summary(summary: ScanSummary, min_cve_level: str, verbose: bool = False) -> None:
    """Print scan summary."""
    print("━" * 120)
    print("📊 SCAN SUMMARY")
    print("━" * 120)
    print()
    print(f"  Namespace:        {summary.namespace}")
    print(f"  Images found:     {summary.total_images_found}")
    print(f"  Images processed: {summary.images_processed}")
    print()
    print(f"  ✅ Successful:    {summary.successful_scans}")
    print(f"  ❌ Failed:        {summary.failed_scans}")
    print(f"  🚫  Skipped:       {summary.skipped_scans} (unsigned)")
    print()

    # Only show failed scan details in verbose mode
    if summary.failed_scans > 0:
        if verbose:
            print("  Failed scans:")
            for item in summary.failed_images:
                print(f"    • {item['image']}")
                print(f"      Error: {item['error']}")
            print()
        else:
            print(f"  💡 Use --verbose to see failed scan details")
            print()

    # CVE Analysis table
    if summary.cve_analysis:
        print("━" * 120)
        print("🔍 CVE ANALYSIS SUMMARY")
        print("=" * 120)
        print(f"Minimum CVE Level: {min_cve_level} (levels below this are considered irrelevant)")
        print()

        # Print table header matching bash script format
        header = (
            f"{'Image':<35} "
            f"{'Unaddressed CVEs':>17} "
            f"{'Addressed CVEs':>15} "
            f"{'Irrelevant CVEs':>16} "
            f"{'Triage':>12} "
            f"{'Triage File':>12} "
            f"{'Chainguard Base':>16}"
        )
        print(header)

        total_unaddressed = 0
        total_addressed = 0
        total_irrelevant = 0
        images_with_triage = 0
        images_with_chainguard = 0

        for analysis in summary.cve_analysis:
            image_short = analysis["image"].split("/")[-1][:33]
            
            # Get CVE counts
            critical = analysis.get("critical", 0)
            high = analysis.get("high", 0)
            medium = analysis.get("medium", 0)
            low = analysis.get("low", 0)
            triaged = analysis.get("triaged", 0)
            
            # Unaddressed = Critical + High (above min_cve_level)
            unaddressed = critical + high
            # Addressed = triaged CVEs
            addressed = triaged
            # Irrelevant = Medium + Low (below min_cve_level HIGH)
            irrelevant = medium + low
            
            # Get triage and chainguard status
            has_triage = triaged > 0  # CVEs were actually triaged/addressed
            has_triage_file = analysis.get("triage_file") is not None  # Triage file exists
            is_chainguard = analysis.get("is_chainguard", False)

            total_unaddressed += unaddressed
            total_addressed += addressed
            total_irrelevant += irrelevant
            if has_triage_file:
                images_with_triage += 1
            if is_chainguard:
                images_with_chainguard += 1

            # Format status icons
            unaddr_icon = "✅" if unaddressed == 0 else "🔴"
            triage_str = "✅ Yes" if has_triage else "❌ No"
            triage_file_str = "✅ Yes" if has_triage_file else "❌ No"
            chainguard_str = "✅ Yes" if is_chainguard else "❌ No"

            # Print row
            row = (
                f"{image_short:<35} "
                f"{unaddr_icon} {unaddressed:<14} "
                f"{addressed:>15} "
                f"{irrelevant:>16} "
                f"{triage_str:>12} "
                f"{triage_file_str:>12} "
                f"{chainguard_str:>16}"
            )
            print(row)

        print()
        print("━" * 120)
        print("📈 STATISTICS")
        print("=" * 120)
        print(f"Total unaddressed CVEs (≥{min_cve_level}): {total_unaddressed}")
        print(f"Total addressed CVEs: {total_addressed}")
        print(f"Total irrelevant CVEs (<{min_cve_level}): {total_irrelevant}")
        print(f"Images with triage: {images_with_triage}/{len(summary.cve_analysis)}")
        print(f"Images with Chainguard base: {images_with_chainguard}/{len(summary.cve_analysis)}")
        print()

        if total_unaddressed == 0:
            print("🎉 All relevant CVEs have been addressed!")
        else:
            print(f"⚠️  {total_unaddressed} unaddressed CVEs need attention")
