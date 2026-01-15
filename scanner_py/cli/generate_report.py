"""CLI for generating reports from existing scan results.

This command allows generating Markdown/JSON reports from previously
completed scans, useful for CI pipelines where scanning and reporting
happen in separate job steps.
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, List, Dict, Optional

from ..models.scan_result import ScanSummary
from ..utils.logging import setup_logging, LogLevel


def create_generate_report_parser(subparsers: Any) -> argparse.ArgumentParser:
    """Create the generate-report subparser."""
    parser = subparsers.add_parser(
        "generate-report",
        help="Generate reports from existing scan results",
        description="""
Generate Markdown or JSON reports from existing scan results.

This is useful in CI pipelines where scanning happens in one job
and report generation/combination happens in a separate job.

The command can read from scan result directories or JSON summary files
and produce combined reports from multiple sources.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate report from scan results directory
  scanner-py generate-report --input-dir ./scan-results

  # Combine multiple scan summaries into one report
  scanner-py generate-report --input-json ./job1/summary.json ./job2/summary.json

  # Generate and append to existing report
  scanner-py generate-report --input-dir ./scan-results --output report.md --append

  # Generate report with custom title
  scanner-py generate-report --input-dir ./scan-results --title "Production Scan"
""",
    )

    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--input-dir",
        help="Directory containing scan results (scan-summary.json)",
    )
    input_group.add_argument(
        "--input-json",
        nargs="+",
        help="One or more JSON summary files to combine",
    )

    # Output options
    parser.add_argument(
        "--output", "-o",
        help="Output file path (default: stdout for Markdown)",
    )
    parser.add_argument(
        "--output-format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    parser.add_argument(
        "--append",
        action="store_true",
        help="Append to existing output file",
    )

    # Report options
    parser.add_argument(
        "--title",
        help="Custom report title",
    )
    parser.add_argument(
        "--min-cve-level",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="HIGH",
        help="Minimum CVE level to consider relevant (default: HIGH)",
    )
    
    # Filter options
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

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    return parser


def load_summary_from_dir(input_dir: str) -> Optional[Dict[str, Any]]:
    """Load scan summary from a results directory."""
    summary_path = Path(input_dir) / "scan-summary.json"
    if not summary_path.exists():
        print(f"❌ Summary file not found: {summary_path}", file=sys.stderr)
        return None
    
    try:
        with open(summary_path) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse JSON: {e}", file=sys.stderr)
        return None


def load_summary_from_file(filepath: str) -> Optional[Dict[str, Any]]:
    """Load scan summary from a JSON file."""
    path = Path(filepath)
    if not path.exists():
        print(f"❌ File not found: {filepath}", file=sys.stderr)
        return None
    
    try:
        with open(path) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse JSON {filepath}: {e}", file=sys.stderr)
        return None


def merge_summaries(summaries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge multiple scan summaries into one combined summary."""
    if len(summaries) == 1:
        return summaries[0]
    
    # Combine the summaries
    combined = {
        "scan_summary": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "namespace": "combined",
            "total_images_found": 0,
            "images_skipped": 0,
            "images_processed": 0,
            "successful_scans": 0,
            "failed_scans": 0,
            "skipped_scans": 0,
            "format": summaries[0].get("scan_summary", {}).get("format", "table"),
            "severity_filter": summaries[0].get("scan_summary", {}).get("severity_filter", "HIGH,CRITICAL"),
        },
        "successful_scans": [],
        "failed_scans": [],
        "skipped_scans": [],
        "cve_analysis": [],
    }
    
    namespaces = []
    for summary in summaries:
        ss = summary.get("scan_summary", {})
        combined["scan_summary"]["total_images_found"] += ss.get("total_images_found", 0)
        combined["scan_summary"]["images_skipped"] += ss.get("images_skipped", 0)
        combined["scan_summary"]["images_processed"] += ss.get("images_processed", 0)
        combined["scan_summary"]["successful_scans"] += ss.get("successful_scans", 0)
        combined["scan_summary"]["failed_scans"] += ss.get("failed_scans", 0)
        combined["scan_summary"]["skipped_scans"] += ss.get("skipped_scans", 0)
        namespaces.append(ss.get("namespace", "unknown"))
        
        combined["successful_scans"].extend(summary.get("successful_scans", []))
        combined["failed_scans"].extend(summary.get("failed_scans", []))
        combined["skipped_scans"].extend(summary.get("skipped_scans", []))
        combined["cve_analysis"].extend(summary.get("cve_analysis", []))
    
    combined["scan_summary"]["namespace"] = ", ".join(set(namespaces))
    
    return combined


def generate_markdown_report(
    summary_data: Dict[str, Any],
    min_cve_level: str,
    title: Optional[str] = None,
    filter_unaddressed: bool = False,
    filter_missing_triage: bool = False,
) -> str:
    """
    Generate CVE analysis summary in Markdown format.
    
    This produces output compatible with oras-scan's format for easy
    combination in CI pipelines.
    
    Args:
        summary_data: Scan summary dictionary
        min_cve_level: Minimum CVE level considered relevant
        title: Custom report title
        filter_unaddressed: Only show images with unaddressed CVEs
        filter_missing_triage: Only show images with missing triage files
        
    Returns:
        Markdown formatted string
    """
    lines = []
    ss = summary_data.get("scan_summary", {})
    cve_analysis = summary_data.get("cve_analysis", [])
    failed_scans = summary_data.get("failed_scans", [])
    skipped_scans = summary_data.get("skipped_scans", [])
    
    # Header
    report_title = title or "🔍 CVE Analysis Summary"
    lines.append(f"# {report_title}")
    lines.append("")
    lines.append(f"Generated on: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    lines.append("")
    
    # Scan info
    lines.append("## 📊 Scan Information")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| **Namespace** | `{ss.get('namespace', 'N/A')}` |")
    lines.append(f"| **Images Found** | {ss.get('total_images_found', 0)} |")
    lines.append(f"| **Images Processed** | {ss.get('images_processed', 0)} |")
    lines.append(f"| **Successful Scans** | ✅ {ss.get('successful_scans', 0)} |")
    lines.append(f"| **Failed Scans** | ❌ {ss.get('failed_scans', 0)} |")
    lines.append(f"| **Skipped (unsigned)** | ⊘ {ss.get('skipped_scans', 0)} |")
    lines.append(f"| **Minimum CVE Level** | `{min_cve_level}` |")
    lines.append("")
    
    # CVE Analysis table
    if cve_analysis:
        lines.append("## 🛡️ CVE Analysis by Image")
        lines.append("")
        lines.append(f"> Minimum CVE Level: **{min_cve_level}** (levels below this are considered irrelevant)")
        lines.append("")
        
        # Table header
        lines.append("| Image | Unaddressed CVEs | Addressed CVEs | Irrelevant CVEs | Triage | Chainguard |")
        lines.append("|-------|:----------------:|:--------------:|:---------------:|:-----------:|:----------:|")
        
        total_unaddressed = 0
        total_addressed = 0
        total_irrelevant = 0
        images_with_triage = 0
        images_with_chainguard = 0
        displayed_count = 0
        
        for analysis in cve_analysis:
            # Get CVE counts
            critical = analysis.get("critical", 0)
            high = analysis.get("high", 0)
            medium = analysis.get("medium", 0)
            low = analysis.get("low", 0)
            triaged = analysis.get("triaged", 0)
            
            # Calculate categories based on min_cve_level=HIGH
            unaddressed = critical + high
            addressed = triaged
            irrelevant = medium + low
            
            # Get status
            has_triage = triaged > 0 or analysis.get("triage_file") is not None
            is_chainguard = analysis.get("is_chainguard", False)
            
            # Accumulate totals
            total_unaddressed += unaddressed
            total_addressed += addressed
            total_irrelevant += irrelevant
            if has_triage:
                images_with_triage += 1
            if is_chainguard:
                images_with_chainguard += 1
            
            # Apply filters
            show_entry = True
            if filter_unaddressed and unaddressed == 0:
                show_entry = False
            if filter_missing_triage and has_triage:
                show_entry = False
            
            if not show_entry and (filter_unaddressed or filter_missing_triage):
                continue
            
            displayed_count += 1
            
            # Format image name
            image_short = analysis["image"].split("/")[-1]
            if len(image_short) > 40:
                image_short = image_short[:37] + "..."
            
            # Format cells
            unaddr_str = f"✅ {unaddressed}" if unaddressed == 0 else f"🔴 **{unaddressed}**"
            triage_str = "✅ Present" if has_triage else "❌ Missing"
            chainguard_str = "✅" if is_chainguard else "❌"
            
            lines.append(f"| `{image_short}` | {unaddr_str} | {addressed} | {irrelevant} | {triage_str} | {chainguard_str} |")
        
        lines.append("")
        
        # Statistics
        lines.append("## 📈 Statistics")
        lines.append("")
        lines.append("| Metric | Count |")
        lines.append("|--------|------:|")
        lines.append(f"| **Total Images** | {len(cve_analysis)} |")
        lines.append(f"| **Displayed Images** | {displayed_count} |")
        lines.append(f"| **Unaddressed CVEs** (≥{min_cve_level}) | {total_unaddressed} |")
        lines.append(f"| **Addressed CVEs** | {total_addressed} |")
        lines.append(f"| **Irrelevant CVEs** (<{min_cve_level}) | {total_irrelevant} |")
        lines.append(f"| **Images with Triage** | {images_with_triage}/{len(cve_analysis)} |")
        lines.append(f"| **Images with Chainguard Base** | {images_with_chainguard}/{len(cve_analysis)} |")
        lines.append("")
        
        # Filter information
        if filter_unaddressed and filter_missing_triage:
            lines.append("**Filter applied:** Showing images with unaddressed CVEs OR missing triage files")
        elif filter_unaddressed:
            lines.append("**Filter applied:** Showing only images with unaddressed CVEs")
        elif filter_missing_triage:
            lines.append("**Filter applied:** Showing only images with missing triage files")
        else:
            lines.append("**Filter applied:** Showing all images")
        lines.append("")
        
        # Result badge
        if total_unaddressed == 0:
            lines.append("> 🎉 **All relevant CVEs have been addressed!**")
        else:
            lines.append(f"> ⚠️ **{total_unaddressed} unaddressed CVEs need attention**")
        lines.append("")
    
    # Failed scans section
    if failed_scans:
        lines.append("## ❌ Failed Scans")
        lines.append("")
        lines.append("<details>")
        lines.append("<summary>Click to expand failed scan details</summary>")
        lines.append("")
        for item in failed_scans:
            if isinstance(item, dict):
                lines.append(f"- `{item.get('image', 'unknown')}`")
                lines.append(f"  - Error: {item.get('error', 'Unknown')}")
            else:
                lines.append(f"- `{item}`")
        lines.append("")
        lines.append("</details>")
        lines.append("")
    
    # Skipped scans section
    if skipped_scans:
        lines.append("## ⊘ Skipped Scans (Unsigned Images)")
        lines.append("")
        lines.append("<details>")
        lines.append("<summary>Click to expand skipped images</summary>")
        lines.append("")
        for image in skipped_scans:
            lines.append(f"- `{image}`")
        lines.append("")
        lines.append("</details>")
        lines.append("")
    
    # Footer
    lines.append("---")
    lines.append(f"*Generated by scanner-py*")
    
    return "\n".join(lines)


def print_cli_summary(
    summary_data: Dict[str, Any],
    min_cve_level: str,
    filter_unaddressed: bool = False,
    filter_missing_triage: bool = False,
) -> None:
    """Print scan summary to CLI."""
    ss = summary_data.get("scan_summary", {})
    cve_analysis = summary_data.get("cve_analysis", [])
    
    print("━" * 120)
    print("📊 SCAN SUMMARY")
    print("━" * 120)
    print()
    print(f"  Namespace:        {ss.get('namespace', 'N/A')}")
    print(f"  Images found:     {ss.get('total_images_found', 0)}")
    print(f"  Images processed: {ss.get('images_processed', 0)}")
    print()
    print(f"  ✅ Successful:    {ss.get('successful_scans', 0)}")
    print(f"  ❌ Failed:        {ss.get('failed_scans', 0)}")
    print(f"  ⊘  Skipped:       {ss.get('skipped_scans', 0)} (unsigned)")
    print()
    
    if cve_analysis:
        print("━" * 120)
        print("🔍 CVE ANALYSIS SUMMARY")
        print("=" * 120)
        print(f"Minimum CVE Level: {min_cve_level} (levels below this are considered irrelevant)")
        print()
        
        # Print table header
        header = (
            f"{'Image':<35} "
            f"{'Unaddressed CVEs':>17} "
            f"{'Addressed CVEs':>15} "
            f"{'Irrelevant CVEs':>16} "
            f"{'Triage':>12} "
            f"{'Chainguard Base':>16}"
        )
        print(header)
        
        total_unaddressed = 0
        total_addressed = 0
        total_irrelevant = 0
        images_with_triage = 0
        images_with_chainguard = 0
        
        for analysis in cve_analysis:
            critical = analysis.get("critical", 0)
            high = analysis.get("high", 0)
            medium = analysis.get("medium", 0)
            low = analysis.get("low", 0)
            triaged = analysis.get("triaged", 0)
            
            unaddressed = critical + high
            addressed = triaged
            irrelevant = medium + low
            
            has_triage = triaged > 0 or analysis.get("triage_file") is not None
            is_chainguard = analysis.get("is_chainguard", False)
            
            # Apply filters
            if filter_unaddressed and unaddressed == 0:
                continue
            if filter_missing_triage and has_triage:
                continue
            
            total_unaddressed += unaddressed
            total_addressed += addressed
            total_irrelevant += irrelevant
            if has_triage:
                images_with_triage += 1
            if is_chainguard:
                images_with_chainguard += 1
            
            image_short = analysis["image"].split("/")[-1][:33]
            unaddr_icon = "✅" if unaddressed == 0 else "🔴"
            triage_str = "✅ Yes" if has_triage else "❌ No"
            chainguard_str = "✅ Yes" if is_chainguard else "❌ No"
            
            row = (
                f"{image_short:<35} "
                f"{unaddr_icon} {unaddressed:<14} "
                f"{addressed:>15} "
                f"{irrelevant:>16} "
                f"{triage_str:>12} "
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
        print(f"Images with triage: {images_with_triage}/{len(cve_analysis)}")
        print(f"Images with Chainguard base: {images_with_chainguard}/{len(cve_analysis)}")
        print()
        
        if total_unaddressed == 0:
            print("🎉 All relevant CVEs have been addressed!")
        else:
            print(f"⚠️  {total_unaddressed} unaddressed CVEs need attention")


def run_generate_report(args: argparse.Namespace) -> int:
    """
    Run report generation from existing scan results.
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        Exit code
    """
    # Setup logging
    log_level = LogLevel.VERBOSE if args.verbose else LogLevel.INFO
    setup_logging(log_level)
    
    # Load summaries
    summaries = []
    
    if args.input_dir:
        summary = load_summary_from_dir(args.input_dir)
        if summary is None:
            return 1
        summaries.append(summary)
    elif args.input_json:
        for json_file in args.input_json:
            summary = load_summary_from_file(json_file)
            if summary is None:
                return 1
            summaries.append(summary)
    
    if not summaries:
        print("❌ No scan summaries loaded", file=sys.stderr)
        return 1
    
    # Merge if multiple
    combined = merge_summaries(summaries)
    
    # Generate output
    if args.output_format == "json":
        output_content = json.dumps(combined, indent=2)
    else:
        output_content = generate_markdown_report(
            combined,
            args.min_cve_level,
            title=args.title,
            filter_unaddressed=args.filter_unaddressed,
            filter_missing_triage=args.filter_missing_triage,
        )
    
    # Print CLI summary
    print()
    print_cli_summary(
        combined,
        args.min_cve_level,
        filter_unaddressed=args.filter_unaddressed,
        filter_missing_triage=args.filter_missing_triage,
    )
    print()
    
    # Write output
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if args.append and output_path.exists():
            with open(output_path, "a") as f:
                f.write("\n\n---\n\n")
                f.write(output_content)
            print(f"📄 Report appended to: {output_path}")
        else:
            with open(output_path, "w") as f:
                f.write(output_content)
            print(f"📄 Report saved to: {output_path}")
    else:
        # Print to stdout if no output file specified
        print()
        print("=" * 80)
        print("MARKDOWN OUTPUT")
        print("=" * 80)
        print(output_content)
    
    return 0

