"""CLI for generating detailed SBOM reports from scan results.

Equivalent to generate-sbom-report.sh
"""

import argparse
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..utils.logging import setup_logging, LogLevel, get_logger

logger = get_logger(__name__)


def create_generate_sbom_report_parser(subparsers: Any) -> argparse.ArgumentParser:
    """Create the generate-sbom-report subparser."""
    parser = subparsers.add_parser(
        "generate-sbom-report",
        help="Generate detailed SBOM report from scan results",
        description="""
Generate a detailed Software Bill of Materials (SBOM) analysis report from
previously completed scans. This report provides comprehensive component
inventory, license information, and package breakdowns for all successfully
scanned images.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate SBOM report from scan results
  scanner-py generate-sbom-report --input-dir ./scan-results --output sbom-report.md

  # Generate report with custom output file
  scanner-py generate-sbom-report --input-dir ./scan-results -o detailed-sbom.md
""",
    )

    parser.add_argument(
        "--input-dir",
        default="./scan-results",
        help="Directory containing scan results (default: ./scan-results)",
    )
    parser.add_argument(
        "--output", "-o",
        default="sbom-detailed-report.md",
        help="Output file path (default: sbom-detailed-report.md)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    return parser


def sanitize_image_name(image: str) -> str:
    """Sanitize image name for use in file paths."""
    return re.sub(r'[^A-Za-z0-9._-]', '_', image)


def load_scan_summary(scan_results_dir: Path) -> Optional[Dict[str, Any]]:
    """Load scan summary JSON file."""
    summary_path = scan_results_dir / "scan-summary.json"
    if not summary_path.exists():
        logger.error(f"scan-summary.json not found in {scan_results_dir}")
        return None

    try:
        with open(summary_path) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse scan-summary.json: {e}")
        return None


def load_sbom(sbom_path: Path) -> Optional[Dict[str, Any]]:
    """Load SBOM JSON file."""
    if not sbom_path.exists():
        return None

    try:
        with open(sbom_path) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse SBOM {sbom_path}: {e}")
        return None


def analyze_sbom(sbom: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze SBOM and extract statistics."""
    components = sbom.get("components", [])
    
    stats = {
        "total_components": len(components),
        "os_components": 0,
        "library_components": 0,
        "application_components": 0,
        "apk_packages": 0,
        "pypi_packages": 0,
        "npm_packages": 0,
        "total_licenses": 0,
        "unique_licenses": set(),
    }

    for component in components:
        comp_type = component.get("type", "")
        if comp_type == "operating-system":
            stats["os_components"] += 1
        elif comp_type == "library":
            stats["library_components"] += 1
        elif comp_type == "application":
            stats["application_components"] += 1

        purl = component.get("purl", "")
        if "pkg:apk" in purl:
            stats["apk_packages"] += 1
        elif "pypi" in purl:
            stats["pypi_packages"] += 1
        elif "npm" in purl:
            stats["npm_packages"] += 1

        licenses = component.get("licenses", [])
        for license_obj in licenses:
            stats["total_licenses"] += 1
            license_id = license_obj.get("license", {}).get("id")
            license_name = license_obj.get("license", {}).get("name")
            if license_id:
                stats["unique_licenses"].add(license_id)
            elif license_name:
                stats["unique_licenses"].add(license_name)

    stats["unique_licenses"] = sorted(list(stats["unique_licenses"]))
    return stats


def get_top_components(sbom: Dict[str, Any], limit: int = 10) -> List[str]:
    """Get top components by name (counting duplicates)."""
    components = sbom.get("components", [])
    component_names = []
    
    for component in components:
        name = component.get("name", "N/A")
        version = component.get("version", "unknown")
        component_names.append(f"{name}@{version}")
    
    counter = Counter(component_names)
    top = counter.most_common(limit)
    return [f"  - {name} (count: {count})" for name, count in top]


def generate_report(
    scan_results_dir: Path,
    output_file: Path,
    successful_scans: List[str],
    namespace: str = "pharia-ai",
) -> bool:
    """Generate detailed SBOM report."""
    total_images = len(successful_scans)
    
    # Calculate overall statistics
    total_components = 0
    total_os_packages = 0
    total_python_packages = 0
    total_licenses = 0
    images_with_licenses = 0
    total_apk = 0
    total_pypi = 0
    total_npm = 0

    # First pass: calculate totals
    for image in successful_scans:
        img_safe = sanitize_image_name(image)
        sbom_path = scan_results_dir / img_safe / "sbom.json"
        sbom = load_sbom(sbom_path)
        
        if sbom:
            stats = analyze_sbom(sbom)
            total_components += stats["total_components"]
            total_os_packages += stats["os_components"] + stats["library_components"]
            total_python_packages += stats["pypi_packages"]
            total_pypi += stats["pypi_packages"]
            total_apk += stats["apk_packages"]
            total_npm += stats["npm_packages"]
            total_licenses += stats["total_licenses"]
            if stats["total_licenses"] > 0:
                images_with_licenses += 1

    # Start writing report
    with open(output_file, "w") as f:
        # Header
        f.write("# Detailed SBOM Analysis Report\n\n")
        f.write(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}\n")
        f.write(f"**Source:** Successful SBOM scans from {namespace} namespace\n")
        f.write(f"**Total Images Analyzed:** {total_images}\n\n")
        f.write("---\n\n")
        f.write("## Executive Summary\n\n")
        f.write(
            f"This report provides detailed analysis of Software Bill of Materials (SBOM) "
            f"for all {total_images} successfully scanned container images. Each SBOM contains "
            f"a complete inventory of all software components, including operating system "
            f"packages, application dependencies, and their licenses.\n\n"
        )

        # Overall statistics
        f.write("## Overall SBOM Statistics\n\n")
        f.write("| Metric | Value |\n")
        f.write("|--------|-------|\n")
        f.write(f"| Total Images Analyzed | {total_images} |\n")
        f.write(f"| Total Components | {total_components} |\n")
        f.write(f"| Total OS Packages | {total_os_packages} |\n")
        f.write(f"| Total Python Packages | {total_python_packages} |\n")
        f.write(f"| Total Licenses | {total_licenses} |\n")
        f.write(f"| Images with License Info | {images_with_licenses} / {total_images} |\n\n")
        f.write("---\n\n")
        f.write("## Detailed Image Analysis\n\n")

        # Detailed section for each image
        image_num = 1
        total_library = 0
        total_os = 0
        total_app = 0

        for image in successful_scans:
            img_safe = sanitize_image_name(image)
            sbom_path = scan_results_dir / img_safe / "sbom.json"
            sbom = load_sbom(sbom_path)

            if not sbom:
                continue

            logger.info(f"Processing image {image_num}/{total_images}: {image}")

            image_name = image.split("/")[-1]
            stats = analyze_sbom(sbom)
            
            total_library += stats["library_components"]
            total_os += stats["os_components"]
            total_app += stats["application_components"]

            # Get license list (top 10)
            license_list = ", ".join(stats["unique_licenses"][:10])
            if not license_list:
                license_list = "N/A"

            # Get top components
            top_components = get_top_components(sbom, limit=10)
            top_components_str = "\n".join(top_components) if top_components else "  - N/A"

            # Get metadata
            metadata_path = scan_results_dir / img_safe / "metadata.json"
            base_image = "N/A"
            if metadata_path.exists():
                try:
                    with open(metadata_path) as mf:
                        metadata = json.load(mf)
                        base_image = metadata.get("base_image", "N/A")
                except Exception:
                    pass

            # Write image section
            f.write(f"### {image_num}. {image_name}\n\n")
            f.write(f"**Image:** `{image}`\n")
            f.write(f"**SBOM File:** `{img_safe}/sbom.json`\n\n")
            f.write("#### Component Summary\n\n")
            f.write("| Metric | Count |\n")
            f.write("|--------|-------|\n")
            f.write(f"| Total Components | {stats['total_components']} |\n")
            f.write(f"| OS Components | {stats['os_components']} |\n")
            f.write(f"| Library Components | {stats['library_components']} |\n")
            f.write(f"| Application Components | {stats['application_components']} |\n\n")
            f.write("#### Package Type Breakdown\n\n")
            f.write("| Package Type | Count |\n")
            f.write("|--------------|-------|\n")
            f.write(f"| APK (Alpine/Chainguard) | {stats['apk_packages']} |\n")
            f.write(f"| PyPI (Python) | {stats['pypi_packages']} |\n")
            f.write(f"| NPM (Node.js) | {stats['npm_packages']} |\n\n")
            f.write("#### License Information\n\n")
            f.write(f"- **Unique Licenses:** {len(stats['unique_licenses'])}\n")
            f.write(f"- **Top Licenses:** {license_list}\n\n")
            f.write("#### Top Components\n\n")
            f.write(f"{top_components_str}\n\n")
            f.write("#### Component Details\n\n")
            f.write("<details>\n")
            f.write("<summary>View all components (click to expand)</summary>\n\n")
            f.write("| Component Name | Version | Type | PURL | License |\n")
            f.write("|----------------|---------|------|------|---------|\n")

            # Write all components
            for component in sbom.get("components", []):
                name = component.get("name", "N/A")
                version = component.get("version", "N/A")
                comp_type = component.get("type", "N/A")
                purl = component.get("purl", "N/A")
                
                license_id = "N/A"
                licenses = component.get("licenses", [])
                if licenses:
                    license_obj = licenses[0].get("license", {})
                    license_id = license_obj.get("id") or license_obj.get("name", "N/A")

                f.write(f"| {name} | {version} | {comp_type} | {purl} | {license_id} |\n")

            f.write(f"\n*Complete component list ({stats['total_components']} components).*\n\n")
            f.write("</details>\n\n")
            f.write("---\n\n")

            image_num += 1

        # Component type distribution
        f.write("---\n\n")
        f.write("## Component Type Distribution\n\n")
        f.write("### By Component Type\n\n")
        f.write("| Type | Count | Percentage |\n")
        f.write("|------|-------|------------|\n")
        
        if total_components > 0:
            lib_pct = (total_library / total_components) * 100
            os_pct = (total_os / total_components) * 100
            app_pct = (total_app / total_components) * 100
            f.write(f"| Library | {total_library} | {lib_pct:.1f}% |\n")
            f.write(f"| Operating System | {total_os} | {os_pct:.1f}% |\n")
            f.write(f"| Application | {total_app} | {app_pct:.1f}% |\n\n")
        else:
            f.write("| Library | 0 | 0.0% |\n")
            f.write("| Operating System | 0 | 0.0% |\n")
            f.write("| Application | 0 | 0.0% |\n\n")

        f.write("### By Package Manager\n\n")
        f.write("| Package Manager | Count | Percentage |\n")
        f.write("|-----------------|-------|------------|\n")
        
        if total_components > 0:
            apk_pct = (total_apk / total_components) * 100
            pypi_pct = (total_pypi / total_components) * 100
            npm_pct = (total_npm / total_components) * 100
            f.write(f"| APK (Chainguard/Alpine) | {total_apk} | {apk_pct:.1f}% |\n")
            f.write(f"| PyPI (Python) | {total_pypi} | {pypi_pct:.1f}% |\n")
            f.write(f"| NPM (Node.js) | {total_npm} | {npm_pct:.1f}% |\n\n")
        else:
            f.write("| APK (Chainguard/Alpine) | 0 | 0.0% |\n")
            f.write("| PyPI (Python) | 0 | 0.0% |\n")
            f.write("| NPM (Node.js) | 0 | 0.0% |\n\n")

        # License analysis
        f.write("---\n\n")
        f.write("## License Analysis\n\n")
        f.write("### License Distribution\n\n")
        f.write("The SBOMs contain license information for components. Common licenses found:\n\n")
        f.write("- **MIT** - Most common permissive license\n")
        f.write("- **Apache-2.0** - Apache License 2.0\n")
        f.write("- **BSD-3-Clause** - BSD 3-Clause License\n")
        f.write("- **GPL-2.0** - GNU General Public License v2\n")
        f.write("- **MPL-2.0** - Mozilla Public License 2.0\n\n")
        f.write("### License Compliance Notes\n\n")
        f.write("- All images use Chainguard base images which have clear licensing\n")
        f.write("- Python packages typically include license information in their metadata\n")
        f.write("- OS packages from Chainguard follow Wolfi licensing standards\n\n")
        f.write("---\n\n")
        f.write("## SBOM Format Information\n\n")
        f.write("All SBOMs are in **CycloneDX 1.6** format with the following characteristics:\n\n")
        f.write("- **Format:** CycloneDX JSON\n")
        f.write("- **Schema:** http://cyclonedx.org/schema/bom-1.6.schema.json\n")
        f.write("- **Generated by:** Trivy\n")
        f.write("- **Includes:** Components, licenses, hashes, PURLs (Package URLs)\n\n")
        f.write("### SBOM Metadata\n\n")
        f.write("Each SBOM includes:\n")
        f.write("- Component inventory (complete list of all software)\n")
        f.write("- Package URLs (PURLs) for component identification\n")
        f.write("- License information where available\n")
        f.write("- Component hashes for integrity verification\n")
        f.write("- Component types and classifications\n\n")
        f.write("---\n\n")
        f.write("**Report End**\n")

    return True


def run_generate_sbom_report(args: argparse.Namespace) -> int:
    """Run the generate-sbom-report command."""
    setup_logging(LogLevel.DEBUG if args.verbose else LogLevel.INFO)

    scan_results_dir = Path(args.input_dir)
    output_file = Path(args.output)

    if not scan_results_dir.exists():
        logger.error(f"Scan results directory not found: {scan_results_dir}")
        return 1

    # Load scan summary
    summary = load_scan_summary(scan_results_dir)
    if not summary:
        return 1

    # Get successful scans
    successful_scans = summary.get("successful_scans", [])
    if not successful_scans:
        logger.error("No successful scans found in scan summary")
        return 1

    # Get namespace
    namespace = summary.get("scan_summary", {}).get("namespace", "pharia-ai")

    # Generate report
    if generate_report(scan_results_dir, output_file, successful_scans, namespace):
        logger.info(f"✅ Detailed SBOM report generated: {output_file}")
        return 0
    else:
        logger.error("Failed to generate SBOM report")
        return 1

