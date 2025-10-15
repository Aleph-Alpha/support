# Aleph Alpha Support Scripts

A collection of public support scripts and utilities for Aleph Alpha customers to help with container security, attestation management, and other operational tasks.

## 📋 Table of Contents

- [Overview](#overview)
- [Scripts](#scripts)
  - [Scanner Scripts](#scanner-scripts)
    - [k8s-image-scanner.sh](#k8s-image-scannersh)
    - [cosign-scan-image.sh](#cosign-scan-imagesh)
  - [Cosign Scripts](#cosign-scripts)
    - [cosign-extract.sh](#cosign-extractsh)
    - [cosign-verify-image.sh](#cosign-verify-imagesh)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Contributing](#contributing)
- [License](#license)

## 🔍 Overview

This repository contains utility scripts designed to help Aleph Alpha customers manage and interact with container images, security attestations, and related infrastructure components. These tools are particularly useful for organizations working with signed container images and security compliance requirements.

## 🛠️ Scripts

### Scanner Scripts

#### k8s-image-scanner.sh

A comprehensive Kubernetes image scanning script that automatically discovers container images in a namespace, downloads SBOM attestations from Cosign-signed images, processes triage attestations, and runs Trivy vulnerability scans on SBOMs with detailed CVE analysis and reporting.

#### Features

- **Kubernetes Integration**: Automatically discovers images from pods, deployments, daemonsets, statefulsets, jobs, and cronjobs
- **SBOM-Based Scanning**: Downloads SBOM attestations and scans them with Trivy for accurate vulnerability detection
- **Cosign Integration**: Processes only Cosign-signed images with SBOM attestations
- **Smart Image Filtering**: Skips unsigned images, images without SBOM, and applies configurable ignore lists
- **Detailed CVE Analysis**: Categorizes CVEs as unaddressed, addressed (via triage), or irrelevant based on severity
- **Parallel Processing**: Configurable parallel scanning for improved performance
- **Comprehensive Reporting**: Generates detailed reports with actual CVE IDs in both table and JSON formats
- **Triage Integration**: Automatically applies Cosign triage attestations to filter known false positives
- **Flexible Configuration**: Support for custom Trivy configurations and severity filtering
- **Dry Run Mode**: Preview what would be scanned without executing actual scans

#### Image Processing Logic

The script processes images based on their signature and attestation status:

| Image Type | Description | Action |
|------------|-------------|---------|
| **Cosign-signed with SBOM and triage** | Images signed with Cosign that have both SBOM and triage attestations | SBOM downloaded and scanned with triage filtering applied |
| **Cosign-signed with SBOM only** | Images signed with Cosign that have SBOM but no triage attestations | SBOM downloaded and scanned without triage filtering |
| **Cosign-signed without SBOM** | Images signed with Cosign but no SBOM attestations | Skipped (cannot scan without SBOM) |
| **Unsigned** | Images without Cosign signatures | Skipped (not scanned) |

#### Usage Examples

**Basic scan of default namespace:**
```bash
./scanner/k8s-image-scanner.sh
```

**Scan specific namespace with ignore file:**
```bash
./scanner/k8s-image-scanner.sh --namespace production --ignore-file ./scanner/ignore-images.txt
```

**Parallel scanning with custom output:**
```bash
./scanner/k8s-image-scanner.sh --namespace staging --output-dir ./security-reports --parallel-scans 5
```

**Dry run to preview what would be scanned:**
```bash
./scanner/k8s-image-scanner.sh --namespace production --dry-run
```

**JSON output with custom severity filtering:**
```bash
./scanner/k8s-image-scanner.sh --format json --severity "CRITICAL,HIGH,MEDIUM" --output-dir ./reports
```

**CVE analysis with custom minimum severity level:**
```bash
./scanner/k8s-image-scanner.sh --min-cve-level MEDIUM --namespace production
```

**Custom Kubernetes context and configuration:**
```bash
./scanner/k8s-image-scanner.sh --context prod-cluster --kubeconfig ~/.kube/prod-config --namespace app-prod
```

#### Command Line Options

```
Usage:
  ./scanner/k8s-image-scanner.sh [OPTIONS]

Options:
  --namespace NAMESPACE         Kubernetes namespace to scan (default: pharia-ai)
  --ignore-file FILE           File containing images to ignore (one per line)
  --output-dir DIR             Output directory for reports (default: ./scan-results)
  --kubeconfig FILE            Path to kubeconfig file (optional)
  --context CONTEXT            Kubernetes context to use (optional)
  --trivy-config FILE          Custom Trivy configuration file (optional)
  --parallel-scans NUM         Number of parallel scans (default: 3)
  --timeout TIMEOUT            Timeout for individual operations in seconds (default: 300)
  --certificate-oidc-issuer ISSUER    OIDC issuer for cosign verification
  --certificate-identity-regexp REGEX Identity regexp for cosign verification
  --min-cve-level LEVEL        Minimum CVE severity level for analysis: LOW|MEDIUM|HIGH|CRITICAL (default: HIGH)
  --verbose                    Enable verbose logging
  --dry-run                    Show what would be scanned without executing
  --format FORMAT              Report format: table|json|sarif (default: table)
  --severity SEVERITIES        Comma-separated list of severities to include (default: LOW,MEDIUM,HIGH,CRITICAL)
  -h, --help                   Show this help
```

#### Ignore File Format

Create a text file with one image pattern per line to exclude from scanning:

```
# Comments start with #
k8s.gcr.io/pause
registry.k8s.io/pause
alpine:latest
internal-registry.company.com/base/
nginx:1.20-alpine
```

See `scanner/sample-ignore-images.txt` for a complete example.

#### Output Structure

The script creates a structured output directory:

```
scan-results/
├── scan-summary.json                    # Overall scan summary with detailed CVE analysis
├── registry_example_com_app_v1_0_0/     # Per-image results (Cosign-signed with SBOM and triage)
│   ├── metadata.json                    # Image scan metadata
│   ├── sbom.json                        # Downloaded SBOM attestation
│   ├── triage.json                      # Downloaded Cosign triage attestation
│   ├── triage.trivyignore               # Converted triage file for Trivy
│   ├── cve_details.json                 # Detailed CVE analysis with actual CVE IDs
│   ├── trivy-analysis.json              # Raw Trivy JSON output
│   └── trivy-report.table               # Trivy scan results (table format)
└── registry_example_com_db_v2_1_0/      # Per-image results (signed with SBOM, no triage)
    ├── metadata.json
    ├── sbom.json                        # Downloaded SBOM attestation
    ├── cve_details.json                 # CVE analysis (no triage applied)
    ├── trivy-analysis.json
    └── trivy-report.table
```

#### CVE Analysis Output

The `scan-summary.json` file includes comprehensive CVE analysis data:

```json
{
  "scan_summary": {
    "successful_scans": 2,
    "failed_scans": 0,
    "skipped_scans": 5
  },
  "cve_analysis": [
    {
      "image": "app:v1.0.0",
      "unaddressed_cves": 0,
      "addressed_cves": 15,
      "irrelevant_cves": 23,
      "has_triage_file": true,
      "unaddressed_cve_list": [],
      "addressed_cve_list": ["CVE-2023-1234", "CVE-2023-5678", ...],
      "irrelevant_cve_list": ["CVE-2022-9999", ...],
      "min_cve_level": "HIGH"
    }
  ]
}
```

#### Integration with Existing Scripts

The scanner leverages the existing `cosign-extract.sh` script for Cosign attestation extraction, ensuring consistent verification and extraction behavior. It automatically:

1. **Detects image signatures** using Cosign verification to determine if images are signed
2. **Downloads SBOM attestations** from Cosign-signed images using `cosign-extract.sh --predicate-only`
3. **Downloads triage attestations** from Cosign-signed images using `cosign-extract.sh --last`
4. **Selects latest attestations** automatically when multiple attestations exist
5. **Verifies attestations** using configurable OIDC settings for security
6. **Scans SBOMs with Trivy** using `trivy sbom` for accurate vulnerability detection
7. **Converts triage data** from JSON attestation format to Trivy ignore format
8. **Applies triage filtering** to Trivy scans automatically
9. **Analyzes CVE results** categorizing them as unaddressed, addressed, or irrelevant
10. **Generates comprehensive reports** with detailed CVE analysis and actual CVE IDs

#### Prerequisites

- **kubectl** (configured with access to target cluster)
- **trivy** (for vulnerability scanning of SBOMs)
- **jq** (for JSON processing)
- **crane** (for container registry operations)
- **docker** (for registry accessibility checking in k8s-image-scanner.sh)
- **cosign** (for signature verification and attestation extraction)
- **column** (for table formatting, usually pre-installed on Unix systems)

#### cosign-scan-image.sh

A focused scanning script for analyzing single container images by downloading SBOM attestations and performing Trivy vulnerability scans on the SBOM. This script automatically applies cosign triage attestations to filter known and addressed vulnerabilities, providing detailed CVE analysis and reporting.

#### Features

- **SBOM-Based Scanning**: Downloads SBOM attestations and scans them with Trivy for accurate vulnerability detection
- **Single Image Focus**: Scan any container image directly without Kubernetes integration
- **Cosign Integration**: Automatically detects signed images and downloads SBOM and triage attestations
- **Triage Filtering**: Applies cosign triage attestations to filter known false positives (optional with `--no-triage`)
- **Flexible Formats**: Support for table, JSON, and SARIF output formats
- **Registry Accessibility Check**: Validates registry access before scanning
- **Comprehensive CVE Analysis**: Categorizes CVEs by severity with detailed counts and integrated CVE table
- **CVE Display Options**: Control CVE table output with `--show-cves` and `--max-cves` flags
- **SBOM Type Selection**: Choose between CycloneDX (default) or SPDX SBOM formats
- **Dry Run Mode**: Preview what would be scanned without executing
- **Verbose Logging**: Optional detailed output for troubleshooting

#### Image Processing Logic

The script handles different image types intelligently:

| Image Type | Description | Action |
|------------|-------------|---------|
| **Cosign-signed with SBOM and triage** | Images signed with Cosign that have both SBOM and triage attestations | SBOM downloaded and scanned with triage filtering applied |
| **Cosign-signed with SBOM only** | Images signed with Cosign that have SBOM but no triage attestations | SBOM downloaded and scanned without triage filtering |
| **Cosign-signed without SBOM** | Images signed with Cosign but no SBOM attestations | Error: Cannot scan without SBOM |
| **Unsigned** | Images without Cosign signatures | Error: Unsigned images cannot be scanned (SBOM required) |

#### Usage Examples

**Basic scan of a container image:**
```bash
./cosign-scan-image.sh --image harbor.example.com/library/myapp:v1.0.0
```

**Scan with JSON output format:**
```bash
./cosign-scan-image.sh --image myregistry.io/app:latest --format json --output-dir ./my-reports
```

**Dry run to preview what would be scanned:**
```bash
./cosign-scan-image.sh --image harbor.example.com/prod/api:1.2.3 --dry-run
```

**Scan with verbose output and custom severity:**
```bash
./cosign-scan-image.sh --image myimage:tag --verbose --severity "CRITICAL,HIGH,MEDIUM"
```

**Scan with custom output directory:**
```bash
./cosign-scan-image.sh --image registry.company.com/app:v2.0 --output-dir ./security-scans
```

#### Command Line Options

```
Usage:
  ./cosign-scan-image.sh --image IMAGE [OPTIONS]

Required:
  --image IMAGE                         Container image to scan (e.g., registry.io/org/image:tag)

Options:
  --output-dir DIR                      Output directory for reports (default: ./scan-results)
  --trivy-config FILE                   Custom Trivy configuration file (optional)
  --timeout TIMEOUT                     Timeout for individual operations in seconds (default: 300)
  --certificate-oidc-issuer ISSUER      OIDC issuer for cosign verification
  --certificate-identity-regexp REGEX   Identity regexp for cosign verification
  --sbom-type TYPE                      SBOM type to extract: cyclonedx|spdx (default: cyclonedx)
  --no-triage                           Skip downloading and applying triage attestations
  --show-cves                           Show detailed CVE table in summary (default: enabled)
  --max-cves NUM                        Maximum CVEs to display in table (0 for all, default: 20)
  --verbose                             Enable verbose logging
  --dry-run                             Show what would be scanned without executing
  --format FORMAT                       Report format: table|json|sarif (default: table)
  --severity LEVEL                      Severity level to report: LOW|MEDIUM|HIGH|CRITICAL (default: CRITICAL)
  -h, --help                            Show this help
```

#### Output Structure

The script creates a structured output directory for the scanned image:

```
scan-results/
└── harbor_example_com_library_myapp_v1_0_0/    # Per-image results
    ├── metadata.json                            # Image scan metadata
    ├── sbom.json                                # Downloaded SBOM attestation (CycloneDX or SPDX)
    ├── triage.json                              # Downloaded Cosign triage attestation (if available)
    ├── triage.trivyignore                       # Converted triage file for Trivy
    ├── trivy-report.json                        # Trivy JSON report for CVE analysis
    └── trivy-report.table                       # Trivy scan results (format: table/json/sarif)
```

#### CVE Summary Output

The script displays an integrated summary with vulnerability counts and detailed CVE table:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 SCAN SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Image:               harbor.example.com/library/myapp:v1.0.0
SBOM:                ✅ Downloaded
Triage:              ✅ Applied
Scan Method:         SBOM-based

Vulnerabilities:
  🔴 Critical: 0
  🟠 High:     2
  🟡 Medium:   5
  🟢 Low:      12

Details:
  CVE ID              SEVERITY    PACKAGE              INSTALLED       FIXED           TITLE
  ──────────────────  ──────────  ────────────────────  ───────────────  ───────────────  ─────────────────────────────
  CVE-2024-1234       🟠 HIGH     libssl1.1            1.1.1f-1ubuntu   1.1.1f-2ubuntu   OpenSSL vulnerability
  CVE-2024-5678       🟠 HIGH     curl                 7.68.0-1ubuntu   7.68.0-2ubuntu   CURL remote code execution
  ...

Output: ./scan-results

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ Scan completed successfully
```

#### Integration with Existing Scripts

The scanner leverages existing scripts for consistent behavior:

1. **Signature Detection**: Uses `cosign-verify-image.sh` to verify image signatures
2. **SBOM Download**: Uses `cosign-extract.sh --predicate-only` to download SBOM attestations
3. **Attestation Download**: Uses `cosign-extract.sh` to download triage attestations
4. **Automatic Selection**: Automatically selects the latest attestation when multiple exist
5. **Verification**: Verifies attestations using configurable OIDC settings
6. **SBOM Scanning**: Uses `trivy sbom` to scan the downloaded SBOM for vulnerabilities
7. **Triage Conversion**: Converts triage data to Trivy ignore format
8. **CVE Analysis**: Categorizes vulnerabilities by severity with integrated table display

#### Prerequisites

- **trivy** (for vulnerability scanning of SBOMs)
- **jq** (for JSON processing)
- **crane** (for image digest resolution)
- **docker** (for registry accessibility checking)
- **cosign** (for signature verification and attestation extraction)
- **cosign-extract.sh** (for extracting SBOM and triage attestations)
- **cosign-verify-image.sh** (for verifying image signatures)

### Cosign Scripts

#### cosign-extract.sh

A powerful bash script for extracting and inspecting Cosign attestations from container images. This tool helps you retrieve various types of security attestations including SLSA provenance, SBOM data, vulnerability reports, and custom attestations.

#### Features

- **Multiple Attestation Types**: Supports SLSA, CycloneDX, SPDX, vulnerability reports, license information, triage data, and custom attestations
- **Flexible Extraction**: Extract single attestations, all attestations of a specific type, or all available attestations
- **Predicate-Only Extraction**: Extract only the predicate content with `--predicate-only` (ideal for raw SBOM extraction for Trivy scanning)
- **Discovery Mode**: List available attestation types for any container image
- **Inspection Tools**: Inspect referrers with missing predicate types
- **Output Options**: Save to files or output to stdout with proper JSON formatting
- **Cryptographic Verification**: Verify attestations using Cosign before extraction with configurable OIDC issuer and identity patterns
- **Verification-Only Mode**: Skip content extraction with `--no-extraction` for verification-only workflows

#### Supported Attestation Types

| Type | Description | Predicate Type |
|------|-------------|----------------|
| `slsa` | SLSA Provenance v1 | `https://slsa.dev/provenance/v1` |
| `cyclonedx` | CycloneDX SBOM | `https://cyclonedx.org/bom` |
| `spdx` | SPDX Document | `https://spdx.dev/Document` |
| `vuln` | Vulnerability Report | `https://cosign.sigstore.dev/attestation/vuln/v1` |
| `license` | License Information | `https://aleph-alpha.com/attestations/license/v1` |
| `triage` | Triage Data | `https://aleph-alpha.com/attestations/triage/v1` |
| `custom` | Custom Attestation | `https://cosign.sigstore.dev/attestation/v1` |

#### Usage Examples

**List available attestations for an image:**
```bash
./cosign-extract.sh --image registry.example.com/myapp:latest --list
```

**Extract a specific attestation type:**
```bash
./cosign-extract.sh --type slsa --image registry.example.com/myapp:latest --output provenance.json
```

**Extract only the predicate content (raw SBOM) for Trivy scanning:**
```bash
./cosign-extract.sh --type cyclonedx --image registry.example.com/myapp:latest --output sbom.json --predicate-only
```

**Extract all SBOM attestations:**
```bash
./cosign-extract.sh --type cyclonedx --image registry.example.com/myapp:latest --choice all --output sbom-
```

**Extract all attestation types to a directory:**
```bash
./cosign-extract.sh --image registry.example.com/myapp:latest --choice all --output ./attestations/
```

**Inspect referrers with missing predicate types:**
```bash
./cosign-extract.sh --image registry.example.com/myapp:latest --inspect-null
```

**Extract and verify an SPDX SBOM with cryptographic verification:**
```bash
./cosign-extract.sh --type spdx --image registry.example.com/myapp:latest --verify --output sbom.spdx.json
```

**Automatically select the most recent attestation when multiple exist:**
```bash
./cosign-extract.sh --type triage --image registry.example.com/myapp:latest --last --output triage.json
```

**Extract with custom verification parameters:**
```bash
./cosign-extract.sh --type slsa --image registry.example.com/myapp:latest --verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "https://github.com/myorg/myrepo/.github/workflows/.*" \
  --output provenance.json
```

**Verify attestations without extracting content:**
```bash
./cosign-extract.sh --type spdx --image registry.example.com/myapp:latest --verify --no-extraction
```

**Verify all attestation types without extraction:**
```bash
./cosign-extract.sh --image registry.example.com/myapp:latest --choice all --verify --no-extraction
```

#### Command Line Options

```
Usage:
  ./cosign-extract.sh --type TYPE --image IMAGE[:TAG] [--choice index|all] [--output FILE] [--verify] [--no-extraction]
  ./cosign-extract.sh --image IMAGE[:TAG] --choice all --output DIR
  ./cosign-extract.sh --image IMAGE[:TAG] --list [--show-null]
  ./cosign-extract.sh --image IMAGE[:TAG] --inspect-null
  ./cosign-extract.sh --type TYPE --image IMAGE[:TAG] --verify --no-extraction  # verify only, no extraction

Options:
  --type TYPE               Attestation type (slsa|cyclonedx|spdx|vuln|license|triage|custom)
  --image IMAGE             Fully qualified image reference (required)
  --choice                  Which attestation to fetch: index, all
  --last                    Automatically select the most recent attestation if multiple exist
  --output PATH             Output file (single type) or directory (all types)
  --predicate-only          Extract only the predicate content (useful for raw SBOM extraction for Trivy)
  --list                    List available predicateTypes and counts
  --show-null               Show entries missing predicateType in --list
  --inspect-null            Inspect referrers missing predicateType
  --verify                  Verify attestations using cosign before extraction
  --no-extraction           Skip extraction and content output (useful with --verify for verification-only)
  --certificate-oidc-issuer ISSUER    OIDC issuer for verification (default: https://token.actions.githubusercontent.com)
  --certificate-identity-regexp REGEX Identity regexp for verification (default: Aleph Alpha workflows)
  -h, --help                Show this help

Verification:
  When --verify is used, attestations are verified using cosign verify-attestation before extraction.
  Default verification uses GitHub Actions OIDC issuer and Aleph Alpha workflow identity patterns.
  Use --no-extraction to skip content output and only perform verification.
```

#### Interactive Mode

When multiple attestations of the same type are found, the script will prompt you to select which one to extract:

```bash
./cosign-extract.sh --type slsa --image registry.example.com/myapp:latest
# Output:
# 🔎 Found 2 attestations for type=slsa:
#   [1] sha256:abc123...
#   [2] sha256:def456...
# Select attestation [1-2]: 1
```

#### Automatic Selection Mode

Use the `--last` flag to automatically select the most recent attestation without interactive prompts:

```bash
./cosign-extract.sh --type triage --image registry.example.com/myapp:latest --last
# Output:
# 🔎 Found 2 attestations for type=triage:
#   [1] sha256:abc123...
#   [2] sha256:def456...
# ℹ️  Automatically selecting most recent attestation [2/2]
```

This is particularly useful for:
- **Automated workflows** where user interaction is not possible
- **CI/CD pipelines** that need the latest attestation data
- **Scripts** that require deterministic behavior without prompts

#### Cryptographic Verification

The script supports cryptographic verification of attestations using Cosign before extraction. This ensures that:

- **Authenticity**: Attestations are signed by trusted entities
- **Integrity**: Attestations haven't been tampered with
- **Identity Verification**: Signatures come from expected workflows/identities

**Default Verification Settings:**
- **OIDC Issuer**: `https://token.actions.githubusercontent.com` (GitHub Actions)
- **Identity Pattern**: Aleph Alpha shared workflows (`https://github.com/Aleph-Alpha/shared-workflows/.github/workflows/(build-and-push|scan-and-attest).yaml@.*`)

**Custom Verification:**
You can override the default verification parameters:

```bash
# Verify with custom GitHub organization workflows
./cosign-extract.sh --type spdx --image myregistry.com/app:latest --verify \
  --certificate-identity-regexp "https://github.com/myorg/.*/.github/workflows/.*"

# Verify with different OIDC issuer
./cosign-extract.sh --type slsa --image myregistry.com/app:latest --verify \
  --certificate-oidc-issuer https://accounts.google.com \
  --certificate-identity-regexp ".*@mycompany.com"
```

**Verification Process:**
1. Script checks if `cosign` is installed
2. Runs `cosign verify-attestation` with specified parameters
3. Only proceeds with extraction if verification succeeds
4. Displays verification status and details

**Verification-Only Mode:**
Use `--no-extraction` to perform verification without extracting content. This is useful for:
- **CI/CD pipelines** that only need to verify attestation authenticity
- **Security audits** where you only need to confirm signatures are valid
- **Compliance checks** without exposing sensitive attestation content
- **Quick verification** without the overhead of content processing

When `--verify --no-extraction` is used together, the script optimizes performance by exiting immediately after successful verification, skipping the ORAS discovery and download phases entirely.

```bash
# Just verify that SLSA provenance exists and is valid
./cosign-extract.sh --type slsa --image myapp:latest --verify --no-extraction

# Verify all attestations are properly signed
./cosign-extract.sh --image myapp:latest --choice all --verify --no-extraction
```

#### cosign-verify-image.sh

A dedicated script for verifying container image signatures using Cosign. This tool focuses specifically on image signature verification (not attestations) and supports both keyless and key-based verification methods.

#### Features

- **Multiple Verification Modes**: Keyless verification (default), key-based verification, or custom OIDC configurations
- **Flexible Identity Matching**: Support for exact identity matching or regex patterns
- **Signature Extraction**: Save signatures and certificates to files for further analysis
- **Flexible Output Levels**: Configurable verbosity (none, info, verbose) for different use cases
- **Non-Failing Mode**: `--no-error` flag allows checking signature status without failing on unsigned images
- **Digest Resolution**: Automatically resolves tags to digests for secure verification
- **Pre-configured Defaults**: Ready-to-use settings for Aleph Alpha workflows

#### Verification Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **Keyless** (default) | Uses OIDC identity and transparency log | GitHub Actions, automated workflows |
| **Key-based** | Uses provided public key file | Traditional key-pair signing |
| **Custom Keyless** | Custom OIDC issuer and identity patterns | Other CI/CD systems, custom workflows |

#### Usage Examples

**Verify with default Aleph Alpha settings:**
```bash
./cosign-verify-image.sh --image registry.example.com/myapp:latest
```

**Verify with custom GitHub organization:**
```bash
./cosign-verify-image.sh --image registry.example.com/myapp:latest \
  --certificate-identity-regexp "https://github.com/myorg/.*/.github/workflows/.*"
```

**Verify with specific workflow identity:**
```bash
./cosign-verify-image.sh --image registry.example.com/myapp:latest \
  --certificate-identity "https://github.com/myorg/myrepo/.github/workflows/build.yaml@refs/heads/main"
```

**Verify with public key file:**
```bash
./cosign-verify-image.sh --image registry.example.com/myapp:latest --key cosign.pub
```

**Verbose verification with signature extraction:**
```bash
./cosign-verify-image.sh --image registry.example.com/myapp:latest --output-level verbose \
  --output-signature signature.sig --output-certificate cert.pem
```

**Silent mode for automation (only exit codes):**
```bash
./cosign-verify-image.sh --image registry.example.com/myapp:latest --output-level none
```

**Check if image is signed without failing (useful for discovery):**
```bash
./cosign-verify-image.sh --image registry.example.com/myapp:latest --output-level none --no-error
```

#### Command Line Options

```
Usage:
  ./cosign-verify-image.sh --image IMAGE[:TAG] [--verify-options]
  ./cosign-verify-image.sh --image IMAGE[:TAG] --certificate-oidc-issuer ISSUER --certificate-identity-regexp REGEX
  ./cosign-verify-image.sh --image IMAGE[:TAG] --key KEY_FILE
  ./cosign-verify-image.sh --image IMAGE[:TAG] --keyless

Options:
  --image IMAGE                         Fully qualified image reference (required)
  --certificate-oidc-issuer ISSUER      OIDC issuer for keyless verification (default: https://token.actions.githubusercontent.com)
  --certificate-identity-regexp REGEX   Identity regexp for keyless verification (default: Aleph Alpha workflows)
  --certificate-identity IDENTITY       Exact certificate identity for keyless verification
  --key KEY_FILE                        Path to public key file for key-based verification
  --keyless                             Use keyless verification (default mode)
  --rekor-url URL                       Rekor transparency log URL (default: https://rekor.sigstore.dev)
  --output-signature FILE               Save signature to file
  --output-certificate FILE             Save certificate to file
  --output-level LEVEL                  Output verbosity: none, info (default), verbose
  --no-error                            Return exit code 0 even on verification failure
  -h, --help                            Show this help
```

#### Security Features

- **Digest-based Verification**: Automatically resolves tags to digests when `crane` is available
- **Transparency Log Integration**: Uses Rekor transparency log for keyless verification
- **Identity Validation**: Strict OIDC identity matching to prevent impersonation
- **Comprehensive Error Reporting**: Clear feedback on verification failures with troubleshooting hints

## 📋 Prerequisites

Before using these scripts, ensure you have the following tools installed:

- **bash** (version 4.0 or later)
- **jq** - JSON processor for parsing and formatting JSON data
- **crane** - Tool for interacting with container registries
- **docker** - Container runtime (for registry accessibility checking in k8s-image-scanner.sh)
- **cosign** - Container signing and verification tool
- **trivy** - Container vulnerability scanner (for k8s-image-scanner.sh)
- **column** - Table formatting utility (usually pre-installed on Unix systems)

### Installation of Prerequisites

**macOS (using Homebrew):**
```bash
brew install jq crane cosign trivy
```

**Ubuntu/Debian:**
```bash
# Install jq
sudo apt-get update && sudo apt-get install -y jq

# Install crane
curl -sL "https://github.com/google/go-containerregistry/releases/latest/download/go-containerregistry_$(uname -s)_$(uname -m).tar.gz" | tar -xz crane
sudo mv crane /usr/local/bin/

# Install cosign
curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
sudo mv cosign-linux-amd64 /usr/local/bin/cosign
sudo chmod +x /usr/local/bin/cosign

# Install trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

## 🚀 Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/Aleph-Alpha/support.git
   cd support
   ```

2. Make the scripts executable:
   ```bash
   chmod +x scanner/k8s-image-scanner.sh cosign-scan-image.sh cosign-extract.sh cosign-verify-image.sh
   ```

3. Optionally, add the scripts to your PATH or create symlinks in `/usr/local/bin/` for system-wide access.

## 🤝 Contributing

We welcome contributions to improve these support scripts! Please feel free to:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure your code follows the existing style and includes appropriate error handling and documentation.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🏢 About Aleph Alpha

[Aleph Alpha](https://aleph-alpha.com) researches, develops and deploys sovereign, explainable AI. At the heart of our offering is PhariaAI – a modular AI suite that empowers enterprises and governments to build, customize, and operate their own AI infrastructure to maintain critical digital sovereignty. Instead of renting black-box technology, organizations retain full ownership, independence, and control over their data, processes, and value creation.

Our support scripts are designed to assist customers and the broader community in streamlining workflows and enhancing efficiency when working with containerized applications and security attestation processes. By simplifying complex tasks, optimizing performance, and ensuring compliance, these tools empower users to focus on innovation and secure deployment practices.

---

For questions, issues, or feature requests, please open an issue in this repository or contact our support team.
