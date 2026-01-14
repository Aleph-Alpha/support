# Aleph Alpha - Container Image Security Scanner (Python)

A Python implementation of the Aleph Alpha container image security scanning tools. This package provides functionality for:

- **Kubernetes namespace scanning** - Extract and scan all container images from a Kubernetes namespace
- **Single image scanning** - Scan individual container images using SBOM attestations
- **Signature verification** - Verify Cosign signatures on container images
- **Attestation extraction** - Extract SBOM, triage, and other attestations from images
- **Chainguard verification** - Verify if images use Chainguard base images

## Prerequisites

This package uses external CLI tools for most operations. Ensure the following are installed:

| Tool | Purpose | Installation |
|------|---------|--------------|
| `kubectl` | Kubernetes access | [kubectl install](https://kubernetes.io/docs/tasks/tools/) |
| `trivy` | Vulnerability scanning | [trivy install](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) |
| `cosign` | Signature verification | [cosign install](https://docs.sigstore.dev/cosign/installation/) |
| `crane` | Image digest resolution | [crane install](https://github.com/google/go-containerregistry/tree/main/cmd/crane) |
| `oras` | OCI artifact handling | [oras install](https://oras.land/docs/installation) |
| `docker` | Registry authentication | [docker install](https://docs.docker.com/get-docker/) |
| `jq` | JSON processing | `brew install jq` or `apt install jq` |

## Installation

```bash
# Install from source
cd scanner_py
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"
```

## Usage

The package provides a unified CLI with multiple subcommands:

### Kubernetes Namespace Scanning

Scan all container images in a Kubernetes namespace:

```bash
# Scan default namespace (pharia-ai)
scanner-py trivy-scan

# Scan specific namespace
scanner-py trivy-scan --namespace production

# With ignore file and custom output
scanner-py trivy-scan --namespace staging --ignore-file ./ignore.txt --output-dir ./reports

# Dry run to see what would be scanned
scanner-py trivy-scan --namespace production --dry-run

# Test mode - scan only first valid image
scanner-py trivy-scan --test-flow
```

### Single Image Scanning

Scan a single container image:

```bash
# Basic scan (HIGH and CRITICAL severities)
scanner-py scan-image --image registry.io/app:v1.0

# Scan with MEDIUM severity and above
scanner-py scan-image --image myregistry.io/app:latest --severity MEDIUM

# JSON output format
scanner-py scan-image --image myimage:tag --format json --output-dir ./reports

# Without triage filtering (show all CVEs)
scanner-py scan-image --image myimage:tag --no-triage
```

### Signature Verification

Verify Cosign signatures on container images:

```bash
# Verify with default Aleph Alpha settings
scanner-py verify --image registry.io/app:v1.0

# Verify with custom identity regexp
scanner-py verify --image registry.io/app:v1.0 \
  --certificate-identity-regexp "https://github.com/myorg/.*"

# Verify with public key
scanner-py verify --image registry.io/app:v1.0 --key cosign.pub

# Silent mode for automation
scanner-py verify --image registry.io/app:v1.0 --output-level none
```

### Attestation Extraction

Extract attestations (SBOM, triage, etc.) from images:

```bash
# List available attestations
scanner-py extract --image registry.io/app:v1.0 --list

# Extract SBOM (CycloneDX)
scanner-py extract --image registry.io/app:v1.0 --type cyclonedx --output sbom.json

# Extract only predicate content
scanner-py extract --image registry.io/app:v1.0 --type cyclonedx --predicate-only --output sbom.json

# Extract triage with verification
scanner-py extract --image registry.io/app:v1.0 --type triage --verify --output triage.json
```

### Chainguard Base Image Verification

Check if an image uses a Chainguard base image:

```bash
# Check base image
scanner-py verify-chainguard --image registry.io/app:v1.0

# Silent mode for automation
scanner-py verify-chainguard --image myapp:latest --output-level none

# Without failing on mismatch
scanner-py verify-chainguard --image myapp:latest --no-error
```

## Python API

You can also use the package programmatically:

```python
from scanner_py import ImageScanner, CosignVerifier, AttestationExtractor

# Scan an image
scanner = ImageScanner(output_dir="./results", format="json")
result = scanner.scan("registry.io/app:v1.0")
print(f"Found {result.total_cves} CVEs")

# Verify signature
verifier = CosignVerifier()
result = verifier.verify("registry.io/app:v1.0")
print(f"Verification: {'✅' if result.success else '❌'}")

# Extract SBOM
extractor = AttestationExtractor()
sbom = extractor.extract_sbom("registry.io/app:v1.0", "sbom.json")
```

## Caching

The scanner supports caching to speed up repeated scans:

```bash
# Show cache statistics
scanner-py trivy-scan --cache-stats

# Clear cache
scanner-py trivy-scan --clear-cache

# Disable caching
scanner-py trivy-scan --no-cache

# Custom cache directory and TTL
scanner-py trivy-scan --cache-dir ~/.my-cache --cache-ttl 12
```

## Output Formats

- **table** - Human-readable table format (default)
- **json** - JSON format for programmatic processing
- **sarif** - SARIF format for integration with code scanning tools

## Severity Levels

- **CRITICAL** - Only critical vulnerabilities
- **HIGH** - High and critical (default)
- **MEDIUM** - Medium, high, and critical
- **LOW** - All vulnerabilities

## Verbose Mode

By default, error messages are suppressed to keep output clean. Use `--verbose` to see detailed error messages and debug information:

```bash
# Normal mode - clean output with progress bar
scanner-py trivy-scan --namespace production

# Verbose mode - shows all errors and debug info
scanner-py trivy-scan --namespace production --verbose

# Single image with verbose mode
scanner-py scan-image --image myapp:latest --verbose

# Verification with verbose mode
scanner-py verify --image myapp:latest --output-level verbose
```

### Output Behavior

| Mode | Progress | Errors | Debug Info |
|------|----------|--------|------------|
| Normal | ✅ Progress bar | ❌ Hidden | ❌ Hidden |
| Verbose | ✅ Progress bar | ✅ Shown | ✅ Shown |

This makes the tool ideal for both interactive use (clean progress) and debugging (full details).

## Progress Indicators

The scanner includes visual progress indicators:

- **Progress Bar**: Shows completion status during batch operations
- **Spinner**: Shows activity during single operations
- **Status Counts**: Real-time success/failure/skipped counts

Example progress output:
```
Scanning images [████████████████░░░░] 80.0% (8/10) ✓6 ✗1 ⊘1 app:v1.2
```

- `✓` = Successful scans
- `✗` = Failed scans  
- `⊘` = Skipped scans (unsigned images)

## Project Structure

```
scanner_py/
├── __init__.py           # Package initialization
├── __main__.py           # Entry point for python -m
├── cli/                  # CLI implementations
│   ├── __init__.py       # Main CLI entry point
│   ├── k8s_scanner.py    # Kubernetes scanner CLI
│   ├── scan_image.py     # Single image scanner CLI
│   ├── verify_image.py   # Signature verification CLI
│   ├── extract.py        # Attestation extraction CLI
│   └── verify_chainguard.py  # Chainguard verification CLI
├── core/                 # Core functionality
│   ├── __init__.py
│   ├── attestation.py    # Attestation extraction
│   ├── cache.py          # Caching functionality
│   ├── chainguard.py     # Chainguard verification
│   ├── kubernetes.py     # Kubernetes image extraction
│   ├── scanner.py        # Trivy scanning
│   └── verification.py   # Cosign verification
├── models/               # Data models
│   ├── __init__.py
│   └── scan_result.py    # Result data classes
├── utils/                # Utilities
│   ├── __init__.py
│   ├── logging.py        # Logging configuration (verbose mode)
│   ├── progress.py       # Progress bars and spinners
│   ├── registry.py       # Registry accessibility
│   └── subprocess.py     # Command execution
├── pyproject.toml        # Project configuration
├── requirements.txt      # Dependencies
└── README.md            # This file
```

## Comparison with Bash Scripts

This Python package is a port of the original bash scripts:

| Bash Script | Python Equivalent |
|-------------|-------------------|
| `k8s-image-scanner.sh` | `scanner-py trivy-scan` |
| `cosign-scan-image.sh` | `scanner-py scan-image` |
| `cosign-verify-image.sh` | `scanner-py verify` |
| `cosign-extract.sh` | `scanner-py extract` |
| `verify-chainguard-base-image.sh` | `scanner-py verify-chainguard` |

## License

MIT License - see LICENSE file for details.

