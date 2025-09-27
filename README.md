# Aleph Alpha Support Scripts

A collection of public support scripts and utilities for Aleph Alpha customers to help with container security, attestation management, and other operational tasks.

## 📋 Table of Contents

- [Overview](#overview)
- [Scripts](#scripts)
  - [cosign-extract.sh](#cosign-extractsh)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Contributing](#contributing)
- [License](#license)

## 🔍 Overview

This repository contains utility scripts designed to help Aleph Alpha customers manage and interact with container images, security attestations, and related infrastructure components. These tools are particularly useful for organizations working with signed container images and security compliance requirements.

## 🛠️ Scripts

### cosign-extract.sh

A powerful bash script for extracting and inspecting Cosign attestations from container images. This tool helps you retrieve various types of security attestations including SLSA provenance, SBOM data, vulnerability reports, and custom attestations.

#### Features

- **Multiple Attestation Types**: Supports SLSA, CycloneDX, SPDX, vulnerability reports, license information, triage data, and custom attestations
- **Flexible Extraction**: Extract single attestations, all attestations of a specific type, or all available attestations
- **Discovery Mode**: List available attestation types for any container image
- **Inspection Tools**: Inspect referrers with missing predicate types
- **Output Options**: Save to files or output to stdout with proper JSON formatting

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

#### Command Line Options

```
Usage:
  ./cosign-extract.sh --type TYPE --image IMAGE[:TAG] [--choice index|all] [--output FILE]
  ./cosign-extract.sh --image IMAGE[:TAG] --choice all --output DIR
  ./cosign-extract.sh --image IMAGE[:TAG] --list [--show-null]
  ./cosign-extract.sh --image IMAGE[:TAG] --inspect-null

Options:
  --type TYPE     Attestation type (slsa|cyclonedx|spdx|vuln|license|triage|custom)
  --image IMAGE   Fully qualified image reference (required)
  --choice        Which attestation to fetch: index, all
  --output PATH   Output file (single type) or directory (all types)
  --list          List available predicateTypes and counts
  --show-null     Show entries missing predicateType in --list
  --inspect-null  Inspect referrers missing predicateType
  -h, --help      Show this help
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

## 📋 Prerequisites

Before using these scripts, ensure you have the following tools installed:

- **bash** (version 4.0 or later)
- **jq** - JSON processor for parsing and formatting JSON data
- **crane** - Tool for interacting with container registries
- **oras** - OCI Registry As Storage client for working with OCI artifacts

### Installation of Prerequisites

**macOS (using Homebrew):**
```bash
brew install jq crane oras
```

**Ubuntu/Debian:**
```bash
# Install jq
sudo apt-get update && sudo apt-get install -y jq

# Install crane
curl -sL "https://github.com/google/go-containerregistry/releases/latest/download/go-containerregistry_$(uname -s)_$(uname -m).tar.gz" | tar -xz crane
sudo mv crane /usr/local/bin/

# Install oras
curl -LO "https://github.com/oras-project/oras/releases/latest/download/oras_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/').tar.gz"
tar -xzf oras_*.tar.gz
sudo mv oras /usr/local/bin/
```

## 🚀 Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/Aleph-Alpha/support.git
   cd support
   ```

2. Make the scripts executable:
   ```bash
   chmod +x cosign-extract.sh
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

[Aleph Alpha](https://aleph-alpha.com) is a leading AI company focused on developing and deploying large language models and AI solutions. These support scripts are provided to help our customers and the broader community work more effectively with containerized applications and security attestations.

---

For questions, issues, or feature requests, please open an issue in this repository or contact our support team.
