#!/usr/bin/env python3
"""
Generate image-source-analysis.json from scan-summary.json by finding repositories
and analyzing their dependencies and Dockerfiles.

This script searches for repositories matching images from scan-summary.json in:
1. Recursively in ../ (excluding support folder)
2. Recursively in ../../ (excluding aleph-alpha folder)

Usage:
    python3 generate-image-source-analysis.py [--verbose] [--scan-summary FILE] [--output FILE]
"""

import json
import argparse
import re
import yaml
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
import sys
import subprocess
from datetime import datetime

# Try to import toml (may not be available)
try:
    import toml
    HAS_TOML = True
except ImportError:
    HAS_TOML = False
    # Fallback: basic TOML parsing for simple cases
    def toml_load(file_path):
        """Basic TOML parser for simple cases."""
        content = file_path.read_text(encoding='utf-8')
        result = {}
        current_section = result
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('[') and line.endswith(']'):
                section = line[1:-1].strip()
                if section not in result:
                    result[section] = {}
                current_section = result[section]
            elif '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                current_section[key] = value
        return result

# Dependency file patterns by language
DEPENDENCY_FILES = {
    'python': [
        'requirements.txt',
        'pyproject.toml',
        'poetry.lock',
        'Pipfile',
        'Pipfile.lock',
        'setup.py',
        'setup.cfg',
        'uv.lock',
    ],
    'go': [
        'go.mod',
        'go.sum',
        'Gopkg.toml',
        'Gopkg.lock',
        'glide.yaml',
        'glide.lock',
    ],
    'rust': [
        'Cargo.toml',
        'Cargo.lock',
    ],
    'nodejs': [
        'package.json',
        'package-lock.json',
        'pnpm-lock.yaml',
        'yarn.lock',
        'npm-shrinkwrap.json',
    ],
}

# Dockerfile patterns
DOCKERFILE_PATTERNS = [
    'Dockerfile',
    'Dockerfile.*',
    '*.dockerfile',
    'docker/Dockerfile',
    'docker/Dockerfile.*',
    '.dockerfile',
]


def extract_image_name(image: str) -> str:
    """
    Extract the base image name from a full image string.
    
    Examples:
        harbor.management-prod01.stackit.run/pharia-data/data:v0.52.2 -> data
        harbor.management-prod01.stackit.run/pharia-os-images/pharia-os-app:1.24.1 -> pharia-os-app
        quay.io/prometheuscommunity/postgres-exporter:v0.17.1 -> postgres-exporter
    """
    # Remove registry prefix
    parts = image.split('/')
    if len(parts) > 1:
        # Get the last part (image:tag)
        image_part = parts[-1]
    else:
        image_part = parts[0]
    
    # Remove tag
    if ':' in image_part:
        image_part = image_part.split(':')[0]
    
    return image_part


def extract_image_tag(image: str) -> Optional[str]:
    """Extract the tag/version from a full image string."""
    parts = image.split('/')
    if len(parts) > 0:
        image_part = parts[-1]
        if ':' in image_part:
            return image_part.split(':', 1)[1]
    return None


def extract_artifact_from_helm_chart(chart_dir: Path, image: str) -> Optional[Dict[str, str]]:
    """
    Extract artifact name and version from Helm chart values.yaml and templates.
    
    Returns dict with 'name' and 'version' keys, or None if not found.
    """
    image_name = extract_image_name(image)
    image_tag = extract_image_tag(image)
    
    # Try to parse values.yaml
    for values_file in [chart_dir / "values.yaml", chart_dir / "values.yml"]:
        if not values_file.exists():
            continue
        
        try:
            content = values_file.read_text(encoding='utf-8')
            # Check if image is referenced
            if image_name not in content and image not in content:
                continue
            
            # Try to parse as YAML
            try:
                values = yaml.safe_load(content)
                if not isinstance(values, dict):
                    continue
                
                # Search for image references in values structure
                def find_image_ref(obj, path=""):
                    """Recursively search for image references."""
                    if isinstance(obj, dict):
                        for key, value in obj.items():
                            new_path = f"{path}.{key}" if path else key
                            if key in ['image', 'repository', 'imageName']:
                                if isinstance(value, str):
                                    if image_name in value or image in value:
                                        return {'name': image_name, 'version': image_tag}
                            elif isinstance(value, (dict, list)):
                                result = find_image_ref(value, new_path)
                                if result:
                                    return result
                    elif isinstance(obj, list):
                        for item in obj:
                            result = find_image_ref(item, path)
                            if result:
                                return result
                    return None
                
                result = find_image_ref(values)
                if result:
                    return result
            except yaml.YAMLError:
                # If YAML parsing fails, try regex matching
                pass
            
            # Fallback: regex search for image patterns
            # Look for patterns like: image: "repo/image:tag" or repository: "repo/image"
            patterns = [
                rf'image:\s*["\']?([^"\'\s]+{re.escape(image_name)}[^"\'\s]*)["\']?',
                rf'repository:\s*["\']?([^"\'\s]+{re.escape(image_name)}[^"\'\s]*)["\']?',
                rf'["\']?([^"\'\s]*{re.escape(image)}[^"\'\s]*)["\']?',
            ]
            
            for pattern in patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    return {
                        'name': image_name,
                        'version': image_tag or ''
                    }
        except (IOError, UnicodeDecodeError):
            continue
    
    # Try templates directory
    templates_dir = chart_dir / "templates"
    if templates_dir.exists():
        for template_file in templates_dir.rglob("*.yaml"):
            try:
                content = template_file.read_text(encoding='utf-8')
                if image_name in content or image in content:
                    # Look for image references in templates
                    patterns = [
                        rf'image:\s*["\']?([^"\'\s]+{re.escape(image_name)}[^"\'\s]*)["\']?',
                        rf'["\']?([^"\'\s]*{re.escape(image)}[^"\'\s]*)["\']?',
                    ]
                    for pattern in patterns:
                        match = re.search(pattern, content, re.IGNORECASE)
                        if match:
                            return {
                                'name': image_name,
                                'version': image_tag or ''
                            }
            except (IOError, UnicodeDecodeError):
                continue
    
    return None


def extract_repo_name_from_image(image: str) -> Optional[str]:
    """
    Try to extract repository name from image path.
    
    Examples:
        harbor.management-prod01.stackit.run/pharia-data/data:v0.52.2 -> pharia-data
        harbor.management-prod01.stackit.run/pharia-os-images/pharia-os-app:1.24.1 -> pharia-os
    """
    parts = image.split('/')
    if len(parts) >= 2:
        # Usually the second-to-last part is the repo/org name
        namespace = parts[-2]
        
        # Remove common suffixes to get base name
        # e.g., "pharia-os-images" -> "pharia-os"
        for suffix in ['-images', '-container-images', 'container-images']:
            if namespace.endswith(suffix):
                namespace = namespace[:-len(suffix)]
                break
        
        return namespace
    return None


def normalize_repo_name(name: str) -> str:
    """Normalize repository name for matching (lowercase, remove special chars)."""
    return name.lower().replace('_', '-').replace(' ', '-')


def normalize_for_comparison(name: str) -> str:
    """
    Normalize name for comparison by removing hyphens.
    This helps match 'pharia-os' with 'phariaos'.
    """
    return normalize_repo_name(name).replace('-', '').replace('_', '')


def is_repository_directory(path: Path) -> bool:
    """Check if a directory looks like a repository."""
    # Must have .git or dependency files
    if (path / '.git').exists():
        return True
    
    # Or have dependency files
    if has_dependency_files(path):
        return True
    
    return False


def calculate_name_similarity(repo_name: str, image_name: str) -> float:
    """
    Calculate similarity score between repo name and image name.
    Returns a score from 0.0 to 1.0, where 1.0 is exact match.
    """
    repo_norm = normalize_repo_name(repo_name)
    image_norm = normalize_repo_name(image_name)
    
    # Exact match
    if repo_norm == image_norm:
        return 1.0
    
    # Normalize without hyphens for comparison
    repo_no_hyphen = normalize_for_comparison(repo_name)
    image_no_hyphen = normalize_for_comparison(image_name)
    
    # Exact match without hyphens (e.g., pharia-os vs phariaos)
    if repo_no_hyphen == image_no_hyphen:
        return 0.95
    
    # Prefix match: image name is a prefix of repo name (e.g., inference -> inference-worker)
    if repo_norm.startswith(image_norm + '-') or repo_norm.startswith(image_norm + '_'):
        return 0.9
    
    # Prefix match: repo name is a prefix of image name (e.g., catch -> catch-backend)
    # This handles cases where image is "catch-api" and repo is "catch-backend"
    if image_norm.startswith(repo_norm + '-') or image_norm.startswith(repo_norm + '_'):
        return 0.85
    
    # One contains the other (substring match)
    if image_norm in repo_norm:
        # Longer the match relative to image name, higher the score
        return 0.7 + (len(image_norm) / len(repo_norm)) * 0.15
    if repo_norm in image_norm:
        return 0.7 + (len(repo_norm) / len(image_norm)) * 0.15
    
    # Handle compound names (e.g., "pharia-os-app" matches "pharia-os")
    image_parts = image_norm.split('-')
    repo_parts = repo_norm.split('-')
    
    # If image name parts are all in repo name
    if len(image_parts) > 1 and all(part in repo_norm for part in image_parts):
        matched_parts = sum(1 for part in image_parts if part in repo_norm)
        return 0.6 + (matched_parts / len(image_parts)) * 0.2
    
    # If repo name parts are all in image name
    if len(repo_parts) > 1 and all(part in image_norm for part in repo_parts):
        matched_parts = sum(1 for part in repo_parts if part in image_norm)
        return 0.6 + (matched_parts / len(repo_parts)) * 0.2
    
    # Check without hyphens for partial matches
    if image_no_hyphen in repo_no_hyphen or repo_no_hyphen in image_no_hyphen:
        return 0.5
    
    return 0.0


def matches_image_name(repo_name: str, image_name: str, repo_hint: Optional[str] = None, min_similarity: float = 0.5) -> bool:
    """
    Check if repository name matches image name with various heuristics.
    
    Args:
        repo_name: Repository name to check
        image_name: Image name to match against
        repo_hint: Optional hint from image path (e.g., 'pharia-os' from 'pharia-os-images')
        min_similarity: Minimum similarity score to consider a match (default: 0.5)
    
    Returns:
        True if similarity score >= min_similarity
    """
    # Check direct match
    similarity = calculate_name_similarity(repo_name, image_name)
    if similarity >= min_similarity:
        return True
    
    # Check with repo hint if provided
    if repo_hint:
        hint_norm = normalize_repo_name(repo_hint)
        repo_norm = normalize_repo_name(repo_name)
        
        # Hint matches repo name
        if hint_norm in repo_norm or repo_norm in hint_norm:
            # Then check if image name matches
            similarity = calculate_name_similarity(repo_name, image_name)
            if similarity >= 0.3:  # Lower threshold when hint matches
                return True
        
        # Check hint without hyphens
        hint_no_hyphen = normalize_for_comparison(repo_hint)
        repo_no_hyphen = normalize_for_comparison(repo_name)
        if hint_no_hyphen in repo_no_hyphen or repo_no_hyphen in hint_no_hyphen:
            similarity = calculate_name_similarity(repo_name, image_name)
            if similarity >= 0.3:
                return True
    
    return False


def extract_artifact_from_repo(repo_path: Path) -> List[Dict[str, str]]:
    """
    Extract artifact names and versions from repository dependency files.
    
    Returns list of dicts with 'name', 'version', and 'file' keys.
    """
    artifacts = []
    
    # Check Cargo.toml (Rust)
    for cargo_file in repo_path.rglob("Cargo.toml"):
        try:
            if HAS_TOML:
                cargo_data = toml.load(cargo_file)
            else:
                cargo_data = toml_load(cargo_file)
            if 'package' in cargo_data:
                pkg = cargo_data['package']
                if 'name' in pkg:
                    artifact = {
                        'name': str(pkg['name']),
                        'version': str(pkg.get('version', '')),
                        'file': str(cargo_file.relative_to(repo_path))
                    }
                    artifacts.append(artifact)
        except (Exception, KeyError, AttributeError):
            pass
    
    # Check package.json (Node.js)
    for pkg_file in repo_path.rglob("package.json"):
        try:
            with open(pkg_file, 'r', encoding='utf-8') as f:
                pkg_data = json.load(f)
                if 'name' in pkg_data:
                    artifact = {
                        'name': pkg_data['name'],
                        'version': pkg_data.get('version', ''),
                        'file': str(pkg_file.relative_to(repo_path))
                    }
                    artifacts.append(artifact)
        except Exception:
            pass
    
    # Check pyproject.toml (Python)
    for pyproject_file in repo_path.rglob("pyproject.toml"):
        try:
            if HAS_TOML:
                pyproject_data = toml.load(pyproject_file)
            else:
                pyproject_data = toml_load(pyproject_file)
            # Check [project] section
            if 'project' in pyproject_data:
                project = pyproject_data['project']
                if isinstance(project, dict) and 'name' in project:
                    artifact = {
                        'name': str(project['name']),
                        'version': str(project.get('version', '')),
                        'file': str(pyproject_file.relative_to(repo_path))
                    }
                    artifacts.append(artifact)
            # Check [tool.poetry] section
            elif ('tool' in pyproject_data and
                  isinstance(pyproject_data['tool'], dict) and
                  'poetry' in pyproject_data['tool']):
                poetry = pyproject_data['tool']['poetry']
                if isinstance(poetry, dict) and 'name' in poetry:
                    artifact = {
                        'name': str(poetry['name']),
                        'version': str(poetry.get('version', '')),
                        'file': str(pyproject_file.relative_to(repo_path))
                    }
                    artifacts.append(artifact)
        except (Exception, KeyError, AttributeError):
            pass
    
    # Check setup.py (Python - basic regex extraction)
    for setup_file in repo_path.rglob("setup.py"):
        try:
            content = setup_file.read_text(encoding='utf-8')
            # Look for name= and version= patterns
            name_match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', content)
            version_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
            if name_match:
                artifact = {
                    'name': name_match.group(1),
                    'version': version_match.group(1) if version_match else '',
                    'file': str(setup_file.relative_to(repo_path))
                }
                artifacts.append(artifact)
        except Exception:
            pass
    
    return artifacts


def matches_artifact(repo_artifact: Dict[str, str], helm_artifact: Dict[str, str]) -> bool:
    """
    Check if a repository artifact matches a Helm chart artifact.
    
    Matches based on:
    1. Name similarity (normalized, handles hyphens)
    2. Version compatibility (exact match or semantic version compatibility)
    """
    repo_name = normalize_for_comparison(repo_artifact['name'])
    helm_name = normalize_for_comparison(helm_artifact['name'])
    
    # Name must match (with hyphen normalization)
    if repo_name != helm_name:
        # Try with image name extraction
        image_name_norm = normalize_for_comparison(extract_image_name(helm_artifact['name']))
        if repo_name != image_name_norm:
            return False
    
    # Version matching (if both have versions)
    repo_version = repo_artifact.get('version', '')
    helm_version = helm_artifact.get('version', '')
    
    if repo_version and helm_version:
        # Exact match
        if repo_version == helm_version:
            return True
        
        # Try semantic version comparison (basic)
        # Remove 'v' prefix if present
        repo_v = repo_version.lstrip('v')
        helm_v = helm_version.lstrip('v')
        
        # Check if major.minor matches (allows patch differences)
        repo_parts = repo_v.split('.')
        helm_parts = helm_v.split('.')
        if len(repo_parts) >= 2 and len(helm_parts) >= 2:
            if repo_parts[0] == helm_parts[0] and repo_parts[1] == helm_parts[1]:
                return True
    
    # If name matches but no version info, still consider it a match
    return True


def find_helm_charts_for_image(image: str, search_paths: List[Path], helm_chart_repos: List[Path]) -> List[Path]:
    """
    Find Helm charts that reference the given image.
    
    Strategy:
    1. First search in dedicated Helm chart repositories (faster, more reliable)
    2. Then search in wider paths if needed
    
    This confirms the image is actually used and helps identify the source repository.
    """
    image_name = extract_image_name(image)
    
    # Also try without registry prefix
    image_without_registry = image.split('/')[-1] if '/' in image else image
    if ':' in image_without_registry:
        image_without_registry = image_without_registry.split(':')[0]
    
    found_charts = []
    
    def search_in_path(search_path: Path):
        """Helper to search for charts in a specific path."""
        if not search_path.exists():
            return
        
        # Search for Chart.yaml files
        try:
            for chart_file in search_path.rglob("Chart.yaml"):
                chart_dir = chart_file.parent
                
                # Skip if already found
                if chart_dir in found_charts:
                    continue
                
                # Check values.yaml files
                for values_file in [chart_dir / "values.yaml", chart_dir / "values.yml"]:
                    if not values_file.exists():
                        continue
                    
                    try:
                        content = values_file.read_text()
                        # Check if image is referenced
                        if image in content or image_without_registry in content or image_name in content:
                            found_charts.append(chart_dir)
                            return  # Found in this path, can stop
                    except (IOError, UnicodeDecodeError):
                        pass
                
                # Check template files
                templates_dir = chart_dir / "templates"
                if templates_dir.exists():
                    for template_file in templates_dir.rglob("*.yaml"):
                        try:
                            content = template_file.read_text()
                            if image in content or image_without_registry in content or image_name in content:
                                found_charts.append(chart_dir)
                                return  # Found in this path, can stop
                        except (IOError, UnicodeDecodeError):
                            pass
        except (PermissionError, OSError):
            pass
    
    # Step 1: Search in Helm chart repositories first (prioritized)
    for helm_repo in helm_chart_repos:
        search_in_path(helm_repo)
        if found_charts:  # If found, we can stop early
            return found_charts
    
    # Step 2: Search in wider paths if not found in Helm chart repos
    for search_path in search_paths:
        search_in_path(search_path)
    
    return found_charts


def get_git_commit_date(repo_path: Path) -> Optional[datetime]:
    """
    Get the date of the most recent commit in a git repository.
    Returns None if not a git repo or if git command fails.
    """
    if not (repo_path / '.git').exists():
        return None
    
    try:
        result = subprocess.run(
            ['git', 'log', '-1', '--format=%ct', 'HEAD'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            timestamp = int(result.stdout.strip())
            return datetime.fromtimestamp(timestamp)
    except (subprocess.TimeoutExpired, ValueError, OSError):
        pass
    
    return None


def rank_candidates(candidates: List[Tuple[Path, int]], image_name: str) -> List[Tuple[Path, float]]:
    """
    Rank candidates by multiple factors:
    1. Name similarity score
    2. Git commit recency (newest commits preferred)
    3. Depth (shallower preferred)
    
    Returns list of (path, score) tuples sorted by score (highest first).
    """
    ranked = []
    
    for repo_path, depth in candidates:
        # Calculate name similarity
        similarity = calculate_name_similarity(repo_path.name, image_name)
        
        # Get git commit date
        commit_date = get_git_commit_date(repo_path)
        
        # Calculate composite score
        # Base score: similarity (0.0-1.0) weighted at 60%
        score = similarity * 0.6
        
        # Depth penalty: shallower is better (0-5 depth, normalized to 0-0.2)
        depth_score = max(0, (6 - depth) / 6) * 0.2
        score += depth_score
        
        # Git recency bonus: newer commits get higher score (0-0.2)
        if commit_date:
            # Calculate days since commit (more recent = higher score)
            days_ago = (datetime.now() - commit_date).days
            # Normalize: 0 days = 0.2, 365 days = 0.0
            recency_score = max(0, (365 - days_ago) / 365) * 0.2
            score += recency_score
        else:
            # No git info: small penalty
            score += 0.05
        
        ranked.append((repo_path, score))
    
    # Sort by score (highest first)
    ranked.sort(key=lambda x: x[1], reverse=True)
    return ranked


def find_repos_by_artifact_name(artifact_name: str, search_paths: List[Path],
                                  exclude_dirs: Set[str]) -> List[Path]:
    """
    Fast search for repositories containing artifact name in dependency files.
    
    Uses grep-like search across TOML, package.json, and go.mod files.
    Returns list of repository paths that might contain the artifact.
    """
    candidates = []
    artifact_norm = normalize_for_comparison(artifact_name)
    artifact_lower = artifact_name.lower()
    
    # File patterns to search
    search_patterns = [
        '**/Cargo.toml',
        '**/pyproject.toml',
        '**/package.json',
        '**/go.mod',
        '**/setup.py',
    ]
    
    for search_path in search_paths:
        if not search_path.exists():
            continue
        
        for pattern in search_patterns:
            try:
                for file_path in search_path.rglob(pattern):
                    # Skip excluded directories
                    if any(part in exclude_dirs for part in file_path.parts):
                        continue
                    
                    # Skip if in .git or node_modules
                    if '.git' in file_path.parts or 'node_modules' in file_path.parts:
                        continue
                    
                    try:
                        content = file_path.read_text(encoding='utf-8', errors='ignore')
                        
                        # Quick check: does the artifact name appear?
                        if artifact_lower not in content.lower():
                            continue
                        
                        # More specific checks based on file type
                        found = False
                        
                        if file_path.name == 'Cargo.toml':
                            # Look for [package] name = "artifact_name"
                            if (f'name = "{artifact_name}"' in content or
                                f"name = '{artifact_name}'" in content or
                                f'name = "{artifact_lower}"' in content):
                                found = True
                            # Also check normalized version
                            elif artifact_norm in normalize_for_comparison(content):
                                # Verify it's in a name field
                                if re.search(r'name\s*=\s*["\']([^"\']*)["\']',
                                            content, re.IGNORECASE):
                                    found = True
                        
                        elif file_path.name == 'package.json':
                            # Look for "name": "artifact_name"
                            if (f'"name": "{artifact_name}"' in content or
                                f'"name": "{artifact_lower}"' in content):
                                found = True
                        
                        elif file_path.name == 'pyproject.toml':
                            # Look for name = "artifact_name" in [project] or [tool.poetry]
                            if (f'name = "{artifact_name}"' in content or
                                f"name = '{artifact_name}'" in content or
                                f'name = "{artifact_lower}"' in content):
                                found = True
                        
                        elif file_path.name == 'go.mod':
                            # Look for module artifact_name
                            if (f'module {artifact_name}' in content or
                                f'module {artifact_lower}' in content):
                                found = True
                        
                        elif file_path.name == 'setup.py':
                            # Look for name="artifact_name"
                            if (f'name="{artifact_name}"' in content or
                                f"name='{artifact_name}'" in content or
                                f'name="{artifact_lower}"' in content):
                                found = True
                        
                        if found:
                            # Find the repository root (directory with .git or parent)
                            repo_path = file_path.parent
                            # Walk up to find .git or dependency files
                            for _ in range(5):  # Max 5 levels up
                                if (repo_path / '.git').exists():
                                    break
                                if has_dependency_files(repo_path):
                                    break
                                if repo_path.parent == repo_path:
                                    break
                                repo_path = repo_path.parent
                            
                            if repo_path not in candidates:
                                candidates.append(repo_path)
                    except (IOError, UnicodeDecodeError, PermissionError):
                        continue
            except (PermissionError, OSError):
                continue
    
    return candidates


def find_repository_for_image(image: str, search_paths: List[Path], exclude_dirs: Set[str], helm_chart_repos: List[Path], verbose: bool = False) -> Tuple[Optional[Path], Dict]:
    """
    Find repository directory that matches the given image.
    
    Strategy:
    1. Find Helm charts that reference the image and extract artifact metadata
    2. Search repositories for matching artifact names/versions in dependency files
    3. Fall back to name-based matching if artifact matching fails
    4. Rank candidates by artifact match quality, git recency, and depth
    
    Searches in the provided paths, excluding specified directories.
    
    Returns:
        Tuple of (repo_path, evidence_dict) where evidence contains:
        - match_method: How the repo was found (artifact_match, grep_name_match, etc.)
        - match_score: Confidence score (0.0-1.0)
        - matched_artifact: Artifact info if found via artifact matching
        - artifact_files: List of files where artifact was found
        - helm_charts_found: Number of Helm charts found
        - helm_artifacts: List of artifact metadata from Helm charts
    """
    import time
    
    image_name = extract_image_name(image)
    repo_name_hint = extract_repo_name_from_image(image)
    
    if verbose:
        print(f"\n  → Searching for: {image_name}", flush=True)
    
    # Step 1: Find Helm charts and extract artifact metadata
    step_start = time.time()
    if verbose:
        print(f"  → Step 1: Searching Helm charts in {len(helm_chart_repos)} repos...", end='', flush=True)
    
    helm_charts = find_helm_charts_for_image(image, search_paths, helm_chart_repos)
    helm_artifacts = []
    
    for chart_dir in helm_charts:
        artifact = extract_artifact_from_helm_chart(chart_dir, image)
        if artifact:
            helm_artifacts.append(artifact)
    
    if verbose:
        print(f" found {len(helm_charts)} charts, {len(helm_artifacts)} artifacts ({time.time()-step_start:.1f}s)", flush=True)
    
    # Step 2: Fast grep-based search for artifact names in dependency files
    candidates = []
    
    step_start = time.time()
    if verbose:
        print(f"  → Step 2: Grep search in dependency files...", end='', flush=True)
    
    # First, try fast grep search for the image name
    grep_candidates = find_repos_by_artifact_name(image_name, search_paths,
                                                   exclude_dirs)
    
    if verbose:
        print(f" found {len(grep_candidates)} candidates ({time.time()-step_start:.1f}s)", flush=True)
    
    # If we have artifact info from Helm charts, also search for those names
    if helm_artifacts:
        if verbose:
            print(f"  → Step 2b: Grep search for Helm artifact names...", end='', flush=True)
        step_start = time.time()
        for helm_artifact in helm_artifacts:
            artifact_name = helm_artifact.get('name', image_name)
            additional_candidates = find_repos_by_artifact_name(
                artifact_name, search_paths, exclude_dirs)
            grep_candidates.extend(additional_candidates)
        if verbose:
            print(f" found {len(grep_candidates)} total ({time.time()-step_start:.1f}s)", flush=True)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_grep_candidates = []
    for candidate in grep_candidates:
        if candidate not in seen:
            seen.add(candidate)
            unique_grep_candidates.append(candidate)
    
    # Step 3: Verify grep candidates by extracting and matching artifacts
    if unique_grep_candidates or helm_artifacts:
        step_start = time.time()
        if verbose:
            print(f"  → Step 3: Verifying {len(unique_grep_candidates)} grep candidates...", end='', flush=True)
        
        # First, check the grep candidates (fast path)
        for repo_path in unique_grep_candidates:
            if not is_repository_directory(repo_path):
                continue
            
            # Extract artifacts from this repo
            repo_artifacts = extract_artifact_from_repo(repo_path)
            
            # Check if any repo artifact matches
            artifact_match_found = False
            if helm_artifacts and repo_artifacts:
                # Match against Helm artifacts
                for repo_artifact in repo_artifacts:
                    for helm_artifact in helm_artifacts:
                        if matches_artifact(repo_artifact, helm_artifact):
                            # Strong match based on artifact metadata
                            depth = len(repo_path.parts) - len(search_paths[0].parts) if search_paths else 0
                            candidates.append((
                                repo_path, depth, 1.0, repo_artifact
                            ))
                            artifact_match_found = True
                            break
                    if artifact_match_found:
                        break
            
            # If found via grep but no artifact match, still add it
            if not artifact_match_found:
                # Check if name matches
                if matches_image_name(repo_path.name, image_name, repo_name_hint):
                    depth = len(repo_path.parts) - len(search_paths[0].parts) if search_paths else 0
                    # Grep-based name match (good confidence)
                    score = 0.7 if repo_artifacts else 0.6
                    candidates.append((
                        repo_path, depth, score, repo_artifacts[0] if repo_artifacts else None
                    ))
        
        if verbose:
            print(f" {len(candidates)} matches ({time.time()-step_start:.1f}s)", flush=True)
        
        # Also do recursive search for completeness (but prioritize grep results)
        step_start = time.time()
        if verbose:
            print(f"  → Step 3b: Recursive search (depth 5) in {len(search_paths)} paths...", end='', flush=True)
        
        for search_path in search_paths:
            if not search_path.exists():
                continue
            
            # Search recursively for repos with matching artifacts
            try:
                def search_recursive(path: Path, current_depth: int, max_depth: int):
                    """Recursively search directories up to max_depth."""
                    if current_depth > max_depth:
                        return
                    
                    try:
                        for item in path.iterdir():
                            if not item.is_dir():
                                continue
                            
                            # Skip excluded directories
                            if item.name in exclude_dirs:
                                continue
                            
                            # Check if any parent is excluded
                            if any(part in exclude_dirs for part in item.parts):
                                continue
                            
                            # Skip if already found via grep
                            if item in unique_grep_candidates:
                                continue
                            
                            # Check if it's a repository
                            if not is_repository_directory(item):
                                # Recurse deeper
                                if current_depth < max_depth:
                                    search_recursive(item, current_depth + 1, max_depth)
                                continue
                            
                            # Check if name matches (always check this)
                            name_matches = matches_image_name(item.name, image_name,
                                                              repo_name_hint)
                            
                            if name_matches:
                                # Extract artifacts to check for bonus score
                                repo_artifacts = extract_artifact_from_repo(item)
                                
                                # Check if any repo artifact matches Helm artifacts
                                artifact_match_found = False
                                if helm_artifacts and repo_artifacts:
                                    for repo_artifact in repo_artifacts:
                                        for helm_artifact in helm_artifacts:
                                            if matches_artifact(repo_artifact,
                                                              helm_artifact):
                                                # Strong match: name + artifact
                                                candidates.append((
                                                    item, current_depth, 1.0,
                                                    repo_artifact
                                                ))
                                                artifact_match_found = True
                                                break
                                        if artifact_match_found:
                                            break
                                
                                # If no artifact match, still add based on name
                                if not artifact_match_found:
                                    # Name match only (lower score)
                                    candidates.append((
                                        item, current_depth, 0.5, None
                                    ))
                            
                            # Recurse deeper
                            if current_depth < max_depth:
                                search_recursive(item, current_depth + 1, max_depth)
                    except (PermissionError, OSError):
                        pass
                
                # Search up to 5 levels deep (handles nested monorepos)
                search_recursive(search_path, 0, 5)
            except (PermissionError, OSError):
                continue
        
        if verbose:
            print(f" {len(candidates)} total candidates ({time.time()-step_start:.1f}s)", flush=True)
    
    # Step 4: Additional name-based search if still no candidates
    if not candidates:
        step_start = time.time()
        if verbose:
            print(f"  → Step 4: Fallback name-based search...", end='', flush=True)
    
    for search_path in search_paths:
        if not search_path.exists():
            continue
        
        # First, try direct children (most common case)
        try:
            for item in search_path.iterdir():
                if not item.is_dir():
                    continue
                
                # Skip excluded directories
                if item.name in exclude_dirs:
                    continue
                
                # Check if it matches and is a repository
                if matches_image_name(item.name, image_name, repo_name_hint):
                    if is_repository_directory(item):
                            candidates.append((
                                item, 0, 0.0, None
                            ))  # depth, score, artifact
        except (PermissionError, OSError):
            continue
        
        # Then try recursive search (limited depth for performance)
        try:
            def search_recursive_fallback(path: Path, current_depth: int,
                                           max_depth: int):
                """Recursively search directories up to max_depth."""
                if current_depth > max_depth:
                    return
                
                try:
                    for item in path.iterdir():
                        if not item.is_dir():
                            continue
                        
                        # Skip excluded directories
                        if item.name in exclude_dirs:
                            continue
                        
                        # Check if any parent is excluded
                        if any(part in exclude_dirs for part in item.parts):
                            continue
                        
                        # Check if it matches and is a repository
                        if matches_image_name(item.name, image_name,
                                              repo_name_hint):
                            if is_repository_directory(item):
                                candidates.append((
                                    item, current_depth, 0.0, None
                                ))
                        
                        # Recurse deeper
                        if current_depth < max_depth:
                            search_recursive_fallback(item,
                                                      current_depth + 1,
                                                      max_depth)
                except (PermissionError, OSError):
                    pass
            
            # Search up to 5 levels deep
            search_recursive_fallback(search_path, 1, 5)
        except (PermissionError, OSError):
            continue
    
        if verbose:
            print(f" {len(candidates)} candidates ({time.time()-step_start:.1f}s)", flush=True)
    
    # Rank and return best match
    if candidates:
        # Sort by score (high to low), then by depth (shallow first)
        candidates.sort(key=lambda x: (-x[2], x[1], len(x[0].parts)))
        
        best_repo_path, best_depth, best_score, best_artifact = candidates[0]
        
        # Build evidence dict
        evidence = {
            'match_score': best_score,
            'search_depth': best_depth,
            'helm_charts_found': len(helm_charts),
            'helm_artifacts': helm_artifacts,
        }
        
        # Add artifact evidence if available
        if best_artifact:
            evidence['matched_artifact'] = best_artifact
            evidence['artifact_files'] = []
            # Find which files contained the artifact
            for lang, dep_files in DEPENDENCY_FILES.items():
                for dep_file in dep_files:
                    file_path = best_repo_path / dep_file
                    if file_path.exists():
                        try:
                            content = file_path.read_text(encoding='utf-8', errors='ignore')
                            artifact_name = best_artifact.get('name', '')
                            if artifact_name and artifact_name.lower() in content.lower():
                                evidence['artifact_files'].append(str(file_path.relative_to(best_repo_path)))
                        except:
                            pass
        
        # Determine match method
        if best_score >= 1.0:
            evidence['match_method'] = 'artifact_match'
        elif best_score >= 0.6:
            evidence['match_method'] = 'grep_name_match'
        elif best_score >= 0.3:
            evidence['match_method'] = 'recursive_name_match'
        else:
            evidence['match_method'] = 'fallback_name_match'
        
        # Additional ranking for name-based candidates with same score
        if candidates[0][2] < 1.0:  # No perfect artifact match
            # Use name similarity and git recency for final ranking
            name_based_candidates = [(c[0], c[1]) for c in candidates]
            ranked = rank_candidates(name_based_candidates, image_name)
            if ranked and ranked[0][1] >= 0.3:
                evidence['git_ranking_applied'] = True
                evidence['name_similarity'] = ranked[0][1]
                return (ranked[0][0], evidence)
        
        # Return the best candidate
        if candidates[0][2] >= 0.3:  # Minimum score threshold
            return (best_repo_path, evidence)
    
    return (None, {})


def has_dependency_files(repo_path: Path) -> bool:
    """Check if a directory looks like a repository with dependency files."""
    for lang, files in DEPENDENCY_FILES.items():
        for dep_file in files:
            if (repo_path / dep_file).exists():
                return True
    return False


def find_dependency_files(repo_path: Path) -> Dict[str, List[str]]:
    """Find all dependency files in a repository."""
    dependencies = {}
    
    for lang, files in DEPENDENCY_FILES.items():
        found_files = []
        for dep_file in files:
            # Check exact match
            if (repo_path / dep_file).exists():
                found_files.append(dep_file)
            else:
                # Check for glob patterns
                if '*' in dep_file:
                    pattern = dep_file.replace('*', '**')
                    for match in repo_path.rglob(pattern):
                        if match.is_file():
                            rel_path = str(match.relative_to(repo_path))
                            if rel_path not in found_files:
                                found_files.append(rel_path)
        
        if found_files:
            dependencies[lang] = found_files
    
    return dependencies


def find_dockerfiles(repo_path: Path) -> List[str]:
    """Find all Dockerfiles in a repository."""
    dockerfiles = []
    
    for pattern in DOCKERFILE_PATTERNS:
        if '*' in pattern:
            # Glob pattern
            for match in repo_path.rglob(pattern):
                if match.is_file():
                    rel_path = str(match.relative_to(repo_path))
                    if rel_path not in dockerfiles:
                        dockerfiles.append(rel_path)
        else:
            # Exact match
            if (repo_path / pattern).exists():
                dockerfiles.append(pattern)
    
    # Also check common locations
    common_locations = [
        'Dockerfile',
        'docker/Dockerfile',
        '.docker/Dockerfile',
        'build/Dockerfile',
    ]
    
    for location in common_locations:
        if (repo_path / location).exists() and location not in dockerfiles:
            dockerfiles.append(location)
    
    return sorted(dockerfiles)


def get_git_remote_url(repo_path: Path) -> Optional[str]:
    """
    Get the git remote URL for a repository.
    
    Returns the URL of the 'origin' remote, or None if not a git repo.
    """
    try:
        result = subprocess.run(
            ['git', 'config', '--get', 'remote.origin.url'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
        pass
    return None


def is_public_image(image: str) -> bool:
    """Determine if an image is public (from public registries)."""
    public_registries = [
        'docker.io',
        'quay.io',
        'gcr.io',
        'k8s.gcr.io',
        'ghcr.io',
    ]
    
    for registry in public_registries:
        if image.startswith(registry):
            return True
    
    return False


def get_repo_name_from_path(repo_path: Path) -> str:
    """Extract repository name from path."""
    return repo_path.name


def main():
    """Main function to generate image-source-analysis.json."""
    parser = argparse.ArgumentParser(
        description='Generate image-source-analysis.json from scan-summary.json',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This script searches for repositories matching images from scan-summary.json in:
1. Recursively in ../ (excluding support folder)
2. Recursively in ../../ (excluding aleph-alpha folder)
        """
    )
    parser.add_argument(
        '--scan-summary',
        type=str,
        help='Path to scan-summary.json (default: ../k8s-images/scan-summary.json)'
    )
    parser.add_argument(
        '--output',
        type=str,
        help='Path to output file (default: image-source-analysis.json in script directory)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    script_dir = Path(__file__).parent
    support_dir = script_dir.parent.parent  # ../.. from postgres-dependency-scanner
    
    # Input file
    if args.scan_summary:
        scan_summary_file = Path(args.scan_summary)
    else:
        # Default: scan-results/k8s-images/scan-summary.json
        scan_summary_file = support_dir / 'scan-results' / 'k8s-images' / 'scan-summary.json'
    
    if not scan_summary_file.exists():
        print(f"Error: {scan_summary_file} not found", file=sys.stderr)
        sys.exit(1)
    
    # Output file
    if args.output:
        output_file = Path(args.output)
    else:
        # Default: scan-results/postgres-analysis/image-source-analysis.json
        output_file = support_dir / 'scan-results' / 'postgres-analysis' / 'image-source-analysis.json'
    
    verbose = args.verbose
    
    # Load scan summary
    if verbose:
        print(f"Loading scan summary from: {scan_summary_file}")
    with open(scan_summary_file, 'r') as f:
        scan_summary = json.load(f)
    
    # Collect all images
    all_images = set()
    all_images.update(scan_summary.get('successful_scans', []))
    all_images.update(scan_summary.get('failed_scans', []))
    all_images.update(scan_summary.get('skipped_scans', []))
    
    print(f"Found {len(all_images)} unique images to analyze")
    if verbose:
        print(f"  - Successful scans: {len(scan_summary.get('successful_scans', []))}")
        print(f"  - Failed scans: {len(scan_summary.get('failed_scans', []))}")
        print(f"  - Skipped scans: {len(scan_summary.get('skipped_scans', []))}")
    print()
    
    # Define search paths
    # 1. ../ (aleph-alpha directory, excluding support folder)
    search_path_1 = support_dir.parent
    # 2. ../../ (all repositories)
    search_path_2 = support_dir.parent.parent
    
    # Only exclude support directory (where this script lives)
    exclude_dirs = {'support'}
    
    # Define Helm chart repositories (searched first, prioritized)
    helm_chart_repos = []
    helm_chart_base = search_path_2  # Start from repositories root
    
    # Common Helm chart repository patterns
    helm_chart_patterns = [
        '**/pharia-ai-helm-chart',
        '**/pharia-ai-prod-deployments',
        '**/inference-helm-charts',
        '**/catch-deployment',
        '**/creance-helm-chart',
        '**/pharia-studio-deployment',
        '**/phariaos-deployment',
        '**/*-deployment',
        '**/*-helm-chart',
        '**/*-helm-charts',
    ]
    
    # Find Helm chart repositories
    if verbose:
        print(f"Searching for Helm chart repositories in {helm_chart_base}...")
        sys.stdout.flush()
    
    helm_search_start = time.time()
    if helm_chart_base.exists():
        for pattern_idx, pattern in enumerate(helm_chart_patterns, 1):
            if verbose:
                print(f"  [{pattern_idx}/{len(helm_chart_patterns)}] Searching pattern: {pattern}", end=' ', flush=True)
            pattern_start = time.time()
            try:
                for helm_repo in helm_chart_base.rglob(pattern):
                    if (helm_repo.is_dir() and
                        ((helm_repo / 'Chart.yaml').exists() or
                         any((helm_repo / f).exists()
                             for f in ['values.yaml', 'templates']))):
                        if helm_repo not in helm_chart_repos:
                            helm_chart_repos.append(helm_repo)
            except (PermissionError, OSError):
                pass
            if verbose:
                pattern_time = time.time() - pattern_start
                print(f"({pattern_time:.2f}s, found {len(helm_chart_repos)} total)")
    
    helm_search_time = time.time() - helm_search_start
    if verbose:
        print(f"✓ Helm chart search completed in {helm_search_time:.2f}s\n")
    
    if verbose:
        print(f"Search paths:")
        print(f"  1. {search_path_1} (excluding: support)")
        print(f"  2. {search_path_2} (excluding: support)")
        print(f"\nHelm chart repositories (searched first): {len(helm_chart_repos)}")
        if verbose and helm_chart_repos:
            for helm_repo in helm_chart_repos[:10]:  # Show first 10
                print(f"    - {helm_repo}")
            if len(helm_chart_repos) > 10:
                print(f"    ... and {len(helm_chart_repos) - 10} more")
        print()
    
    # Process each image
    results = []
    found_count = 0
    not_found_count = 0
    
    start_time = time.time()
    
    for idx, image in enumerate(sorted(all_images), 1):
        image_start = time.time()
        
        if verbose:
            print(f"[{idx}/{len(all_images)}] Processing: {image}...", end=' ', flush=True)
        else:
            # Show progress for non-verbose mode
            elapsed = time.time() - start_time
            avg_time = elapsed / idx if idx > 0 else 0
            remaining = (len(all_images) - idx) * avg_time
            print(f"[{idx}/{len(all_images)} | {elapsed:.1f}s | ~{remaining:.0f}s left] {image[:50]}...", end=' ', flush=True)
        
        # Check if public
        is_public = is_public_image(image)
        
        # Try to find repository
        repo_path, evidence = find_repository_for_image(
            image,
            [search_path_1, search_path_2],
            exclude_dirs,
            helm_chart_repos,
            verbose=verbose
        )
        
        if repo_path:
            image_time = time.time() - image_start
            if verbose:
                print(f"✓ Found: {repo_path.name} ({image_time:.2f}s)")
            else:
                print(f"✓ {repo_path.name} ({image_time:.1f}s)")
            found_count += 1
            
            # Analyze repository
            dependencies = find_dependency_files(repo_path)
            dockerfiles = find_dockerfiles(repo_path)
            repo_name = get_repo_name_from_path(repo_path)
            git_remote_url = get_git_remote_url(repo_path)
            
            results.append({
                'image': image,
                'repo': repo_name,
                'repo_path': str(repo_path.resolve()),
                'git_remote_url': git_remote_url,
                'status': 'found',
                'is_public': is_public,
                'dependencies': dependencies,
                'dockerfiles': dockerfiles,
                'evidence': evidence
            })
        else:
            image_time = time.time() - image_start
            if verbose:
                print(f"✗ Not found ({image_time:.2f}s)")
            else:
                print(f"✗ ({image_time:.1f}s)")
            not_found_count += 1
            
            # Still add to results with status 'not_found'
            results.append({
                'image': image,
                'repo': extract_image_name(image),
                'repo_path': None,
                'status': 'not_found',
                'is_public': is_public,
                'dependencies': {},
                'dockerfiles': [],
            })
    
    # Create output structure
    output_data = {
        'results': results
    }
    
    # Write output
    total_time = time.time() - start_time
    print(f"\n{'='*80}")
    print("SUMMARY")
    print(f"{'='*80}")
    print(f"Total images: {len(all_images)}")
    print(f"Repositories found: {found_count}")
    print(f"Repositories not found: {not_found_count}")
    print(f"Total time: {total_time:.1f}s ({total_time/len(all_images):.2f}s per image)")
    print(f"\nWriting results to: {output_file}")
    
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)
    
    print(f"✓ Successfully generated: {output_file}")


if __name__ == '__main__':
    main()
