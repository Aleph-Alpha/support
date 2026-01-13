"""Caching module for scan results and attestations."""

import json
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Dict, Any

from ..utils.subprocess import run_command
from ..utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class CacheStats:
    """Cache statistics."""
    total_size_bytes: int
    total_images: int
    attestation_types: int
    sbom_cyclonedx: int
    sbom_spdx: int
    triage_files: int
    valid_items: int
    expired_items: int


class ScanCache:
    """
    Cache for scan results, SBOMs, and attestations.
    
    Uses image digests as cache keys for accuracy.
    """

    def __init__(
        self,
        cache_dir: Optional[str] = None,
        ttl_hours: int = 24,
        enabled: bool = True,
    ):
        """
        Initialize cache.

        Args:
            cache_dir: Cache directory path
            ttl_hours: Cache TTL in hours
            enabled: Whether caching is enabled
        """
        if cache_dir is None:
            cache_dir = os.path.expanduser("~/.cache/k8s-image-scanner")
        
        self.cache_dir = Path(cache_dir)
        self.ttl_hours = ttl_hours
        self.ttl_seconds = ttl_hours * 3600
        self.enabled = enabled

    def init(self) -> None:
        """Initialize cache directory."""
        if self.enabled:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Cache directory: {self.cache_dir} (TTL: {self.ttl_hours}h)")
        else:
            logger.debug("Caching disabled")

    def clear(self) -> None:
        """Clear all cached data."""
        if self.cache_dir.exists():
            logger.info(f"Clearing cache directory: {self.cache_dir}")
            shutil.rmtree(self.cache_dir)
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            logger.success("Cache cleared")

    def _get_image_digest(self, image: str) -> Optional[str]:
        """Get image digest for cache key."""
        result = run_command(["crane", "digest", image], timeout=30)
        if result.success:
            return result.stdout.strip().replace("sha256:", "")
        return None

    def _get_cache_key(self, image: str) -> str:
        """Get cache key for an image."""
        digest = self._get_image_digest(image)
        if digest:
            return digest
        # Fallback to sanitized image name
        import re
        return re.sub(r"[^A-Za-z0-9._-]", "_", image)

    def _get_image_cache_dir(self, image: str) -> Path:
        """Get cache directory for an image."""
        key = self._get_cache_key(image)
        return self.cache_dir / key

    def _is_file_valid(self, filepath: Path) -> bool:
        """Check if a cached file is still valid (within TTL)."""
        if not filepath.exists():
            return False
        
        file_age = time.time() - filepath.stat().st_mtime
        return file_age < self.ttl_seconds

    def get_attestation_type(self, image: str) -> Optional[str]:
        """
        Get cached attestation type for an image.

        Args:
            image: Image reference

        Returns:
            Cached attestation type or None
        """
        if not self.enabled:
            return None

        cache_file = self._get_image_cache_dir(image) / "attestation-type.json"
        
        if self._is_file_valid(cache_file):
            try:
                with open(cache_file) as f:
                    data = json.load(f)
                atype = data.get("attestation_type")
                if atype:
                    logger.debug(f"Cache hit: attestation type for {image}")
                    return atype
            except (json.JSONDecodeError, FileNotFoundError):
                pass
        
        return None

    def set_attestation_type(self, image: str, attestation_type: str) -> None:
        """
        Cache attestation type for an image.

        Args:
            image: Image reference
            attestation_type: Attestation type value
        """
        if not self.enabled:
            return

        cache_dir = self._get_image_cache_dir(image)
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / "attestation-type.json"

        digest = self._get_image_digest(image)

        data = {
            "cached_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "cache_version": "1.0",
            "image": image,
            "image_digest": digest or "",
            "attestation_type": attestation_type,
            "ttl_hours": self.ttl_hours,
        }

        with open(cache_file, "w") as f:
            json.dump(data, f, indent=2)

        logger.debug(f"Cached attestation type for {image}: {attestation_type}")

    def get_sbom(self, image: str, sbom_type: str = "cyclonedx") -> Optional[Path]:
        """
        Get cached SBOM file for an image.

        Args:
            image: Image reference
            sbom_type: SBOM format (cyclonedx or spdx)

        Returns:
            Path to cached SBOM or None
        """
        if not self.enabled:
            return None

        cache_file = self._get_image_cache_dir(image) / f"sbom-{sbom_type}.json"
        
        if self._is_file_valid(cache_file):
            logger.debug(f"Cache hit: SBOM ({sbom_type}) for {image}")
            return cache_file
        
        return None

    def set_sbom(self, image: str, sbom_file: str, sbom_type: str = "cyclonedx") -> None:
        """
        Cache SBOM file for an image.

        Args:
            image: Image reference
            sbom_file: Path to SBOM file
            sbom_type: SBOM format
        """
        if not self.enabled or not Path(sbom_file).exists():
            return

        cache_dir = self._get_image_cache_dir(image)
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / f"sbom-{sbom_type}.json"

        shutil.copy(sbom_file, cache_file)
        logger.debug(f"Cached SBOM ({sbom_type}) for {image}")

    def get_triage(self, image: str) -> Optional[Path]:
        """
        Get cached triage file for an image.

        Args:
            image: Image reference

        Returns:
            Path to cached triage or None
        """
        if not self.enabled:
            return None

        cache_file = self._get_image_cache_dir(image) / "triage.json"
        
        if self._is_file_valid(cache_file):
            logger.debug(f"Cache hit: triage for {image}")
            return cache_file
        
        return None

    def set_triage(self, image: str, triage_file: str) -> None:
        """
        Cache triage file for an image.

        Args:
            image: Image reference
            triage_file: Path to triage file
        """
        if not self.enabled or not Path(triage_file).exists():
            return

        cache_dir = self._get_image_cache_dir(image)
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / "triage.json"

        shutil.copy(triage_file, cache_file)
        logger.debug(f"Cached triage for {image}")

    def get_stats(self) -> CacheStats:
        """
        Get cache statistics.

        Returns:
            CacheStats with cache information
        """
        stats = CacheStats(
            total_size_bytes=0,
            total_images=0,
            attestation_types=0,
            sbom_cyclonedx=0,
            sbom_spdx=0,
            triage_files=0,
            valid_items=0,
            expired_items=0,
        )

        if not self.cache_dir.exists():
            return stats

        # Calculate total size
        for path in self.cache_dir.rglob("*"):
            if path.is_file():
                stats.total_size_bytes += path.stat().st_size

        # Count items by type
        for entry in self.cache_dir.iterdir():
            if not entry.is_dir():
                continue
            
            stats.total_images += 1

            # Check attestation type
            atype_file = entry / "attestation-type.json"
            if atype_file.exists():
                if self._is_file_valid(atype_file):
                    stats.attestation_types += 1
                    stats.valid_items += 1
                else:
                    stats.expired_items += 1

            # Check SBOM files
            for sbom_file in ["sbom-cyclonedx.json", "sbom-spdx.json"]:
                file_path = entry / sbom_file
                if file_path.exists():
                    if self._is_file_valid(file_path):
                        if "cyclonedx" in sbom_file:
                            stats.sbom_cyclonedx += 1
                        else:
                            stats.sbom_spdx += 1
                        stats.valid_items += 1
                    else:
                        stats.expired_items += 1

            # Check triage file
            triage_file = entry / "triage.json"
            if triage_file.exists():
                if self._is_file_valid(triage_file):
                    stats.triage_files += 1
                    stats.valid_items += 1
                else:
                    stats.expired_items += 1

        return stats

    def print_stats(self) -> None:
        """Print cache statistics to console."""
        stats = self.get_stats()

        def format_bytes(b: int) -> str:
            """Format bytes to human readable."""
            if b >= 1073741824:
                return f"{b / 1073741824:.2f} GB"
            elif b >= 1048576:
                return f"{b / 1048576:.2f} MB"
            elif b >= 1024:
                return f"{b / 1024:.2f} KB"
            return f"{b} B"

        print("📊 Cache Statistics")
        print("=" * 40)
        print()
        print("Cache Configuration:")
        print(f"  Directory: {self.cache_dir}")
        print(f"  TTL: {self.ttl_hours} hours")
        print()
        print("Cache Size:")
        print(f"  Total: {format_bytes(stats.total_size_bytes)}")
        print(f"  Cached images: {stats.total_images}")
        print()
        print("Cached Items:")
        print(f"  Attestation types: {stats.attestation_types}")
        print(f"  SBOM (CycloneDX): {stats.sbom_cyclonedx}")
        print(f"  SBOM (SPDX): {stats.sbom_spdx}")
        print(f"  Triage files: {stats.triage_files}")
        print(f"  Total cached items: {stats.valid_items}")
        if stats.expired_items > 0:
            print(f"  Expired items: {stats.expired_items}")
        print()
        print("💡 Tip: Use --clear-cache to clear expired entries, "
              "or --no-cache to disable caching")

