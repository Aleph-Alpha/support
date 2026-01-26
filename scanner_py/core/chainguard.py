"""Chainguard base image verification module.

Equivalent to verify-chainguard-base-image.sh
"""

import json
from dataclasses import dataclass
from typing import Optional, Tuple

from ..utils.subprocess import run_command, run_with_timeout
from ..utils.logging import get_logger, is_verbose

logger = get_logger(__name__)


@dataclass
class ChainguardVerificationResult:
    """Result of Chainguard base image verification."""
    is_chainguard: bool
    base_image: str
    signature_verified: bool
    error: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "is_chainguard": self.is_chainguard,
            "base_image": self.base_image,
            "signature_verified": self.signature_verified,
        }


class ChainguardVerifier:
    """
    Verify if a Docker image is built using a Chainguard base image.
    
    Supports both public Chainguard images (cgr.dev/chainguard/*)
    and Aleph Alpha production images (cgr.dev/aleph-alpha.com/*).
    """

    # Aleph Alpha organization IDs (hardcoded)
    ALEPH_ALPHA_CATALOG_SYNCER = "a494e1f9538be93dd89e483286f716c09f970134/1efb903b603e7516"
    ALEPH_ALPHA_APKO_BUILDER = "a494e1f9538be93dd89e483286f716c09f970134/ff0d9a2471189a21"

    # Public Chainguard verification settings
    PUBLIC_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
    PUBLIC_IDENTITY = (
        "https://github.com/chainguard-images/images/"
        ".github/workflows/release.yaml@refs/heads/main"
    )

    # Production Chainguard verification settings
    PRODUCTION_OIDC_ISSUER = "https://issuer.enforce.dev"

    def __init__(self, timeout: int = 180):
        """
        Initialize verifier.

        Args:
            timeout: Timeout for verification operations
        """
        self.timeout = timeout

    def _extract_base_from_docker_inspect(
        self, config_json: dict
    ) -> Optional[str]:
        """
        Extract base image from Docker inspect output.

        Args:
            config_json: Docker inspect JSON output

        Returns:
            Base image reference or None
        """
        try:
            # Try OCI standard labels first
            labels = config_json[0].get("Config", {}).get("Labels", {}) or {}

            # Base image name label
            base_name = labels.get("org.opencontainers.image.base.name")
            if base_name:
                return base_name

            # Base digest label
            base_digest = labels.get("org.opencontainers.image.base.digest")
            if base_digest:
                return base_digest

            # Parse history for FROM statements
            history = config_json[0].get("History", [])
            for entry in history:
                created_by = entry.get("created_by", "")
                if "FROM" in created_by:
                    # Extract image name from FROM statement
                    parts = created_by.split()
                    for i, part in enumerate(parts):
                        if part.upper() == "FROM" and i + 1 < len(parts):
                            return parts[i + 1]

            # Check parent image
            parent = config_json[0].get("Parent")
            if parent:
                return parent

        except (KeyError, IndexError, TypeError):
            pass

        return None

    def _extract_base_from_crane_config(self, config_json: dict) -> Optional[str]:
        """
        Extract base image from crane config output.

        Args:
            config_json: Crane config JSON output

        Returns:
            Base image reference or None
        """
        try:
            # Try OCI standard labels first
            labels = config_json.get("config", {}).get("Labels", {}) or {}

            # Base image name label
            base_name = labels.get("org.opencontainers.image.base.name")
            if base_name:
                return base_name

            # Base digest label
            base_digest = labels.get("org.opencontainers.image.base.digest")
            if base_digest:
                return base_digest

            # Parse history for FROM statements
            history = config_json.get("history", [])
            for entry in history:
                created_by = entry.get("created_by", "")
                if "FROM" in created_by:
                    parts = created_by.split()
                    for i, part in enumerate(parts):
                        if part.upper() == "FROM" and i + 1 < len(parts):
                            return parts[i + 1]

        except (KeyError, TypeError):
            pass

        return None

    def get_base_image(self, image: str) -> Optional[str]:
        """
        Get the base image for a given image.

        Args:
            image: Image reference

        Returns:
            Base image reference or None
        """
        # Try local Docker inspect first
        result = run_command(
            ["docker", "image", "inspect", image],
            timeout=30,
        )

        if result.success:
            try:
                config = json.loads(result.stdout)
                base = self._extract_base_from_docker_inspect(config)
                if base:
                    return base
            except json.JSONDecodeError:
                pass

        # Fall back to crane config
        result = run_command(["crane", "config", image], timeout=60)

        if result.success:
            try:
                config = json.loads(result.stdout)
                base = self._extract_base_from_crane_config(config)
                if base:
                    return base
            except json.JSONDecodeError:
                pass

        return None

    def _verify_public_chainguard(self, image: str) -> bool:
        """
        Verify a public Chainguard starter image.

        Args:
            image: Image reference (must be cgr.dev/chainguard/*)

        Returns:
            True if verification succeeds
        """
        logger.debug("Using public Chainguard verification")

        result = run_with_timeout(
            [
                "cosign", "verify", image,
                f"--certificate-oidc-issuer={self.PUBLIC_OIDC_ISSUER}",
                f"--certificate-identity={self.PUBLIC_IDENTITY}",
            ],
            self.timeout,
        )

        return result.success

    def _verify_production_chainguard(self, image: str) -> bool:
        """
        Verify an Aleph Alpha production Chainguard image.

        Args:
            image: Image reference (must be cgr.dev/aleph-alpha.com/*)

        Returns:
            True if verification succeeds
        """
        logger.debug("Using production Chainguard verification")

        identity_regexp = (
            f"https://issuer.enforce.dev/("
            f"{self.ALEPH_ALPHA_CATALOG_SYNCER}|"
            f"{self.ALEPH_ALPHA_APKO_BUILDER})"
        )

        result = run_with_timeout(
            [
                "cosign", "verify", image,
                f"--certificate-oidc-issuer={self.PRODUCTION_OIDC_ISSUER}",
                f"--certificate-identity-regexp={identity_regexp}",
            ],
            self.timeout,
        )

        return result.success

    def verify_chainguard_signature(self, image: str) -> Tuple[bool, str]:
        """
        Verify Chainguard signature on an image.

        Args:
            image: Image reference

        Returns:
            Tuple of (success, message)
        """
        logger.debug(f"Verifying Chainguard signature for: {image}")

        # Public Chainguard images
        if image.startswith("cgr.dev/chainguard"):
            if self._verify_public_chainguard(image):
                return True, "Starter Chainguard signature verified"
            return False, "Public Chainguard verification failed"

        # Aleph Alpha production images
        elif image.startswith("cgr.dev/aleph-alpha.com"):
            if self._verify_production_chainguard(image):
                return True, "Production Chainguard signature verified"
            return False, "Production Chainguard verification failed"

        else:
            return False, f"Image '{image}' is not a supported Chainguard image"

    def verify(
        self, image: str, fail_on_mismatch: bool = True
    ) -> ChainguardVerificationResult:
        """
        Verify if an image uses a Chainguard base image.

        Args:
            image: Image reference to check
            fail_on_mismatch: Whether to treat mismatch as error

        Returns:
            ChainguardVerificationResult with verification details
        """
        logger.debug(f"Checking Chainguard base image: {image}")

        # Get base image
        base_image = self.get_base_image(image)

        if not base_image:
            if is_verbose():
                logger.warning("Could not determine base image from metadata")
            return ChainguardVerificationResult(
                is_chainguard=False,
                base_image="unknown",
                signature_verified=False,
                error="Could not determine base image",
            )

        logger.debug(f"Detected base image: {base_image}")

        # Verify Chainguard signature
        success, message = self.verify_chainguard_signature(base_image)

        if success:
            logger.debug("Base image is signed by Chainguard")
            return ChainguardVerificationResult(
                is_chainguard=True,
                base_image=base_image,
                signature_verified=True,
            )
        else:
            if is_verbose():
                logger.warning(f"Chainguard verification failed: {message}")
            return ChainguardVerificationResult(
                is_chainguard=False,
                base_image=base_image,
                signature_verified=False,
                error=message if fail_on_mismatch else None,
            )

    def print_result(self, result: ChainguardVerificationResult) -> None:
        """
        Print verification result.

        Args:
            result: Verification result to print
        """
        print()
        print("📋 Results:")
        print(f"    - Base Image: {result.base_image}")
        print(f"    - Is Chainguard: {result.is_chainguard}")
        print(f"    - Signature Verified: {result.signature_verified}")
        if result.error:
            print(f"    - Error: {result.error}")

