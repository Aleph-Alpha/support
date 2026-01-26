"""Cosign signature verification module.

Equivalent to cosign-verify-image.sh
"""

from dataclasses import dataclass
from typing import Optional
from ..utils.subprocess import run_command, run_with_timeout
from ..utils.logging import get_logger, is_verbose
from .cache import get_digest_cache

logger = get_logger(__name__)


@dataclass
class VerificationResult:
    """Result of signature verification."""
    success: bool
    message: str
    certificate_issuer: Optional[str] = None
    certificate_identity: Optional[str] = None
    signature_file: Optional[str] = None
    certificate_file: Optional[str] = None


class CosignVerifier:
    """
    Verify container image signatures using cosign.

    Supports both keyless and key-based verification modes.
    """

    DEFAULT_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
    DEFAULT_IDENTITY_REGEXP = (
        "https://github.com/Aleph-Alpha/shared-workflows/"
        ".github/workflows/build-and-push.yaml@.*"
    )
    DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"

    def __init__(
        self,
        certificate_oidc_issuer: str = DEFAULT_OIDC_ISSUER,
        certificate_identity_regexp: Optional[str] = DEFAULT_IDENTITY_REGEXP,
        certificate_identity: Optional[str] = None,
        key_file: Optional[str] = None,
        rekor_url: str = DEFAULT_REKOR_URL,
        timeout: int = 60,
    ):
        """
        Initialize the verifier.

        Args:
            certificate_oidc_issuer: OIDC issuer for keyless verification
            certificate_identity_regexp: Identity regexp for keyless verification
            certificate_identity: Exact identity for keyless verification
            key_file: Path to public key file for key-based verification
            rekor_url: Rekor transparency log URL
            timeout: Timeout for verification operations
        """
        self.certificate_oidc_issuer = certificate_oidc_issuer
        self.certificate_identity_regexp = certificate_identity_regexp
        self.certificate_identity = certificate_identity
        self.key_file = key_file
        self.rekor_url = rekor_url
        self.timeout = timeout
        self.keyless = key_file is None

    def resolve_image_digest(self, image: str) -> Optional[str]:
        """
        Resolve image tag to digest using crane (cached).

        Args:
            image: Image reference

        Returns:
            Image digest or None if resolution fails
        """
        digest = get_digest_cache().get_or_fetch(image, timeout=30)
        if not digest and is_verbose():
            logger.warning(f"Failed to resolve digest for {image}")
        return digest

    def verify(
        self,
        image: str,
        output_signature: Optional[str] = None,
        output_certificate: Optional[str] = None,
    ) -> VerificationResult:
        """
        Verify an image signature.

        Args:
            image: Image reference to verify
            output_signature: Path to save signature (optional)
            output_certificate: Path to save certificate (optional)

        Returns:
            VerificationResult with verification status
        """
        # Resolve digest for more secure verification
        digest = self.resolve_image_digest(image)
        if digest:
            image_ref = f"{image}@{digest}"
            logger.debug(f"Using image digest: {digest}")
        else:
            image_ref = image
            if is_verbose():
                logger.warning("Using tag reference (less secure)")

        logger.debug(f"Verifying image signature for: {image_ref}")

        # Build cosign arguments
        args = ["cosign", "verify"]

        if self.keyless:
            logger.debug(f"Mode: Keyless verification")
            logger.debug(f"OIDC Issuer: {self.certificate_oidc_issuer}")

            args.extend([f"--certificate-oidc-issuer={self.certificate_oidc_issuer}"])

            if self.certificate_identity:
                logger.debug(f"Identity: {self.certificate_identity}")
                args.append(f"--certificate-identity={self.certificate_identity}")
            elif self.certificate_identity_regexp:
                logger.debug(f"Identity Regexp: {self.certificate_identity_regexp}")
                args.append(
                    f"--certificate-identity-regexp={self.certificate_identity_regexp}"
                )

            args.append(f"--rekor-url={self.rekor_url}")
        else:
            logger.debug(f"Mode: Key-based verification")
            logger.debug(f"Public Key: {self.key_file}")
            args.append(f"--key={self.key_file}")

        if output_signature:
            args.append(f"--output-signature={output_signature}")
        if output_certificate:
            args.append(f"--output-certificate={output_certificate}")

        args.append(image_ref)

        # Execute verification
        result = run_with_timeout(args, self.timeout)

        if result.success:
            logger.debug("Image signature verification successful!")
            return VerificationResult(
                success=True,
                message="Image is cryptographically signed and verified!",
                signature_file=output_signature,
                certificate_file=output_certificate,
            )
        else:
            error_msg = result.stderr or "Verification failed"
            if is_verbose():
                logger.error(f"Image signature verification failed: {error_msg}")
            return VerificationResult(
                success=False,
                message=error_msg,
            )

    def is_signed(self, image: str) -> bool:
        """
        Check if an image is signed (without full verification).

        Args:
            image: Image reference

        Returns:
            True if image appears to be signed
        """
        result = self.verify(image)
        return result.success
