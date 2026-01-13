"""Attestation extraction module.

Equivalent to cosign-extract.sh
"""

import json
import base64
import tempfile
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from pathlib import Path
from enum import Enum

from ..utils.subprocess import run_command, run_with_timeout
from ..utils.logging import get_logger, is_verbose

logger = get_logger(__name__)


class AttestationTypeEnum(Enum):
    """Known attestation types."""
    SLSA = "slsa"
    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"
    VULN = "vuln"
    LICENSE = "license"
    TRIAGE = "triage"
    CUSTOM = "custom"


# Map type names to predicate types
PREDICATE_TYPE_MAP = {
    AttestationTypeEnum.SLSA: "https://slsa.dev/provenance/v1",
    AttestationTypeEnum.CYCLONEDX: "https://cyclonedx.org/bom",
    AttestationTypeEnum.SPDX: "https://spdx.dev/Document",
    AttestationTypeEnum.VULN: "https://cosign.sigstore.dev/attestation/vuln/v1",
    AttestationTypeEnum.LICENSE: "https://aleph-alpha.com/attestations/license/v1",
    AttestationTypeEnum.TRIAGE: "https://aleph-alpha.com/attestations/triage/v1",
    AttestationTypeEnum.CUSTOM: "https://cosign.sigstore.dev/attestation/v1",
}


@dataclass
class AttestationInfo:
    """Information about an attestation."""
    predicate_type: str
    digest: str
    content: Optional[Dict[str, Any]] = None


@dataclass
class AttestationList:
    """List of available attestations."""
    attestations: Dict[str, int] = field(default_factory=dict)

    def has_sbom(self) -> bool:
        """Check if SBOM attestation exists."""
        sbom_types = [
            PREDICATE_TYPE_MAP[AttestationTypeEnum.CYCLONEDX],
            PREDICATE_TYPE_MAP[AttestationTypeEnum.SPDX],
        ]
        return any(pt in self.attestations for pt in sbom_types)

    def has_triage(self) -> bool:
        """Check if triage attestation exists."""
        return PREDICATE_TYPE_MAP[AttestationTypeEnum.TRIAGE] in self.attestations


class AttestationExtractor:
    """
    Extract attestations from container images using cosign and oras.

    Supports SBOM (CycloneDX, SPDX), triage, and other attestation types.
    """

    DEFAULT_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
    DEFAULT_IDENTITY_REGEXP = (
        "https://github.com/Aleph-Alpha/shared-workflows/"
        ".github/workflows/(build-and-push|scan-and-reattest).yaml@.*"
    )

    def __init__(
        self,
        certificate_oidc_issuer: str = DEFAULT_OIDC_ISSUER,
        certificate_identity_regexp: str = DEFAULT_IDENTITY_REGEXP,
        timeout: int = 60,
    ):
        """
        Initialize the extractor.

        Args:
            certificate_oidc_issuer: OIDC issuer for verification
            certificate_identity_regexp: Identity regexp for verification
            timeout: Timeout for operations
        """
        self.certificate_oidc_issuer = certificate_oidc_issuer
        self.certificate_identity_regexp = certificate_identity_regexp
        self.timeout = timeout

    def resolve_digest(self, image: str) -> Optional[str]:
        """
        Resolve image tag to digest.

        Args:
            image: Image reference

        Returns:
            Digest or None
        """
        result = run_command(["crane", "digest", image], timeout=30)
        if result.success:
            return result.stdout.strip()
        return None

    def list_attestations(
        self, image: str, show_null: bool = False
    ) -> AttestationList:
        """
        List available attestations for an image.

        Args:
            image: Image reference
            show_null: Include entries with null predicateType

        Returns:
            AttestationList with predicate types and counts
        """
        digest = self.resolve_digest(image)
        if not digest:
            if is_verbose():
                logger.error(f"Failed to resolve digest for {image}")
            return AttestationList()

        image_with_digest = f"{image}@{digest}"
        logger.debug(f"Listing attestations for: {image_with_digest}")

        # Get referrers
        result = run_command(
            ["oras", "discover", image_with_digest, "--format", "json"],
            timeout=self.timeout,
        )

        if not result.success:
            if is_verbose():
                logger.error(f"Failed to discover referrers: {result.stderr}")
            return AttestationList()

        try:
            data = json.loads(result.stdout)
            referrers = data.get("referrers", [])
        except json.JSONDecodeError:
            if is_verbose():
                logger.error("Failed to parse oras output")
            return AttestationList()

        # Filter for bundle artifact types
        bundle_type = "application/vnd.dev.sigstore.bundle.v0.3+json"
        bundle_refs = [
            r for r in referrers
            if r.get("artifactType") == bundle_type
        ]

        # Extract predicate types from bundles
        predicate_types: Dict[str, int] = {}

        for ref in bundle_refs:
            ref_digest = ref.get("digest")
            if not ref_digest:
                continue

            pred_type = self._get_predicate_type_from_bundle(
                image, ref_digest
            )
            if pred_type:
                predicate_types[pred_type] = predicate_types.get(pred_type, 0) + 1

        return AttestationList(attestations=predicate_types)

    def _get_predicate_type_from_bundle(
        self, image: str, ref_digest: str
    ) -> Optional[str]:
        """
        Extract predicate type from a bundle referrer.

        Args:
            image: Image reference
            ref_digest: Referrer digest

        Returns:
            Predicate type or None
        """
        # Get manifest to find layer digest
        result = run_command(
            ["oras", "manifest", "fetch", f"{image}@{ref_digest}"],
            timeout=30,
        )

        if not result.success:
            return None

        try:
            manifest = json.loads(result.stdout)
            layers = manifest.get("layers", [])
            if not layers:
                return None
            layer_digest = layers[0].get("digest")
        except (json.JSONDecodeError, KeyError, IndexError):
            return None

        if not layer_digest:
            return None

        # Fetch bundle blob
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
            bundle_file = f.name

        result = run_command(
            ["oras", "blob", "fetch", f"{image}@{layer_digest}",
             "--output", bundle_file],
            timeout=30,
        )

        if not result.success:
            Path(bundle_file).unlink(missing_ok=True)
            return None

        try:
            with open(bundle_file) as f:
                bundle = json.load(f)

            # Decode payload
            payload_b64 = bundle.get("dsseEnvelope", {}).get("payload")
            if not payload_b64:
                return None

            payload = json.loads(base64.b64decode(payload_b64))
            return payload.get("predicateType")

        except (json.JSONDecodeError, KeyError):
            return None
        finally:
            Path(bundle_file).unlink(missing_ok=True)

    def extract(
        self,
        image: str,
        attestation_type: AttestationTypeEnum,
        output_file: Optional[str] = None,
        predicate_only: bool = False,
        verify: bool = False,
        use_last: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """
        Extract an attestation from an image.

        Args:
            image: Image reference
            attestation_type: Type of attestation to extract
            output_file: Path to save attestation (optional)
            predicate_only: Extract only predicate content
            verify: Verify attestation before extraction
            use_last: Use most recent attestation if multiple exist

        Returns:
            Attestation content as dictionary or None
        """
        pred_type = PREDICATE_TYPE_MAP.get(attestation_type)
        if not pred_type:
            if is_verbose():
                logger.error(f"Unknown attestation type: {attestation_type}")
            return None

        digest = self.resolve_digest(image)
        if not digest:
            if is_verbose():
                logger.error(f"Failed to resolve digest for {image}")
            return None

        image_with_digest = f"{image}@{digest}"

        # Verify if requested
        if verify:
            if not self._verify_attestation(image_with_digest, pred_type):
                if is_verbose():
                    logger.error("Attestation verification failed")
                return None

        # Find matching referrers
        digests = self._find_attestation_digests(image, pred_type, digest)

        if not digests:
            if is_verbose():
                logger.error(f"No attestations found for type {attestation_type.value}")
            return None

        # Select which attestation to use
        if use_last:
            ref_digest = digests[-1]  # Most recent
        else:
            ref_digest = digests[0]

        # Extract content
        content = self._fetch_attestation_content(image, ref_digest)

        if content is None:
            if is_verbose():
                logger.error("Failed to extract attestation content")
            return None

        # Extract predicate only if requested
        if predicate_only:
            content = content.get("predicate", content)

        # Save to file if requested
        if output_file:
            with open(output_file, "w") as f:
                json.dump(content, f, indent=2)
            logger.debug(f"Attestation written to {output_file}")

        return content

    def _verify_attestation(self, image: str, pred_type: str) -> bool:
        """Verify an attestation using cosign."""
        args = [
            "cosign", "verify-attestation",
            "--type", pred_type,
            "--new-bundle-format",
            f"--certificate-oidc-issuer={self.certificate_oidc_issuer}",
            f"--certificate-identity-regexp={self.certificate_identity_regexp}",
            image,
        ]

        result = run_with_timeout(args, self.timeout)
        return result.success

    def _find_attestation_digests(
        self, image: str, pred_type: str, image_digest: str
    ) -> List[str]:
        """Find all attestation digests matching a predicate type."""
        image_with_digest = f"{image}@{image_digest}"

        result = run_command(
            ["oras", "discover", image_with_digest, "--format", "json"],
            timeout=self.timeout,
        )

        if not result.success:
            return []

        try:
            data = json.loads(result.stdout)
            referrers = data.get("referrers", [])
        except json.JSONDecodeError:
            return []

        bundle_type = "application/vnd.dev.sigstore.bundle.v0.3+json"
        matching_digests = []

        for ref in referrers:
            if ref.get("artifactType") != bundle_type:
                continue

            ref_digest = ref.get("digest")
            if not ref_digest:
                continue

            # Check if this bundle has the right predicate type
            actual_pred_type = self._get_predicate_type_from_bundle(
                image, ref_digest
            )
            if actual_pred_type == pred_type:
                matching_digests.append(ref_digest)

        return matching_digests

    def _fetch_attestation_content(
        self, image: str, ref_digest: str
    ) -> Optional[Dict[str, Any]]:
        """Fetch and decode attestation content."""
        # Get layer digest from manifest
        result = run_command(
            ["oras", "manifest", "fetch", f"{image}@{ref_digest}"],
            timeout=30,
        )

        if not result.success:
            return None

        try:
            manifest = json.loads(result.stdout)
            layer_digest = manifest["layers"][0]["digest"]
        except (json.JSONDecodeError, KeyError, IndexError):
            return None

        # Fetch bundle blob
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
            bundle_file = f.name

        result = run_command(
            ["oras", "blob", "fetch", f"{image}@{layer_digest}",
             "--output", bundle_file],
            timeout=30,
        )

        if not result.success:
            Path(bundle_file).unlink(missing_ok=True)
            return None

        try:
            with open(bundle_file) as f:
                bundle = json.load(f)

            payload_b64 = bundle["dsseEnvelope"]["payload"]
            payload = json.loads(base64.b64decode(payload_b64))
            return payload

        except (json.JSONDecodeError, KeyError):
            return None
        finally:
            Path(bundle_file).unlink(missing_ok=True)

    def extract_sbom(
        self,
        image: str,
        output_file: str,
        sbom_type: str = "cyclonedx",
        predicate_only: bool = True,
    ) -> bool:
        """
        Extract SBOM attestation from an image.

        Args:
            image: Image reference
            output_file: Path to save SBOM
            sbom_type: SBOM format (cyclonedx or spdx)
            predicate_only: Extract only SBOM content (not envelope)

        Returns:
            True if successful
        """
        atype = (
            AttestationTypeEnum.CYCLONEDX
            if sbom_type == "cyclonedx"
            else AttestationTypeEnum.SPDX
        )

        content = self.extract(
            image, atype,
            output_file=output_file,
            predicate_only=predicate_only,
            use_last=True,
        )

        return content is not None

    def extract_triage(
        self, image: str, output_file: str, verify: bool = False
    ) -> bool:
        """
        Extract triage attestation from an image.

        Args:
            image: Image reference
            output_file: Path to save triage file
            verify: Verify attestation before extraction

        Returns:
            True if successful
        """
        content = self.extract(
            image,
            AttestationTypeEnum.TRIAGE,
            output_file=output_file,
            predicate_only=False,
            verify=verify,
            use_last=True,
        )

        return content is not None

