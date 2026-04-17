"""Attestation extraction module.

Equivalent to cosign-extract.sh and oras-scan/2-oras-scan.sh

Supports both:
- Cosign attestations (JSON format with sigstore bundles)
- Legacy TOML triage files (triage.toml via ORAS referrers)
"""

import json
import base64
import re
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Set
from pathlib import Path
from enum import Enum

from ..utils.subprocess import run_command, run_with_timeout
from ..utils.logging import get_logger, is_verbose
from .cache import get_digest_cache

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

    # Predicate type emitted by ``cosign sign`` (the image-signature DSSE
    # statement), used to detect that an image is signed without invoking
    # ``cosign verify`` against the registry. This is the same payload that
    # cosign verify-attestation downloads as the signature half of a
    # sigstore bundle, so its mere presence in the image's OCI 1.1 referrers
    # list is sufficient evidence of a cosign signature.
    COSIGN_SIGNATURE_PREDICATE = "https://sigstore.dev/cosign/sign/v1"

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

    def has_signature(self) -> bool:
        """Check if a cosign signature DSSE statement is present.

        The image-signature side of a cosign-signed image is a DSSE
        envelope with predicateType ``https://sigstore.dev/cosign/sign/v1``,
        stored as a sigstore bundle in the OCI 1.1 referrers list. We use
        its presence as proof the image is signed -- avoiding a separate
        ``cosign verify`` round trip which on Harbor enumerates the
        Referrers API a second time (linear in referrer count and the
        primary cause of long-tail timeouts on heavily-attested images).
        """
        return self.COSIGN_SIGNATURE_PREDICATE in self.attestations


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
        Resolve image tag to digest (cached).

        Args:
            image: Image reference

        Returns:
            Digest or None
        """
        return get_digest_cache().get_or_fetch(image, timeout=30)

    def list_attestations(
        self, image: str, show_null: bool = False
    ) -> AttestationList:
        """
        List available attestations for an image.

        Uses parallel predicate type extraction for better performance.

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

        logger.debug(f"Listing attestations for: {image} ({digest})")

        # Use the tristate variant so a discovery failure (timeout, network
        # blip, registry without referrers support) is distinguishable from
        # a definitive "no referrers". The legacy ``_discover_referrers``
        # alias collapses both into ``[]`` and would silently misclassify a
        # signed image as ``UNSIGNED`` if the registry was momentarily slow.
        referrers = self.discover_referrers(image, digest)
        if referrers is None:
            if is_verbose():
                logger.error(
                    f"Referrers discovery failed for {image} — cannot enumerate"
                    " attestations"
                )
            return AttestationList()
        if not referrers:
            return AttestationList()

        bundle_type = "application/vnd.dev.sigstore.bundle.v0.3+json"
        bundle_refs = [
            r for r in referrers
            if r.get("artifactType") == bundle_type
        ]

        if not bundle_refs:
            return AttestationList()

        predicate_types: Dict[str, int] = {}
        image_name = self._strip_tag(image)

        def fetch_predicate_type(ref: dict) -> Optional[str]:
            ref_digest = ref.get("digest")
            if not ref_digest:
                return None
            return self._get_predicate_type_from_bundle(image_name, ref_digest)

        max_workers = min(len(bundle_refs), 5)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(fetch_predicate_type, ref): ref
                for ref in bundle_refs
            }

            for future in as_completed(futures):
                try:
                    pred_type = future.result()
                    if pred_type:
                        predicate_types[pred_type] = predicate_types.get(pred_type, 0) + 1
                except Exception:
                    pass

        return AttestationList(attestations=predicate_types)

    def _get_predicate_type_from_bundle(
        self, image_name: str, ref_digest: str
    ) -> Optional[str]:
        """
        Extract predicate type from a bundle referrer.

        Args:
            image_name: Image name without tag (registry/repo only)
            ref_digest: Referrer digest

        Returns:
            Predicate type or None
        """
        result = run_command(
            ["oras", "manifest", "fetch", f"{image_name}@{ref_digest}"],
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

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
            bundle_file = f.name

        result = run_command(
            ["oras", "blob", "fetch", f"{image_name}@{layer_digest}",
             "--output", bundle_file],
            timeout=30,
        )

        if not result.success:
            Path(bundle_file).unlink(missing_ok=True)
            return None

        try:
            with open(bundle_file) as f:
                bundle = json.load(f)

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

    def discover_referrers(
        self, image: str, image_digest: Optional[str] = None
    ) -> Optional[List[dict]]:
        """
        Discover OCI referrers for an image.

        Tries image@digest first for precision, falls back to image with tag
        if the registry doesn't support digest-based referrer discovery (e.g. JFrog).

        Returns:
            * ``None`` if the discovery itself failed (timeout, network
              error, JSON parse error, registry without Referrers API
              support). Callers can use this to fall back to slower
              alternatives such as ``cosign verify`` or
              ``extract_triage_tag_based()``.
            * ``[]`` if discovery succeeded and the image legitimately has
              no referrers attached. Callers can rely on this as a
              definitive "no attestations / no signatures" signal.
            * a non-empty list of referrer manifests otherwise.
        """
        # The oras discover request hits the registry's OCI 1.1 Referrers
        # API. On Harbor this is O(N) in referrer count -- empirically
        # ~8 s for 36 refs, ~95 s for 403 refs. The previous 15 s cap
        # turned every heavily-attested image into a false ``None``
        # (timeout) result, which downstream callers interpret as either
        # "fall back to cosign verify" (also slow) or "discovery failed,
        # treat as empty" (a silent miss). 120 s comfortably covers our
        # heaviest known images (pharia-os-app at ~95 s) while still
        # bounding worker latency. Capped at ``self.timeout`` so callers
        # that supply a tighter budget (e.g. unit tests) keep control.
        fast_timeout = min(self.timeout, 120)

        if image_digest:
            image_with_digest = f"{image}@{image_digest}"
            result = run_command(
                ["oras", "discover", image_with_digest, "--format", "json"],
                timeout=fast_timeout,
            )
            if result.success:
                try:
                    data = json.loads(result.stdout)
                    refs = data.get("referrers", data.get("manifests", []))
                    return refs if refs is not None else []
                except json.JSONDecodeError:
                    logger.debug(
                        f"oras discover for {image} returned non-JSON output"
                    )
                    return None

            if result.timed_out:
                logger.debug(
                    f"Referrers API timed out for {image} — registry may not support it"
                )
                return None

            logger.debug(
                f"Digest-based oras discover failed, falling back to tag: {result.stderr}"
            )

        result = run_command(
            ["oras", "discover", image, "--format", "json"],
            timeout=fast_timeout,
        )
        if not result.success:
            if result.timed_out:
                logger.debug(
                    f"Referrers API timed out for {image} — registry may not support it"
                )
            return None

        try:
            data = json.loads(result.stdout)
            refs = data.get("referrers", data.get("manifests", []))
            return refs if refs is not None else []
        except json.JSONDecodeError:
            logger.debug(
                f"oras discover for {image} returned non-JSON output"
            )
            return None

    # Backwards-compatible alias kept as the previously private API. Existing
    # call-sites that treat ``[]`` and ``None`` interchangeably can keep
    # using this; new call-sites that need to distinguish between
    # "discovery failed" and "no referrers" should call
    # :meth:`discover_referrers` directly.
    def _discover_referrers(
        self, image: str, image_digest: Optional[str] = None
    ) -> List[dict]:
        refs = self.discover_referrers(image, image_digest)
        return refs if refs is not None else []

    @staticmethod
    def _strip_tag(image: str) -> str:
        """Return image reference without tag (keep registry/repo only)."""
        if "@" in image:
            return image.split("@")[0]
        if ":" in image.rsplit("/", 1)[-1]:
            return image.rsplit(":", 1)[0]
        return image

    def _find_attestation_digests(
        self, image: str, pred_type: str, image_digest: str
    ) -> List[str]:
        """Find all attestation digests matching a predicate type."""
        referrers = self._discover_referrers(image, image_digest)

        bundle_type = "application/vnd.dev.sigstore.bundle.v0.3+json"
        matching_digests = []
        image_name = self._strip_tag(image)

        for ref in referrers:
            if ref.get("artifactType") != bundle_type:
                continue

            ref_digest = ref.get("digest")
            if not ref_digest:
                continue

            actual_pred_type = self._get_predicate_type_from_bundle(
                image_name, ref_digest
            )
            if actual_pred_type == pred_type:
                matching_digests.append(ref_digest)

        return matching_digests

    def _fetch_attestation_content(
        self, image: str, ref_digest: str
    ) -> Optional[Dict[str, Any]]:
        """Fetch and decode attestation content."""
        image_name = self._strip_tag(image)

        result = run_command(
            ["oras", "manifest", "fetch", f"{image_name}@{ref_digest}"],
            timeout=30,
        )

        if not result.success:
            return None

        try:
            manifest = json.loads(result.stdout)
            layer_digest = manifest["layers"][0]["digest"]
        except (json.JSONDecodeError, KeyError, IndexError):
            return None

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
            bundle_file = f.name

        result = run_command(
            ["oras", "blob", "fetch", f"{image_name}@{layer_digest}",
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
        Extract triage attestation from an image via OCI Referrers API.

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

    def extract_triage_tag_based(
        self, image: str, output_file: str
    ) -> bool:
        """
        Extract triage attestation via tag-based cosign storage (sha256-<digest>.att).

        Fallback for registries that don't support the OCI Referrers API
        (e.g. JFrog remote/virtual repos). Tag-based attestations are stored as
        regular OCI tags that any registry can proxy.

        Args:
            image: Image reference
            output_file: Path to save triage file

        Returns:
            True if successful
        """
        triage_pred_type = PREDICATE_TYPE_MAP[AttestationTypeEnum.TRIAGE]

        result = run_command(
            ["cosign", "download", "attestation", image],
            timeout=self.timeout,
        )
        if not result.success:
            logger.debug(f"No tag-based attestations for {image}")
            return False

        for line in result.stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                envelope = json.loads(line)
                payload = json.loads(base64.b64decode(envelope.get("payload", "")))
                if payload.get("predicateType") == triage_pred_type:
                    with open(output_file, "w") as f:
                        json.dump(payload, f, indent=2)
                    logger.debug(f"Tag-based triage attestation written to {output_file}")
                    return True
            except (json.JSONDecodeError, KeyError, ValueError):
                continue

        logger.debug(f"No triage predicate in tag-based attestations for {image}")
        return False


class LegacyTriageExtractor:
    """
    Extract legacy TOML triage files from container images using ORAS.

    This is equivalent to the oras-scan bash scripts that look for
    triage.toml files attached as ORAS referrers with "triage.toml"
    in the annotation content.

    The TOML format contains sections like:
        [trivy.CVE-2024-1234]
        reason = "Not applicable"
    """

    def __init__(self, timeout: int = 60):
        """
        Initialize the extractor.

        Args:
            timeout: Timeout for operations
        """
        self.timeout = timeout

    def _get_image_name(self, full_image: str) -> str:
        """Get image name without version/digest."""
        if "@" in full_image:
            return full_image.split("@")[0]
        return full_image.split(":")[0]

    def find_triage_reference(self, image: str) -> Optional[str]:
        """
        Find ORAS referrer containing triage.toml.

        Equivalent to the bash script logic that searches for
        "triage.toml" in annotation content.

        Args:
            image: Image reference

        Returns:
            Reference digest or None
        """
        # Discover referrers
        result = run_command(
            ["oras", "discover", image, "--format", "json"],
            timeout=self.timeout,
        )

        if not result.success:
            # Try with --plain-http as fallback
            result = run_command(
                ["oras", "discover", image, "--format", "json", "--plain-http"],
                timeout=self.timeout,
            )
            if not result.success:
                logger.debug(f"Failed to discover referrers for {image}")
                return None

        try:
            data = json.loads(result.stdout)
            referrers = data.get("referrers", [])
        except json.JSONDecodeError:
            logger.debug("Failed to parse oras discover output")
            return None

        # Find referrer with triage.toml in annotation content
        for ref in referrers:
            annotations = ref.get("annotations", {})
            content = annotations.get("content", "")

            if "triage.toml" in content:
                return ref.get("reference")

        return None

    def extract_triage_toml(
        self, image: str, output_file: str
    ) -> Optional[str]:
        """
        Extract triage.toml file from an image.

        Equivalent to oras-scan/2-oras-scan.sh triage extraction.

        Args:
            image: Image reference
            output_file: Path to save triage.toml

        Returns:
            Path to extracted file or None
        """
        triage_ref = self.find_triage_reference(image)
        if not triage_ref:
            logger.debug(f"No triage.toml found for {image}")
            return None

        # Fetch manifest to get layer digest
        result = run_command(
            ["oras", "manifest", "fetch", triage_ref],
            timeout=30,
        )

        if not result.success:
            logger.debug(f"Failed to fetch manifest for {triage_ref}")
            return None

        try:
            manifest = json.loads(result.stdout)
            layer_digest = manifest["layers"][0]["digest"]
        except (json.JSONDecodeError, KeyError, IndexError):
            logger.debug("Failed to parse manifest")
            return None

        # Fetch the blob (triage.toml content)
        image_name = self._get_image_name(image)
        result = run_command(
            ["oras", "blob", "fetch", f"{image_name}@{layer_digest}",
             "--output", output_file],
            timeout=30,
        )

        if not result.success:
            logger.debug(f"Failed to fetch triage blob")
            return None

        # Verify file is not empty
        if not Path(output_file).exists() or Path(output_file).stat().st_size == 0:
            Path(output_file).unlink(missing_ok=True)
            return None

        logger.debug(f"Successfully extracted triage.toml to {output_file}")
        return output_file

    def parse_triage_toml(self, triage_file: str) -> Set[str]:
        """
        Parse CVE IDs from a triage.toml file.

        Equivalent to the bash grep patterns:
        grep -o '\\(only: \\)?\\[trivy\\.[A-Z0-9\\-]*\\]' | sed 's/trivy\\.//'

        Args:
            triage_file: Path to triage.toml file

        Returns:
            Set of CVE IDs (e.g., {"CVE-2024-1234", "CVE-2023-5678"})
        """
        cves: Set[str] = set()

        try:
            with open(triage_file, "r") as f:
                content = f.read()
        except FileNotFoundError:
            return cves

        # Pattern to match [trivy.CVE-XXXX-XXXX] sections
        # This matches: [trivy.CVE-2024-1234] or only: [trivy.CVE-2024-1234]
        pattern = r'\[trivy\.(CVE-[A-Z0-9\-]+)\]'

        for match in re.finditer(pattern, content):
            cves.add(match.group(1))

        return cves

    def has_triage(self, image: str) -> bool:
        """
        Check if image has a legacy triage.toml file.

        Args:
            image: Image reference

        Returns:
            True if triage.toml exists
        """
        return self.find_triage_reference(image) is not None


class TriageExtractor:
    """
    Unified triage extractor supporting both formats:
    - Cosign attestation (JSON format)
    - Legacy TOML format (triage.toml via ORAS)

    This combines functionality from both cosign-based attestation
    extraction and the legacy oras-scan bash scripts.
    """

    def __init__(
        self,
        certificate_oidc_issuer: str = AttestationExtractor.DEFAULT_OIDC_ISSUER,
        certificate_identity_regexp: str = AttestationExtractor.DEFAULT_IDENTITY_REGEXP,
        timeout: int = 60,
    ):
        """
        Initialize the unified triage extractor.

        Args:
            certificate_oidc_issuer: OIDC issuer for cosign verification
            certificate_identity_regexp: Identity regexp for cosign verification
            timeout: Timeout for operations
        """
        self.cosign_extractor = AttestationExtractor(
            certificate_oidc_issuer=certificate_oidc_issuer,
            certificate_identity_regexp=certificate_identity_regexp,
            timeout=timeout,
        )
        self.legacy_extractor = LegacyTriageExtractor(timeout=timeout)
        self.timeout = timeout

    def extract_triage(
        self, image: str, output_dir: str
    ) -> Optional[Dict[str, Any]]:
        """
        Extract triage data from an image, trying both formats.

        Tries cosign attestation first, then falls back to legacy TOML.

        Args:
            image: Image reference
            output_dir: Directory to save extracted files

        Returns:
            Dictionary with triage info:
            {
                "format": "cosign" | "toml",
                "file": path to extracted file,
                "cve_ids": set of CVE IDs,
            }
            or None if no triage found
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Try cosign attestation first (JSON format)
        cosign_file = output_path / "triage.json"
        if self.cosign_extractor.extract_triage(image, str(cosign_file)):
            try:
                with open(cosign_file) as f:
                    triage_data = json.load(f)

                # Extract CVE IDs from cosign triage format
                # Format: {"predicate": {"trivy": {"CVE-ID": {...}, ...}}}
                trivy_data = triage_data.get("predicate", {}).get("trivy", {})
                cve_ids = set(trivy_data.keys())

                return {
                    "format": "cosign",
                    "file": str(cosign_file),
                    "cve_ids": cve_ids,
                }
            except (json.JSONDecodeError, KeyError):
                logger.debug("Failed to parse cosign triage")

        # Fall back to legacy TOML format
        toml_file = output_path / "triage.toml"
        if self.legacy_extractor.extract_triage_toml(image, str(toml_file)):
            cve_ids = self.legacy_extractor.parse_triage_toml(str(toml_file))

            return {
                "format": "toml",
                "file": str(toml_file),
                "cve_ids": cve_ids,
            }

        return None

    def has_triage(self, image: str) -> bool:
        """
        Check if image has any triage (cosign or legacy).

        Args:
            image: Image reference

        Returns:
            True if triage exists in any format
        """
        # Check cosign attestation
        attestations = self.cosign_extractor.list_attestations(image)
        if attestations.has_triage():
            return True

        # Check legacy TOML
        return self.legacy_extractor.has_triage(image)
