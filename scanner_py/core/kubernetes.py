"""Kubernetes image extraction module.

Extracts container images from Kubernetes resources in a namespace.
"""

import json
from dataclasses import dataclass, field
from typing import List, Set, Optional, Callable

from ..utils.subprocess import run_command, run_with_timeout
from ..utils.logging import get_logger, is_verbose

logger = get_logger(__name__)


@dataclass
class KubernetesConfig:
    """Kubernetes connection configuration."""
    namespace: str = "pharia-ai"
    kubeconfig: Optional[str] = None
    context: Optional[str] = None

    def get_kubectl_args(self) -> List[str]:
        """Get kubectl command arguments."""
        args = []
        if self.kubeconfig:
            args.append(f"--kubeconfig={self.kubeconfig}")
        if self.context:
            args.append(f"--context={self.context}")
        return args


@dataclass
class ImageExtractionResult:
    """Result of image extraction from Kubernetes."""
    images: List[str] = field(default_factory=list)
    total_found: int = 0
    ignored_count: int = 0
    inaccessible_count: int = 0
    inaccessible_registries: Set[str] = field(default_factory=set)


class KubernetesImageExtractor:
    """
    Extract container images from Kubernetes namespace.
    
    Discovers images from pods, deployments, daemonsets, statefulsets,
    jobs, and cronjobs.
    """

    def __init__(
        self,
        config: Optional[KubernetesConfig] = None,
        timeout: int = 30,
    ):
        """
        Initialize extractor.

        Args:
            config: Kubernetes configuration
            timeout: Timeout for kubectl operations
        """
        self.config = config or KubernetesConfig()
        self.timeout = timeout
        self._kubectl_args = self.config.get_kubectl_args()

    def test_connectivity(self) -> bool:
        """
        Test Kubernetes cluster connectivity.

        Returns:
            True if cluster is accessible
        """
        logger.debug(f"Testing Kubernetes connectivity (timeout: {self.timeout}s)")

        args = ["kubectl"] + self._kubectl_args + [
            "get", "namespace", self.config.namespace
        ]

        result = run_with_timeout(args, self.timeout)

        if result.success:
            logger.debug(f"Connected to cluster, namespace: {self.config.namespace}")
            return True
        elif result.timed_out:
            if is_verbose():
                logger.error("Kubernetes connectivity test timed out")
                logger.error("This usually indicates network issues or unreachable cluster")
        else:
            if is_verbose():
                logger.error(f"Cannot access namespace '{self.config.namespace}'")
                logger.error(f"kubectl output: {result.stderr}")

        return False

    def _run_kubectl_jsonpath(
        self, resource: str, jsonpath: str
    ) -> List[str]:
        """
        Run kubectl with jsonpath and return images.

        Args:
            resource: Kubernetes resource type
            jsonpath: JSONPath expression

        Returns:
            List of image references
        """
        args = ["kubectl"] + self._kubectl_args + [
            "get", resource,
            "-n", self.config.namespace,
            "-o", f"jsonpath={jsonpath}",
        ]

        result = run_command(args, timeout=self.timeout)

        if not result.success:
            logger.debug(f"Failed to get {resource}: {result.stderr}")
            return []

        # Split output by newlines and filter empty strings
        images = [img.strip() for img in result.stdout.split("\n") if img.strip()]
        return images

    def extract_images(
        self,
        ignore_patterns: Optional[List[str]] = None,
        registry_checker: Optional[Callable[[str], bool]] = None,
    ) -> ImageExtractionResult:
        """
        Extract all container images from the namespace.

        Args:
            ignore_patterns: List of image patterns to ignore
            registry_checker: Function to check registry accessibility

        Returns:
            ImageExtractionResult with discovered images
        """
        logger.debug(f"Discovering images in namespace: {self.config.namespace}")

        ignore_patterns = ignore_patterns or []
        all_images: Set[str] = set()

        # JSONPath templates for different resources
        container_path = (
            "{range .items[*]}"
            "{range .spec.containers[*]}{.image}{\"\\n\"}{end}"
            "{range .spec.initContainers[*]}{.image}{\"\\n\"}{end}"
            "{end}"
        )

        template_container_path = (
            "{range .items[*]}"
            "{range .spec.template.spec.containers[*]}{.image}{\"\\n\"}{end}"
            "{range .spec.template.spec.initContainers[*]}{.image}{\"\\n\"}{end}"
            "{end}"
        )

        cronjob_container_path = (
            "{range .items[*]}"
            "{range .spec.jobTemplate.spec.template.spec.containers[*]}{.image}{\"\\n\"}{end}"
            "{range .spec.jobTemplate.spec.template.spec.initContainers[*]}{.image}{\"\\n\"}{end}"
            "{end}"
        )

        # Extract from different resource types
        resources = [
            ("pods", container_path),
            ("deployments", template_container_path),
            ("daemonsets", template_container_path),
            ("statefulsets", template_container_path),
            ("jobs", template_container_path),
            ("cronjobs", cronjob_container_path),
        ]

        for resource, jsonpath in resources:
            images = self._run_kubectl_jsonpath(resource, jsonpath)
            all_images.update(images)
            logger.debug(f"Found {len(images)} images from {resource}")

        result = ImageExtractionResult(total_found=len(all_images))

        # Filter images
        filtered_images = []
        inaccessible_registries: Set[str] = set()

        for image in sorted(all_images):
            # Check ignore patterns
            if self._should_ignore(image, ignore_patterns):
                logger.debug(f"Ignoring image: {image}")
                result.ignored_count += 1
                continue

            # Check registry accessibility
            if registry_checker and not registry_checker(image):
                registry = self._extract_registry(image)
                logger.debug(f"Skipping inaccessible registry: {registry}")
                result.inaccessible_count += 1
                inaccessible_registries.add(registry)
                continue

            filtered_images.append(image)

        result.images = filtered_images
        result.inaccessible_registries = inaccessible_registries

        # Log summary (only in verbose mode to avoid interfering with progress bars)
        logger.debug(f"Found {len(filtered_images)} unique images to scan")

        if result.ignored_count > 0:
            logger.debug(f"Skipped {result.ignored_count} ignored images")

        if result.inaccessible_count > 0 and is_verbose():
            logger.warning(
                f"🚫 Inaccessible registries: {', '.join(inaccessible_registries)}"
            )
            logger.warning(
                f"   Skipped {result.inaccessible_count} images from these registries"
            )
            logger.warning("   To access, run: docker login <registry>")

        return result

    def _should_ignore(self, image: str, patterns: List[str]) -> bool:
        """Check if image matches any ignore pattern."""
        for pattern in patterns:
            if pattern in image:
                return True
        return False

    @staticmethod
    def _extract_registry(image: str) -> str:
        """Extract registry from image reference."""
        parts = image.split("/")
        if len(parts) == 1:
            return "docker.io"
        
        first = parts[0]
        if "." in first or ":" in first or first == "localhost":
            return first
        
        return "docker.io"

    def load_ignore_patterns(self, filepath: str) -> List[str]:
        """
        Load ignore patterns from a file.

        Args:
            filepath: Path to ignore file

        Returns:
            List of ignore patterns
        """
        patterns = []
        try:
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if line and not line.startswith("#"):
                        patterns.append(line)
            logger.debug(f"Loaded {len(patterns)} ignore patterns from {filepath}")
        except FileNotFoundError:
            if is_verbose():
                logger.warning(f"Ignore file not found: {filepath}")
        return patterns

