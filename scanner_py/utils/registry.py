"""Registry accessibility utilities."""

from typing import Set, Tuple
from .subprocess import run_command
from .logging import get_logger

logger = get_logger(__name__)


class RegistryChecker:
    """Utility class for checking registry accessibility."""

    def __init__(self):
        self._accessible_registries: Set[str] = set()
        self._inaccessible_registries: Set[str] = set()

    @staticmethod
    def extract_registry(image: str) -> str:
        """
        Extract registry from image reference.

        Args:
            image: Full image reference

        Returns:
            Registry hostname
        """
        # Handle images without registry (docker.io)
        parts = image.split("/")
        if len(parts) == 1:
            return "docker.io"

        # Check if first part looks like a registry
        first = parts[0]
        if "." in first or ":" in first or first == "localhost":
            return first

        # Default to docker.io
        return "docker.io"

    def is_registry_accessible(self, image: str) -> bool:
        """
        Check if registry is accessible for a given image.

        Args:
            image: Full image reference to test

        Returns:
            True if registry is accessible
        """
        registry = self.extract_registry(image)

        # Check cache
        if registry in self._accessible_registries:
            logger.debug(f"Registry already known to be accessible: {registry}")
            return True

        if registry in self._inaccessible_registries:
            logger.debug(f"Registry already known to be inaccessible: {registry}")
            return False

        # Test accessibility
        logger.debug(f"Checking registry accessibility: {registry} using image: {image}")

        result = run_command(
            ["docker", "manifest", "inspect", image],
            timeout=30,
        )

        if result.success:
            logger.debug(f"Registry is accessible: {registry}")
            self._accessible_registries.add(registry)
            return True
        else:
            logger.debug(f"Registry is not accessible: {registry}")
            self._inaccessible_registries.add(registry)
            return False

    def should_skip_image(self, image: str) -> Tuple[bool, str]:
        """
        Check if image should be skipped due to inaccessible registry.

        Args:
            image: Image reference

        Returns:
            Tuple of (should_skip, reason)
        """
        if not self.is_registry_accessible(image):
            registry = self.extract_registry(image)
            return True, f"Registry {registry} is not accessible"
        return False, ""

    @property
    def inaccessible_registries(self) -> Set[str]:
        """Get set of inaccessible registries."""
        return self._inaccessible_registries.copy()

    @property
    def accessible_registries(self) -> Set[str]:
        """Get set of accessible registries."""
        return self._accessible_registries.copy()
