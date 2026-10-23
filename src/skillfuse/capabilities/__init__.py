"""Capability taxonomy, inference, and manifest diffing."""

from skillfuse.capabilities.inference import infer_capabilities
from skillfuse.capabilities.manifest import declared_manifest, diff_manifests, manifest_findings
from skillfuse.capabilities.taxonomy import (
    CAPABILITIES,
    WRITE_CAPABILITIES,
    capabilities_for_tool,
    covers,
    is_valid_capability,
)

__all__ = [
    "CAPABILITIES",
    "WRITE_CAPABILITIES",
    "capabilities_for_tool",
    "covers",
    "declared_manifest",
    "diff_manifests",
    "infer_capabilities",
    "is_valid_capability",
    "manifest_findings",
]
