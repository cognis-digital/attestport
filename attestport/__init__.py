"""attestport — air-gap software supply-chain attestation + SBOM gate.

Part of the Cognis Neural Suite. Standard library only; no network required.
"""

from attestport.core import (
    TOOL_NAME,
    TOOL_VERSION,
    SEVERITY_ORDER,
    AttestError,
    Component,
    Finding,
    GateReport,
    canonical_bytes,
    sha256_file,
    sha256_bytes,
    detect_components,
    hash_tree,
    merkle_digest,
    generate_sbom,
    sbom_components,
    build_statement,
    sign_statement,
    attest,
    verify,
    gate,
    load_policy,
    to_sarif,
)

__version__ = TOOL_VERSION

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "__version__",
    "SEVERITY_ORDER",
    "AttestError",
    "Component",
    "Finding",
    "GateReport",
    "canonical_bytes",
    "sha256_file",
    "sha256_bytes",
    "detect_components",
    "hash_tree",
    "merkle_digest",
    "generate_sbom",
    "sbom_components",
    "build_statement",
    "sign_statement",
    "attest",
    "verify",
    "gate",
    "load_policy",
    "to_sarif",
]
