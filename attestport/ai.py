"""Opt-in AI risk summary for ATTESTPORT.

This is OFF BY DEFAULT and air-gap safe: with no ``COGNIS_AI_*`` configuration,
``summarize_sbom_risk`` returns ``None`` and the tool stays 100% deterministic.

It reuses the canonical Cognis shared AI backend (``tools/_shared/
cognis_ai_backend.py``) when present, talking only to a LOCAL OpenAI-compatible
fleet endpoint (nothing leaves the box). Any import error, disablement, or
runtime failure degrades silently to ``None`` so the core never depends on it.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, Optional


def _load_backend():
    """Best-effort import of the shared backend from the suite _shared dir."""
    try:
        # Walk up to the suite root and add tools/_shared to the path.
        here = os.path.dirname(os.path.abspath(__file__))
        cur = here
        for _ in range(8):
            shared = os.path.join(cur, "tools", "_shared")
            if os.path.isdir(shared):
                if shared not in sys.path:
                    sys.path.insert(0, shared)
                break
            cur = os.path.dirname(cur)
        import cognis_ai_backend  # type: ignore
        return cognis_ai_backend
    except Exception:
        return None


def is_enabled() -> bool:
    backend = _load_backend()
    if backend is None:
        return False
    try:
        return bool(backend.is_enabled())
    except Exception:
        return False


def summarize_sbom_risk(sbom: Dict[str, Any]) -> Optional[str]:
    """Return a short natural-language risk summary, or None if AI is off."""
    backend = _load_backend()
    if backend is None or not is_enabled():
        return None
    comps = sbom.get("components", [])
    listing = [
        {"name": c.get("name"), "version": c.get("version")}
        for c in comps[:200]
    ]
    prompt = (
        "You are a software supply-chain security analyst. Given this SBOM "
        "component list, write a concise (max 8 bullet points) risk summary: "
        "flag obviously risky/abandoned packages, license concerns, and "
        "unpinned-looking versions. Do not invent CVEs you cannot justify.\n\n"
        + json.dumps(listing, indent=2)
    )
    try:
        # The shared backend's analyze_code accepts arbitrary text context;
        # we pass the prompt as the code body and ask for a free-form review.
        findings = backend.analyze_code(prompt, focus="supply-chain risk")
        if isinstance(findings, list) and findings:
            lines = []
            for f in findings[:8]:
                if isinstance(f, dict):
                    lines.append("- " + str(f.get("message") or f.get("title") or f))
                else:
                    lines.append("- " + str(f))
            return "\n".join(lines)
    except Exception:
        return None
    return None
