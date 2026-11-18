"""Trivy (``trivy --format json``) -> secledger findings.

Covers the ``Vulnerabilities`` arrays (OS + language dependencies). The
signature uses a ``CVE:package`` fingerprint, so the same CVE in the same
package dedupes across runs even as the surrounding scan changes. Known CVEs in
installed packages are treated as ``confirmed`` (they are facts, not leads).
"""
from __future__ import annotations

from typing import Any

from .common import (
    TRIVY_SEVERITY,
    build_document,
    clip,
    dedupe_keep_order,
    default_run_id,
)


def _finding(target: str, vuln: dict[str, Any]) -> dict[str, Any]:
    vid = str(vuln.get("VulnerabilityID", "VULN"))
    pkg = str(vuln.get("PkgName", "pkg"))
    installed = str(vuln.get("InstalledVersion", ""))
    fixed = str(vuln.get("FixedVersion", ""))
    location = f"{pkg}@{installed}" if installed else pkg
    fingerprint = f"{vid}:{pkg}"

    title = str(vuln.get("Title") or f"{vid} in {pkg}")
    description = clip(str(vuln.get("Description", "")))
    bits = [f"**{vid}** in `{location}`"]
    if fixed:
        bits.append(f"Fixed in: `{fixed}`")
    if vuln.get("PrimaryURL"):
        bits.append(str(vuln["PrimaryURL"]))
    description = "\n\n".join(bits) + ("\n\n" + description if description else "")

    references = [str(vid)]
    references += [str(c) for c in (vuln.get("CweIDs") or [])]
    references += [str(r) for r in (vuln.get("References") or [])]

    return {
        "id": f"{target}:{fingerprint}",
        "title": title,
        "severity": TRIVY_SEVERITY.get(str(vuln.get("Severity", "")).upper(), "info"),
        "category": "dependency",
        "location": location,
        "description": description,
        "status": "confirmed",
        "fingerprint": fingerprint,
        "references": dedupe_keep_order(references),
        "extra": {"target": target, "vulnerability_id": vid, "pkg": pkg},
    }


def convert(raw: dict[str, Any], *, run_id: str | None = None, target: str = "") -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for result in raw.get("Results") or []:
        rtarget = str(result.get("Target", ""))
        for vuln in result.get("Vulnerabilities") or []:
            findings.append(_finding(rtarget, vuln))
    return build_document(
        run_id=run_id or default_run_id(),
        scanner="trivy",
        target=target or str(raw.get("ArtifactName", "")),
        findings=findings,
    )
