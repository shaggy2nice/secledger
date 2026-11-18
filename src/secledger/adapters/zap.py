"""OWASP ZAP (JSON report) -> secledger findings.

One finding per alert (grouped across its instances), located at the first
instance's ``METHOD uri``. No ``fingerprint`` is emitted on purpose: the
default ``category :: location`` signature then dedupes per alert-type per
endpoint across runs. Switch to one-finding-per-instance if you want each URL
tracked separately — it's a two-line change in ``_alert_findings``.
"""
from __future__ import annotations

import html
import re
from typing import Any

from .common import ZAP_RISK, build_document, clip, dedupe_keep_order, default_run_id, slug

_TAG = re.compile(r"<[^>]+>")


def _text(raw_html: str) -> str:
    """Strip the light HTML ZAP wraps around desc/solution/reference."""
    s = _TAG.sub(" ", raw_html or "")
    s = html.unescape(s)
    return re.sub(r"\s+", " ", s).strip()


def _risk(riskcode: Any) -> str:
    try:
        return ZAP_RISK.get(int(riskcode), "info")
    except (TypeError, ValueError):
        return "info"


def _alert_findings(site_name: str, alert: dict[str, Any]) -> list[dict[str, Any]]:
    name = str(alert.get("alert") or alert.get("name") or "ZAP alert")
    instances = alert.get("instances") or [{}]
    first = instances[0] if instances else {}
    method = str(first.get("method", "")).strip()
    uri = str(first.get("uri", site_name)).strip()
    location = f"{method} {uri}".strip()

    desc = _text(str(alert.get("desc", "")))
    solution = _text(str(alert.get("solution", "")))
    body = clip(desc)
    if len(instances) > 1:
        extra_uris = dedupe_keep_order([i.get("uri", "") for i in instances[1:]], limit=8)
        if extra_uris:
            body += "\n\nAlso seen at:\n" + "\n".join(f"- `{u}`" for u in extra_uris)
    if solution:
        body += f"\n\n**Solution:** {clip(solution, 1000)}"

    references: list[str] = []
    if alert.get("cweid") and str(alert["cweid"]) not in ("", "-1"):
        references.append(f"CWE-{alert['cweid']}")
    ref_text = _text(str(alert.get("reference", "")))
    references += re.findall(r"https?://\S+", ref_text)

    return [
        {
            "id": f"{site_name}:{alert.get('pluginid', '')}:{alert.get('alertRef', name)}",
            "title": name,
            "severity": _risk(alert.get("riskcode")),
            "category": slug(name),
            "location": location,
            "description": body,
            "references": dedupe_keep_order(references),
            "extra": {
                "pluginid": str(alert.get("pluginid", "")),
                "confidence": str(alert.get("confidence", "")),
                "site": site_name,
            },
        }
    ]


def convert(raw: dict[str, Any], *, run_id: str | None = None, target: str = "") -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    sites = raw.get("site") or []
    for site in sites:
        site_name = str(site.get("@name", ""))
        for alert in site.get("alerts") or []:
            findings.extend(_alert_findings(site_name, alert))
    return build_document(
        run_id=run_id or default_run_id(),
        scanner="zap",
        target=target or (str(sites[0].get("@name", "")) if sites else ""),
        findings=findings,
    )
