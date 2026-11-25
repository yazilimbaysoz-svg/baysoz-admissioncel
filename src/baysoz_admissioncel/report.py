"""Deterministic SARIF/JSON/text renderers.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from . import __version__, __author__
from .analyzer import rule_title
from .model import CheckResult, Finding

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _result_payload(result: CheckResult) -> dict[str, Any]:
    return {
        "attribution": __author__,
        "tool": "baysoz-admissioncel",
        "version": __version__,
        "summary": {
            "policies": result.policies,
            "bindings": result.bindings,
            "fixtures": result.fixtures,
            "evaluations": result.evaluations,
            "allowed": result.allowed,
            "denied": result.denied,
            "errors": result.errors,
            "matched": result.matched,
            "findings": len(result.findings),
            "error_findings": result.error_count,
            "warning_findings": result.warning_count,
        },
        "findings": [asdict(finding) for finding in result.findings],
    }


def render_json(result: CheckResult) -> str:
    """Render a stable JSON document for machine consumers."""
    return json.dumps(
        _result_payload(result), indent=2, sort_keys=True, ensure_ascii=False
    ) + "\n"


def _sarif_result(finding: Finding) -> dict[str, Any]:
    level = {"ERROR": "error", "WARNING": "warning", "NOTE": "note"}.get(
        finding.level, "warning"
    )
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": finding.source or "unknown"},
            "region": {"startLine": max(1, finding.line)},
        }
    }
    return {
        "ruleId": finding.rule_id,
        "level": level,
        "message": {"text": finding.message},
        "locations": [location],
        "properties": {
            "policy": finding.policy,
            "binding": finding.binding,
            "fixture": finding.fixture,
            "evidence": finding.evidence,
            "attribution": __author__,
        },
    }


def render_sarif(result: CheckResult) -> str:
    """Render a deterministic SARIF 2.1.0 log."""
    rule_ids = sorted({item.rule_id for item in result.findings})
    payload: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "baysoz-admissioncel",
                        "version": __version__,
                        "informationUri": (
                            "https://github.com/yazilimbaysoz-svg/"
                            "baysoz-admissioncel"
                        ),
                        "fullDescription": {
                            "text": (
                                "Offline ValidatingAdmissionPolicy CEL conformance "
                                f"oracle by {__author__}"
                            )
                        },
                        "rules": [
                            {
                                "id": rule_id,
                                "name": rule_id,
                                "shortDescription": {
                                    "text": rule_title(rule_id)
                                },
                            }
                            for rule_id in rule_ids
                        ],
                    }
                },
                "results": [_sarif_result(item) for item in result.findings],
                "properties": _result_payload(result)["summary"],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": "baysoz-admissioncel check",
                    }
                ],
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_text(result: CheckResult) -> str:
    """Render a concise human-readable report."""
    lines = [
        f"baysoz-admissioncel {__version__} | {__author__}",
        (
            f"policies={result.policies} bindings={result.bindings} "
            f"fixtures={result.fixtures} evaluations={result.evaluations} "
            f"matched={result.matched}"
        ),
        (
            f"outcomes: allow={result.allowed} deny={result.denied} "
            f"error={result.errors}"
        ),
        (
            f"findings: error={result.error_count} "
            f"warning={result.warning_count}"
        ),
    ]
    if not result.findings:
        lines.append("PASS: zero policy defects detected.")
        return "\n".join(lines) + "\n"
    for finding in result.findings:
        lines.append(
            f"[{finding.level}] {finding.rule_id} {finding.message} "
            f"({finding.source}:{finding.line})"
        )
        if finding.policy:
            lines.append(f"    policy={finding.policy} binding={finding.binding}")
        if finding.fixture:
            lines.append(f"    fixture={finding.fixture}")
        if finding.evidence:
            lines.append(f"    evidence={finding.evidence}")
    return "\n".join(lines) + "\n"
