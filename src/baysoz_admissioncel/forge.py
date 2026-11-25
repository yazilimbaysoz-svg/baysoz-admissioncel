"""Bounded adversarial admission-request fixture forge.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import re
from typing import Any

from .model import Fixture, Policy, ResourceRule
from .selector import resources_for_kind

_FIELD_PATH = re.compile(
    r"object\.([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){0,3})"
)
_SAMPLE_VERSIONS = ("v1", "apps/v1", "networking.k8s.io/v1")
_SAMPLE_KINDS = ("Pod", "Deployment", "Service", "ConfigMap")
_ADVERSARIAL_NAME = "adversarial-é-\"-payload"


def _nested(path: str, value: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    cursor = result
    parts = path.split(".")
    for part in parts[:-1]:
        child: dict[str, Any] = {}
        cursor[part] = child
        cursor = child
    cursor[parts[-1]] = value
    return result


def _merge(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in extra.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _base_object(kind: str, name: str, namespace: str | None) -> dict[str, Any]:
    metadata: dict[str, Any] = {"name": name, "labels": {"app": "oracle"}}
    if namespace:
        metadata["namespace"] = namespace
    obj: dict[str, Any] = {"apiVersion": "v1", "kind": kind, "metadata": metadata}
    if kind in {"Pod", "Deployment"}:
        obj["spec"] = {
            "replicas": 1,
            "containers": [
                {
                    "name": "app",
                    "image": "registry.example.invalid/app:1",
                    "securityContext": {"privileged": False},
                }
            ],
        }
    return obj


def _versions_for(rule: ResourceRule) -> list[str]:
    if not rule.api_versions or "*" in rule.api_versions:
        return list(_SAMPLE_VERSIONS[:2])
    return [item for item in rule.api_versions if item != "*"][:2]


def _kinds_for(rule: ResourceRule) -> list[str]:
    if not rule.resources or "*" in rule.resources:
        return list(_SAMPLE_KINDS[:2])
    reverse: dict[str, str] = {}
    for kind in (*_SAMPLE_KINDS, "Ingress", "NetworkPolicy"):
        for resource in resources_for_kind(kind):
            reverse.setdefault(resource, kind)
    kinds: list[str] = []
    for resource in rule.resources:
        base = resource.split("/", 1)[0]
        if base != "*" and base in reverse and reverse[base] not in kinds:
            kinds.append(reverse[base])
        if len(kinds) == 2:
            break
    return kinds or list(_SAMPLE_KINDS[:1])


def _operations_for(rule: ResourceRule) -> list[str]:
    if not rule.operations or "*" in rule.operations:
        return ["CREATE", "UPDATE"]
    return [item for item in rule.operations if item != "*"][:2]


def _field_paths(policy: Policy) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for validation in policy.validations:
        for path in _FIELD_PATH.findall(validation.expression):
            if path.startswith("metadata.") or path in seen:
                continue
            seen.add(path)
            paths.append(path)
            if len(paths) == 3:
                return paths
    return paths


def forge_fixtures(
    policies: tuple[Policy, ...], max_fixtures: int = 64
) -> tuple[Fixture, ...]:
    """Forge deterministic adversarial fixtures for the supplied policies."""
    if max_fixtures < 1:
        return ()
    forged: list[Fixture] = []
    for policy in policies:
        for rule_index, rule in enumerate(policy.rules):
            versions = _versions_for(rule)
            kinds = _kinds_for(rule)
            operations = _operations_for(rule)
            namespace = "forge-ns" if rule.scope in {"Namespaced", "*"} else None
            paths = _field_paths(policy)
            for version in versions:
                for kind in kinds:
                    base = _base_object(kind, "forge-workload", namespace)
                    variants: list[tuple[str, dict[str, Any], str | None]] = [
                        ("minimal", {"metadata": {"name": "forge-minimal"}}, None),
                        ("null-spec", {"spec": None}, None),
                        (
                            "unicode-name",
                            {"metadata": {"name": _ADVERSARIAL_NAME}},
                            None,
                        ),
                    ]
                    for path in paths:
                        variants.append(
                            (
                                f"type-confusion-{path.replace('.', '-')}",
                                _nested(path, "adversarial-scalar"),
                                None,
                            )
                        )
                    variants.append(
                        (
                            "update-oldobject-divergence",
                            {"metadata": {"name": "forge-updated"}},
                            _base_object(kind, "forge-original", namespace),
                        )
                    )
                    for operation in operations:
                        for suffix, extra, old in variants:
                            if len(forged) >= max_fixtures:
                                return tuple(forged)
                            name = (
                                f"{policy.name}-r{rule_index}-{version}-"
                                f"{kind}-{operation}-{suffix}"
                            )
                            obj = _merge(base, extra)
                            forged.append(
                                Fixture(
                                    name=name,
                                    api_version=version,
                                    kind=kind,
                                    object=obj,
                                    operation=operation,
                                    source=f"forge:{policy.name}",
                                    old_object=old if operation == "UPDATE" else None,
                                    namespace=namespace,
                                    namespace_labels={"app": "forge"},
                                    labels={
                                        str(key): str(value)
                                        for key, value in obj["metadata"].get(
                                            "labels", {}
                                        ).items()
                                    },
                                )
                            )
    return tuple(forged)
