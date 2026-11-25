"""Kubernetes resource-rule and label-selector semantics.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .model import Binding, Fixture, Policy, ResourceRule, split_api_version

_OPERATOR_SCOPE = {"Cluster": "Cluster", "Namespaced": "Namespaced", "*": "*"}
_IRREGULAR_RESOURCES = {
    "policy": "policies",
    "ingress": "ingresses",
    "networkpolicy": "networkpolicies",
    "endpoints": "endpoints",
    "namespace": "namespaces",
}


def resources_for_kind(kind: str) -> tuple[str, ...]:
    """Map a Kubernetes kind to the resource names used in resourceRules."""
    lower = kind.lower()
    irregular = _IRREGULAR_RESOURCES.get(lower)
    if irregular:
        return (irregular,)
    if lower.endswith("s"):
        return (lower,)
    return (f"{lower}s",)


def label_selector_matches(
    selector: Mapping[str, Any] | None, labels: Mapping[str, str]
) -> bool:
    """Evaluate matchLabels and matchExpressions with Kubernetes semantics."""
    if not selector:
        return True
    for key, value in (selector.get("matchLabels") or {}).items():
        if labels.get(str(key)) != str(value):
            return False
    for raw in selector.get("matchExpressions") or ():
        if not isinstance(raw, Mapping):
            return False
        key = str(raw.get("key", ""))
        operator = str(raw.get("operator", ""))
        values = [str(item) for item in raw.get("values") or ()]
        present = key in labels
        if operator == "In":
            if not present or labels[key] not in values:
                return False
        elif operator == "NotIn":
            if not values or (present and labels[key] in values):
                return False
        elif operator == "Exists":
            if not present:
                return False
        elif operator == "DoesNotExist":
            if present:
                return False
        else:
            return False
    return True


def _in_collection(value: str, collection: tuple[str, ...]) -> bool:
    return not collection or "*" in collection or value in collection


def resource_matches(resources: tuple[str, ...], kind: str) -> bool:
    candidates = resources_for_kind(kind)
    for resource in resources:
        base = resource.split("/", 1)[0]
        if base == "*" or base in candidates:
            return True
    return False


def matches_resource_rule(
    rule: ResourceRule, fixture: Fixture, match_policy: str
) -> tuple[bool, bool]:
    """Return applicability and whether matchPolicy Equivalent was approximated."""
    if not resource_matches(rule.resources, fixture.kind):
        return False, False
    if not _in_collection(fixture.operation, rule.operations):
        return False, False
    if rule.resource_names and "*" not in rule.resource_names:
        name = str(fixture.object.get("metadata", {}).get("name", ""))
        if name not in rule.resource_names:
            return False, False
    scope = "Namespaced" if fixture.namespace else "Cluster"
    expected_scope = _OPERATOR_SCOPE.get(rule.scope, "*")
    if expected_scope != "*" and expected_scope != scope:
        return False, False

    group, version = split_api_version(fixture.api_version)
    group_ok = _in_collection(group, rule.api_groups)
    version_ok = _in_collection(version, rule.api_versions)
    if group_ok and version_ok:
        return True, False
    if match_policy != "Equivalent":
        return False, False
    if group_ok and (not rule.api_versions or "*" in rule.api_versions):
        return True, True
    if group_ok:
        return True, True
    return True, True


def is_applicable(
    policy: Policy, binding: Binding, fixture: Fixture
) -> tuple[bool, bool]:
    """Return whether a binding enforces a policy on the given fixture."""
    any_rule = False
    any_equivalent = False
    for rule in policy.rules:
        matched, equivalent = matches_resource_rule(rule, fixture, policy.match_policy)
        if matched:
            any_rule = True
            any_equivalent = any_equivalent or equivalent
    if not any_rule:
        return False, False
    namespace_labels = fixture.namespace_labels
    if not label_selector_matches(policy.namespace_selector, namespace_labels):
        return False, False
    if not label_selector_matches(binding.namespace_selector, namespace_labels):
        return False, False
    if not label_selector_matches(policy.object_selector, fixture.labels):
        return False, False
    if not label_selector_matches(binding.object_selector, fixture.labels):
        return False, False
    return True, any_equivalent
