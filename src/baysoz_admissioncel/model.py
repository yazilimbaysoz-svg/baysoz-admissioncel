"""Domain model for the Baysöz Labs admission-policy oracle.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Fixture:
    """A concrete admission request replayed against policies."""

    name: str
    api_version: str
    kind: str
    object: Mapping[str, Any]
    operation: str
    source: str
    old_object: Mapping[str, Any] | None = None
    namespace: str | None = None
    namespace_labels: Mapping[str, str] = field(default_factory=dict)
    labels: Mapping[str, str] = field(default_factory=dict)
    subresource: str = ""

    @property
    def group(self) -> str:
        """Return the API group, with the core group spelled as empty string."""
        return split_api_version(self.api_version)[0]

    @property
    def version(self) -> str:
        """Return the API version component of the fixture apiVersion."""
        return split_api_version(self.api_version)[1]


@dataclass(frozen=True, slots=True)
class ResourceRule:
    """A matchConstraints.resourceRules entry."""

    api_groups: tuple[str, ...]
    api_versions: tuple[str, ...]
    resources: tuple[str, ...]
    operations: tuple[str, ...]
    scope: str = "*"
    resource_names: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Validation:
    """A single CEL validation expression in a policy."""

    expression: str
    index: int
    message: str = "denied by admission policy"
    reason: str = "Invalid"
    audit_annotations: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Policy:
    """A ValidatingAdmissionPolicy document."""

    name: str
    source: str
    rules: tuple[ResourceRule, ...]
    validations: tuple[Validation, ...]
    variables: tuple[tuple[str, str], ...] = ()
    failure_policy: str = "Fail"
    match_policy: str = "Exact"
    param_kind: str | None = None
    namespace_selector: Mapping[str, Any] | None = None
    object_selector: Mapping[str, Any] | None = None
    line: int = 1


@dataclass(frozen=True, slots=True)
class Binding:
    """A ValidatingAdmissionPolicyBinding document."""

    name: str
    policy_name: str
    source: str
    param_ref: Mapping[str, Any] | None = None
    namespace_selector: Mapping[str, Any] | None = None
    object_selector: Mapping[str, Any] | None = None
    validation_actions: Mapping[str, str] = field(default_factory=dict)
    line: int = 1


@dataclass(frozen=True, slots=True)
class ParamObject:
    """A parameter object referenced by a binding."""

    name: str
    kind: str
    data: Mapping[str, Any]
    namespace: str = ""
    source: str = ""


@dataclass(frozen=True, slots=True)
class Evaluation:
    """Result of evaluating one CEL expression against one fixture."""

    outcome: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class Finding:
    """A deterministic, reportable policy defect."""

    rule_id: str
    level: str
    message: str
    source: str = ""
    line: int = 1
    policy: str = ""
    binding: str = ""
    fixture: str = ""
    evidence: str = ""


@dataclass(slots=True)
class CheckResult:
    """Aggregated analyzer output and measurable execution statistics."""

    findings: list[Finding] = field(default_factory=list)
    policies: int = 0
    bindings: int = 0
    fixtures: int = 0
    evaluations: int = 0
    allowed: int = 0
    denied: int = 0
    errors: int = 0
    matched: int = 0

    @property
    def error_count(self) -> int:
        """Return the number of ERROR-level findings."""
        return sum(item.level == "ERROR" for item in self.findings)

    @property
    def warning_count(self) -> int:
        """Return the number of WARNING-level findings."""
        return sum(item.level == "WARNING" for item in self.findings)


def split_api_version(api_version: str) -> tuple[str, str]:
    """Split an apiVersion into group and version, normalizing the core group."""
    if "/" in api_version:
        group, version = api_version.split("/", 1)
        return group, version
    return "", api_version


def tuple_of_strings(value: Any) -> tuple[str, ...]:
    """Convert a YAML sequence of scalars into a stable tuple of strings."""
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    return tuple(str(item) for item in value)
