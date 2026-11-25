"""Deterministic YAML loading and normalization.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .model import (
    Binding,
    Fixture,
    ParamObject,
    Policy,
    ResourceRule,
    Validation,
    tuple_of_strings,
)

POLICY_KIND = "ValidatingAdmissionPolicy"
BINDING_KIND = "ValidatingAdmissionPolicyBinding"
FIXTURE_KIND = "AdmissionFixture"


class LoadError(ValueError):
    """Raised when an input document cannot be interpreted safely."""


@dataclass(frozen=True, slots=True)
class Document:
    """One YAML document with provenance."""

    kind: str
    data: Mapping[str, Any]
    source: str
    line: int


def _read_documents(paths: Iterable[str | Path]) -> list[Document]:
    documents: list[Document] = []
    for raw_path in paths:
        path = Path(raw_path)
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            msg = f"cannot read {path}: {exc}"
            raise LoadError(msg) from exc
        try:
            nodes = list(yaml.compose_all(text))
            loaded = list(yaml.safe_load_all(text))
        except yaml.YAMLError as exc:
            msg = f"invalid YAML in {path}: {exc}"
            raise LoadError(msg) from exc
        if len(nodes) != len(loaded):
            msg = f"YAML node mismatch in {path}"
            raise LoadError(msg)
        for node, data in zip(nodes, loaded, strict=True):
            if data is None:
                continue
            if not isinstance(data, Mapping):
                msg = f"{path}:{node.start_mark.line + 1} expected a mapping"
                raise LoadError(msg)
            kind = str(data.get("kind", ""))
            if not kind:
                continue
            documents.append(
                Document(
                    kind=kind,
                    data=data,
                    source=str(path),
                    line=node.start_mark.line + 1,
                )
            )
    return documents


def _metadata_name(data: Mapping[str, Any], source: str) -> str:
    metadata = data.get("metadata")
    if not isinstance(metadata, Mapping) or not metadata.get("name"):
        msg = f"{source}: metadata.name is required"
        raise LoadError(msg)
    return str(metadata["name"])


def _spec(data: Mapping[str, Any], source: str) -> Mapping[str, Any]:
    spec = data.get("spec")
    if not isinstance(spec, Mapping):
        msg = f"{source}: spec must be a mapping"
        raise LoadError(msg)
    return spec


def load_policies(paths: Iterable[str | Path]) -> tuple[Policy, ...]:
    """Load all ValidatingAdmissionPolicy documents from the given paths."""
    policies: list[Policy] = []
    for doc in _read_documents(paths):
        if doc.kind != POLICY_KIND:
            continue
        spec = _spec(doc.data, doc.source)
        rules: list[ResourceRule] = []
        constraints = spec.get("matchConstraints")
        if isinstance(constraints, Mapping):
            for raw_rule in constraints.get("resourceRules") or ():
                if not isinstance(raw_rule, Mapping):
                    msg = f"{doc.source}: resourceRules entries must be mappings"
                    raise LoadError(msg)
                rules.append(
                    ResourceRule(
                        api_groups=tuple_of_strings(raw_rule.get("apiGroups")),
                        api_versions=tuple_of_strings(raw_rule.get("apiVersions")),
                        resources=tuple_of_strings(
                            raw_rule.get("resources")
                            or raw_rule.get("kinds")
                        ),
                        operations=tuple_of_strings(raw_rule.get("operations")),
                        scope=str(raw_rule.get("scope", "*")),
                        resource_names=tuple_of_strings(
                            raw_rule.get("resourceNames")
                        ),
                    )
                )
        validations: list[Validation] = []
        for index, raw_validation in enumerate(spec.get("validations") or ()):
            if not isinstance(raw_validation, Mapping):
                msg = f"{doc.source}: validations entries must be mappings"
                raise LoadError(msg)
            expression = raw_validation.get("expression")
            if not isinstance(expression, str) or not expression.strip():
                msg = f"{doc.source}: validation {index} needs an expression"
                raise LoadError(msg)
            annotations = raw_validation.get("auditAnnotations") or {}
            if not isinstance(annotations, Mapping):
                annotations = {}
            validations.append(
                Validation(
                    expression=expression,
                    index=index,
                    message=str(raw_validation.get("message", "denied")),
                    reason=str(raw_validation.get("reason", "Invalid")),
                    audit_annotations={
                        str(key): str(value)
                        for key, value in annotations.items()
                    },
                )
            )
        variables: list[tuple[str, str]] = []
        for raw_variable in spec.get("variables") or ():
            if not isinstance(raw_variable, Mapping):
                msg = f"{doc.source}: variables entries must be mappings"
                raise LoadError(msg)
            name = raw_variable.get("name")
            expression = raw_variable.get("expression")
            if not isinstance(name, str) or not isinstance(expression, str):
                msg = f"{doc.source}: variable name and expression are required"
                raise LoadError(msg)
            variables.append((name, expression))
        param_kind = None
        raw_param_kind = spec.get("paramKind")
        if isinstance(raw_param_kind, Mapping) and raw_param_kind.get("kind"):
            param_kind = str(raw_param_kind["kind"])
        policies.append(
            Policy(
                name=_metadata_name(doc.data, doc.source),
                source=doc.source,
                rules=tuple(rules),
                validations=tuple(validations),
                variables=tuple(variables),
                failure_policy=str(spec.get("failurePolicy", "Fail")),
                match_policy=str(spec.get("matchPolicy", "Exact")),
                param_kind=param_kind,
                namespace_selector=spec.get("namespaceSelector")
                if isinstance(spec.get("namespaceSelector"), Mapping)
                else None,
                object_selector=spec.get("objectSelector")
                if isinstance(spec.get("objectSelector"), Mapping)
                else None,
                line=doc.line,
            )
        )
    return tuple(policies)


def load_bindings(paths: Iterable[str | Path]) -> tuple[Binding, ...]:
    """Load all ValidatingAdmissionPolicyBinding documents."""
    bindings: list[Binding] = []
    for doc in _read_documents(paths):
        if doc.kind != BINDING_KIND:
            continue
        spec = _spec(doc.data, doc.source)
        policy_name = spec.get("policyName")
        if not isinstance(policy_name, str) or not policy_name:
            msg = f"{doc.source}: spec.policyName is required"
            raise LoadError(msg)
        actions = spec.get("validationActions") or {}
        if not isinstance(actions, Mapping):
            actions = {}
        bindings.append(
            Binding(
                name=_metadata_name(doc.data, doc.source),
                policy_name=policy_name,
                source=doc.source,
                param_ref=spec.get("paramRef")
                if isinstance(spec.get("paramRef"), Mapping)
                else None,
                namespace_selector=spec.get("namespaceSelector")
                if isinstance(spec.get("namespaceSelector"), Mapping)
                else None,
                object_selector=spec.get("objectSelector")
                if isinstance(spec.get("objectSelector"), Mapping)
                else None,
                validation_actions={
                    str(key): str(value) for key, value in actions.items()
                },
                line=doc.line,
            )
        )
    return tuple(bindings)


def load_param_objects(paths: Iterable[str | Path]) -> tuple[ParamObject, ...]:
    """Load non-policy documents that may serve as binding parameters."""
    params: list[ParamObject] = []
    for doc in _read_documents(paths):
        if doc.kind in {POLICY_KIND, BINDING_KIND, FIXTURE_KIND}:
            continue
        items: list[Mapping[str, Any]] = []
        if doc.kind == "List" and isinstance(doc.data.get("items"), list):
            items = [
                item
                for item in doc.data["items"]
                if isinstance(item, Mapping)
            ]
        else:
            items = [doc.data]
        for item in items:
            metadata = item.get("metadata")
            if not isinstance(metadata, Mapping) or not metadata.get("name"):
                continue
            params.append(
                ParamObject(
                    name=str(metadata["name"]),
                    kind=str(item.get("kind", "")),
                    data=item,
                    namespace=str(metadata.get("namespace", "")),
                    source=doc.source,
                )
            )
    return tuple(params)


def _labels(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def _fixture_from_doc(doc: Document) -> list[Fixture]:
    if doc.kind == "List":
        children = [
            item for item in doc.data.get("items", []) if isinstance(item, Mapping)
        ]
        result: list[Fixture] = []
        for child in children:
            synthetic = Document(
                kind=str(child.get("kind", "")),
                data=child,
                source=doc.source,
                line=doc.line,
            )
            result.extend(_fixture_from_doc(synthetic))
        return result
    if doc.kind == FIXTURE_KIND:
        spec = _spec(doc.data, doc.source)
        api_version = str(spec.get("apiVersion", "v1"))
        kind = str(spec.get("kind", "Pod"))
        obj = spec.get("object")
        if not isinstance(obj, Mapping):
            msg = f"{doc.source}: fixture.object must be a mapping"
            raise LoadError(msg)
        metadata = obj.get("metadata")
        labels = (
            _labels(metadata.get("labels"))
            if isinstance(metadata, Mapping)
            else {}
        )
        namespace = (
            str(metadata.get("namespace", ""))
            if isinstance(metadata, Mapping) and metadata.get("namespace")
            else None
        )
        old_object = spec.get("oldObject")
        return [
            Fixture(
                name=doc.data.get("metadata", {}).get("name", doc.kind)
                if isinstance(doc.data.get("metadata"), Mapping)
                else str(spec.get("name", doc.kind)),
                api_version=api_version,
                kind=kind,
                object=obj,
                operation=str(spec.get("operation", "CREATE")).upper(),
                source=doc.source,
                old_object=old_object if isinstance(old_object, Mapping) else None,
                namespace=namespace,
                namespace_labels=_labels(spec.get("namespaceLabels")),
                labels=labels,
                subresource=str(spec.get("subresource", "")),
            )
        ]
    metadata = doc.data.get("metadata")
    labels = _labels(metadata.get("labels")) if isinstance(metadata, Mapping) else {}
    namespace = (
        str(metadata.get("namespace", ""))
        if isinstance(metadata, Mapping) and metadata.get("namespace")
        else None
    )
    return [
        Fixture(
            name=str(metadata.get("name", doc.kind))
            if isinstance(metadata, Mapping)
            else doc.kind,
            api_version=str(doc.data.get("apiVersion", "v1")),
            kind=doc.kind,
            object=doc.data,
            operation="CREATE",
            source=doc.source,
            namespace=namespace,
            namespace_labels={},
            labels=labels,
        )
    ]


def load_fixtures(paths: Iterable[str | Path]) -> tuple[Fixture, ...]:
    """Load admission fixtures and raw Kubernetes objects as fixtures."""
    fixtures: list[Fixture] = []
    for doc in _read_documents(paths):
        fixtures.extend(_fixture_from_doc(doc))
    return tuple(fixtures)
