"""Shared test factories. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from typing import Any

from baysoz_admissioncel.model import (
    Binding,
    Fixture,
    ParamObject,
    Policy,
    ResourceRule,
    Validation,
)


def pod_rule(
    *,
    operations: tuple[str, ...] = ("CREATE", "UPDATE"),
    groups: tuple[str, ...] = ("",),
    versions: tuple[str, ...] = ("v1",),
    resources: tuple[str, ...] = ("pods",),
    scope: str = "Namespaced",
) -> ResourceRule:
    return ResourceRule(groups, versions, resources, operations, scope)


def make_policy(
    *,
    name: str = "policy",
    expression: str = "true",
    failure_policy: str = "Fail",
    match_policy: str = "Exact",
    rules: tuple[ResourceRule, ...] | None = None,
    variables: tuple[tuple[str, str], ...] = (),
    param_kind: str | None = None,
    message: str = "denied",
) -> Policy:
    return Policy(
        name=name,
        source="policy.yaml",
        rules=rules if rules is not None else (pod_rule(),),
        validations=(Validation(expression=expression, index=0, message=message),),
        variables=variables,
        failure_policy=failure_policy,
        match_policy=match_policy,
        param_kind=param_kind,
    )


def make_binding(
    *,
    name: str = "binding",
    policy_name: str = "policy",
    param_ref: dict[str, Any] | None = None,
    namespace_selector: dict[str, Any] | None = None,
    object_selector: dict[str, Any] | None = None,
) -> Binding:
    return Binding(
        name=name,
        policy_name=policy_name,
        source="binding.yaml",
        param_ref=param_ref,
        namespace_selector=namespace_selector,
        object_selector=object_selector,
    )


def make_fixture(
    *,
    name: str = "fixture",
    operation: str = "CREATE",
    kind: str = "Pod",
    api_version: str = "v1",
    spec: dict[str, Any] | None = None,
    labels: dict[str, str] | None = None,
    namespace_labels: dict[str, str] | None = None,
    old_object: dict[str, Any] | None = None,
) -> Fixture:
    obj: dict[str, Any] = {
        "apiVersion": api_version,
        "kind": kind,
        "metadata": {
            "name": name,
            "namespace": "default",
            "labels": labels or {"app": "demo"},
        },
    }
    if spec is not None:
        obj["spec"] = spec
    return Fixture(
        name=name,
        api_version=api_version,
        kind=kind,
        object=obj,
        operation=operation,
        source="fixtures.yaml",
        old_object=old_object,
        namespace="default",
        namespace_labels=namespace_labels or {"team": "platform"},
        labels=labels or {"app": "demo"},
    )


def make_param(
    *, name: str = "params", kind: str = "AdmissionPolicyParams"
) -> ParamObject:
    return ParamObject(
        name=name,
        kind=kind,
        data={"allowedRegistry": "registry.example.invalid/"},
        namespace="default",
        source="params.yaml",
    )
