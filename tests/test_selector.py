"""Selector semantics tests. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from baysoz_admissioncel.model import Fixture, ResourceRule
from baysoz_admissioncel.selector import (
    is_applicable,
    label_selector_matches,
    matches_resource_rule,
    resources_for_kind,
)

from .factories import make_binding, make_fixture, make_policy


def _fixture(**kwargs: object) -> Fixture:
    return make_fixture(**kwargs)  # type: ignore[arg-type]


def test_resource_alias_mapping() -> None:
    assert resources_for_kind("Pod") == ("pods",)
    assert "ingresses" in resources_for_kind("Ingress")
    assert "networkpolicies" in resources_for_kind("NetworkPolicy")


def test_exact_resource_rule_matching() -> None:
    rule = ResourceRule(("",), ("v1",), ("pods",), ("CREATE",), "Namespaced")
    matched, equivalent = matches_resource_rule(rule, _fixture(), "Exact")
    assert matched is True
    assert equivalent is False
    cluster = _fixture(name="node", kind="Node", api_version="v1")
    assert matches_resource_rule(rule, cluster, "Exact")[0] is False


def test_wildcard_and_equivalent_group_matching() -> None:
    ingress = _fixture(
        kind="Ingress",
        api_version="networking.k8s.io/v1",
    )
    exact_rule = ResourceRule(
        ("networking.k8s.io",), ("v1",), ("ingresses",), ("CREATE",), "*"
    )
    assert matches_resource_rule(exact_rule, ingress, "Exact")[0] is True
    aliased = ResourceRule(("",), ("v1",), ("ingresses",), ("CREATE",), "*")
    matched, equivalent = matches_resource_rule(aliased, ingress, "Equivalent")
    assert matched is True
    assert equivalent is True


def test_label_selector_operators() -> None:
    labels = {"app": "api", "tier": "backend"}
    assert label_selector_matches({"matchLabels": {"app": "api"}}, labels)
    assert not label_selector_matches({"matchLabels": {"app": "web"}}, labels)
    expressions = {
        "matchExpressions": [
            {"key": "app", "operator": "In", "values": ["api", "web"]},
            {"key": "secret", "operator": "DoesNotExist"},
        ]
    }
    assert label_selector_matches(expressions, labels)
    assert not label_selector_matches(
        {
            "matchExpressions": [
                {"key": "tier", "operator": "NotIn", "values": ["backend"]}
            ]
        },
        labels,
    )


def test_is_applicable_requires_policy_and_binding_selectors() -> None:
    policy = make_policy()
    binding = make_binding(namespace_selector={"matchLabels": {"team": "platform"}})
    fixture = _fixture()
    assert is_applicable(policy, binding, fixture)[0] is True
    other = make_binding(namespace_selector={"matchLabels": {"team": "other"}})
    assert is_applicable(policy, other, fixture)[0] is False
    object_binding = make_binding(object_selector={"matchLabels": {"app": "web"}})
    assert is_applicable(policy, object_binding, fixture)[0] is False
