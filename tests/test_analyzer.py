"""Analyzer tests. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from baysoz_admissioncel.analyzer import analyze
from baysoz_admissioncel.report import render_json, render_sarif, render_text

from .factories import (
    make_binding,
    make_fixture,
    make_param,
    make_policy,
    pod_rule,
)


def _ids(result: object) -> set[str]:
    return {item.rule_id for item in result.findings}  # type: ignore[attr-defined]


def test_fail_open_evaluation_error_is_an_error() -> None:
    policy = make_policy(
        expression="object.spec.missing > 1", failure_policy="Ignore"
    )
    result = analyze([policy], [make_binding()], [make_fixture()])
    assert "VAP002" in _ids(result)
    assert result.error_count >= 1
    assert result.errors == 1


def test_fail_closed_evaluation_error_is_a_warning() -> None:
    policy = make_policy(expression="object.spec.missing > 1")
    result = analyze([policy], [make_binding()], [make_fixture()])
    assert "VAP003" in _ids(result)
    assert result.error_count == 0


def test_dead_rule_detection() -> None:
    policy = make_policy(expression="true")
    result = analyze(
        [policy],
        [make_binding()],
        [make_fixture(name="one"), make_fixture(name="two")],
    )
    assert "VAP004" in _ids(result)
    assert result.denied == 0
    assert result.allowed == 2


def test_oldobject_on_create_and_message_disclosure() -> None:
    policy = make_policy(
        expression="oldObject.spec.replicas > 0",
        message="denied object.metadata.name",
    )
    result = analyze([policy], [make_binding()], [make_fixture()])
    assert "VAP008" in _ids(result)
    assert "VAP009" in _ids(result)


def test_non_boolean_expression_rule() -> None:
    policy = make_policy(expression="1")
    result = analyze([policy], [make_binding()], [make_fixture()])
    assert "VAP013" in _ids(result)


def test_dangling_param_and_missing_binding() -> None:
    policy = make_policy(param_kind="AdmissionPolicyParams")
    result = analyze([policy], [make_binding(param_ref={"name": "absent"})], [])
    assert "VAP007" in _ids(result)


def test_compile_error_and_unbound_policy() -> None:
    policy = make_policy(expression="object.spec[")
    result = analyze([policy], [], [])
    assert "VAP001" in _ids(result)
    assert "VAP006" in _ids(result)


def test_unknown_binding_and_duplicate_names() -> None:
    policy = make_policy()
    result = analyze(
        [policy, make_policy()],
        [make_binding(policy_name="missing"), make_binding()],
        [],
    )
    assert "VAP019" in _ids(result)
    assert "VAP020" in _ids(result)


def test_equivalent_group_alias_is_flagged() -> None:
    policy = make_policy(
        match_policy="Equivalent",
        rules=(
            pod_rule(
                groups=("",),
                versions=("v1",),
                resources=("ingresses",),
                scope="*",
            ),
        ),
    )
    fixture = make_fixture(kind="Ingress", api_version="networking.k8s.io/v1")
    result = analyze([policy], [make_binding()], [fixture])
    assert "VAP011" in _ids(result)


def test_param_resolution_and_real_denial() -> None:
    policy = make_policy(
        expression="object.spec.image.startsWith(params.allowedRegistry)",
        param_kind="AdmissionPolicyParams",
    )
    binding = make_binding(param_ref={"name": "params", "namespace": "default"})
    bad = make_fixture(spec={"image": "docker.io/library/app:latest"})
    good = make_fixture(spec={"image": "registry.example.invalid/app:1"})
    result = analyze([policy], [binding], [bad, good], [make_param()])
    assert result.denied == 1
    assert result.allowed == 1
    assert "VAP007" not in _ids(result)


def test_reports_are_deterministic_and_attributed() -> None:
    policy = make_policy(expression="object.spec.missing > 1")
    result = analyze([policy], [make_binding()], [make_fixture()])
    sarif = render_sarif(result)
    assert sarif == render_sarif(result)
    assert "Baysöz Labs <baysozlabs@proton.me>" in sarif
    assert "2.1.0" in sarif
    assert "Baysöz Labs" in render_json(result)
    assert "baysoz-admissioncel" in render_text(result)
