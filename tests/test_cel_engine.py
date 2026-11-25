"""CEL engine tests. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import pytest

from baysoz_admissioncel.cel_engine import (
    CelEngine,
    ExpressionError,
    VariableCycleError,
)
from baysoz_admissioncel.model import Validation

from .factories import make_fixture, make_param, make_policy


def test_real_cel_allow_deny_and_macros() -> None:
    engine = CelEngine()
    policy = make_policy()
    fixture = make_fixture(
        spec={
            "containers": [
                {"name": "app", "image": "registry.example.invalid/app:1"}
            ]
        }
    )
    assert engine.evaluate_validation(
        policy,
        Validation(
            expression="object.spec.containers.all(c, c.image.startsWith('registry'))",
            index=0,
        ),
        fixture,
        None,
    ).outcome == "allow"
    assert engine.evaluate_validation(
        policy,
        Validation(expression="object.spec.replicas > 3", index=0),
        fixture,
        None,
    ).outcome == "error"


def test_variables_are_evaluated_in_dependency_order() -> None:
    engine = CelEngine()
    policy = make_policy(
        variables=(
            ("registry", "'registry.example.invalid/'"),
            ("trusted", "object.spec.image.startsWith(variables.registry)"),
        )
    )
    fixture = make_fixture(spec={"image": "registry.example.invalid/app:1"})
    result = engine.evaluate_validation(
        policy, policy.validations[0], fixture, None
    )
    assert result.outcome == "allow"


def test_request_context_is_deterministic_and_attributed() -> None:
    fixture = make_fixture()
    first = CelEngine.request_context(fixture)
    second = CelEngine.request_context(fixture)
    assert first == second
    assert first["operation"] == "CREATE"
    assert first["userInfo"]["username"] == (
        "system:serviceaccount:baysöz-labs:admission-oracle"
    )


def test_params_activation() -> None:
    engine = CelEngine()
    policy = make_policy()
    validation = Validation(
        expression="params.allowedRegistry.startsWith('registry.')", index=0
    )
    assert engine.evaluate_validation(
        policy, validation, make_fixture(), make_param()
    ).outcome == "allow"


def test_parse_error_and_cycle_are_reported() -> None:
    engine = CelEngine()
    with pytest.raises(ExpressionError):
        engine.compile("object.spec[")
    cyclic = make_policy(variables=(("a", "variables.b"), ("b", "variables.a")))
    with pytest.raises(VariableCycleError):
        engine.validate_variables(cyclic)


def test_non_boolean_result_is_an_error() -> None:
    engine = CelEngine()
    policy = make_policy()
    validation = Validation(expression="1", index=0)
    result = engine.evaluate_validation(policy, validation, make_fixture(), None)
    assert result.outcome == "error"
    assert "expression returned" in result.detail


def test_oldobject_on_create_is_an_error() -> None:
    engine = CelEngine()
    policy = make_policy()
    validation = Validation(
        expression="oldObject.spec.replicas > 0", index=0
    )
    result = engine.evaluate_validation(policy, validation, make_fixture(), None)
    assert result.outcome == "error"
