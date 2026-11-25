"""Real CEL expression compilation and evaluation.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

import celpy
from celpy.celtypes import BoolType, MapType, StringType

from .model import (
    Evaluation,
    Fixture,
    ParamObject,
    Policy,
    Validation,
    split_api_version,
)
from .selector import resources_for_kind

_VARIABLE_REF = re.compile(r"variables\.([A-Za-z_][A-Za-z0-9_]*)")


class ExpressionError(ValueError):
    """Raised for invalid or unresolvable CEL expressions."""


class VariableCycleError(ExpressionError):
    """Raised when policy variables form a dependency cycle."""


class CelEngine:
    """Stateful compiler/evaluator with a bounded compiled-expression cache."""

    def __init__(self) -> None:
        self._env = celpy.Environment()
        self._cache: dict[str, Any] = {}

    def compile(self, expression: str) -> Any:
        """Compile an expression, raising ExpressionError on parse failure."""
        cached = self._cache.get(expression)
        if cached is not None:
            return cached
        try:
            program = self._env.program(self._env.compile(expression))
        except Exception as exc:
            msg = f"CEL parse error: {exc}"
            raise ExpressionError(msg) from exc
        self._cache[expression] = program
        return program

    @staticmethod
    def request_context(fixture: Fixture) -> dict[str, Any]:
        """Build the request activation object from a fixture."""
        group, version = split_api_version(fixture.api_version)
        metadata = fixture.object.get("metadata")
        name = (
            str(metadata.get("name", fixture.name))
            if isinstance(metadata, Mapping)
            else fixture.name
        )
        uid_source = f"{fixture.name}|{fixture.operation}|{name}".encode()
        digest = hashlib.sha256(uid_source).hexdigest()
        return {
            "uid": f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-"
            f"{digest[16:20]}-{digest[20:32]}",
            "kind": {"apiVersion": fixture.api_version, "kind": fixture.kind},
            "resource": {
                "group": group,
                "version": version,
                "resource": resources_for_kind(fixture.kind)[0],
            },
            "subResource": fixture.subresource,
            "requestKind": {"apiVersion": fixture.api_version, "kind": fixture.kind},
            "name": name,
            "namespace": fixture.namespace or "",
            "operation": fixture.operation,
            "userInfo": {
                "username": "system:serviceaccount:baysöz-labs:admission-oracle",
                "groups": ["system:authenticated"],
            },
            "dryRun": True,
        }

    @staticmethod
    def _variable_order(policy: Policy) -> list[str]:
        dependencies = {
            name: sorted(_VARIABLE_REF.findall(expression))
            for name, expression in policy.variables
        }
        known = set(dependencies)
        for name, refs in dependencies.items():
            unknown = set(refs) - known
            if unknown:
                refs_text = sorted(unknown)
                msg = (
                    f"variable '{name}' references unknown variable: "
                    f"{refs_text}"
                )
                raise VariableCycleError(msg)
        ordered: list[str] = []
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(name: str) -> None:
            if name in visited:
                return
            if name in visiting:
                msg = f"variable dependency cycle at '{name}'"
                raise VariableCycleError(msg)
            visiting.add(name)
            for dependency in dependencies.get(name, ()):
                visit(dependency)
            visiting.remove(name)
            visited.add(name)
            ordered.append(name)

        for name in dependencies:
            visit(name)
        return ordered

    def _activation(
        self,
        fixture: Fixture,
        params: ParamObject | None,
        variables: Mapping[str, Any],
    ) -> dict[str, Any]:
        return {
            "object": celpy.json_to_cel(dict(fixture.object)),
            "oldObject": (
                celpy.json_to_cel(dict(fixture.old_object))
                if fixture.old_object is not None
                else None
            ),
            "params": (
                celpy.json_to_cel(dict(params.data))
                if params is not None
                else celpy.json_to_cel({})
            ),
            "request": celpy.json_to_cel(self.request_context(fixture)),
            "variables": MapType(
                {StringType(name): value for name, value in variables.items()}
            ),
        }

    def validate_variables(self, policy: Policy) -> list[str]:
        """Return a stable variable evaluation order or raise VariableCycleError."""
        return self._variable_order(policy)

    def evaluate_variables(
        self, policy: Policy, fixture: Fixture, params: ParamObject | None
    ) -> dict[str, Any]:
        """Evaluate policy variables in dependency order for one fixture."""
        expressions = dict(policy.variables)
        values: dict[str, Any] = {}
        for name in self._variable_order(policy):
            program = self.compile(expressions[name])
            context = self._activation(fixture, params, values)
            try:
                values[name] = program.evaluate(context)
            except Exception as exc:
                msg = f"variable '{name}' evaluation failed: {exc}"
                raise ExpressionError(msg) from exc
        return values

    def evaluate_validation(
        self,
        policy: Policy,
        validation: Validation,
        fixture: Fixture,
        params: ParamObject | None,
    ) -> Evaluation:
        """Evaluate a real CEL validation expression; never simulate its result."""
        try:
            program = self.compile(validation.expression)
            variables = self.evaluate_variables(policy, fixture, params)
            value = program.evaluate(self._activation(fixture, params, variables))
        except ExpressionError as exc:
            return Evaluation(outcome="error", detail=str(exc))
        except Exception as exc:
            return Evaluation(
                outcome="error", detail=f"CEL evaluation error: {exc}"
            )
        if not isinstance(value, BoolType):
            return Evaluation(
                outcome="error", detail=f"expression returned {type(value).__name__}"
            )
        if bool(value):
            return Evaluation(outcome="allow")
        return Evaluation(outcome="deny")
