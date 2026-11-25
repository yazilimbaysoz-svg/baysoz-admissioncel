"""Policy analysis: real evaluation, defect detection, deterministic findings.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from .cel_engine import CelEngine, ExpressionError, VariableCycleError
from .model import (
    Binding,
    CheckResult,
    Finding,
    Fixture,
    ParamObject,
    Policy,
    split_api_version,
)
from .selector import is_applicable, resource_matches

_OLDOBJECT_REF = re.compile(r"\boldObject\b")
_OBJECT_FIELD_REF = re.compile(r"\b(?:object|oldObject)\.")
_RULE_TITLES = {
    "VAP001": "CEL expression does not compile",
    "VAP002": "Fail-open evaluation error",
    "VAP003": "Fail-closed evaluation error",
    "VAP004": "Validation never denies any fixture",
    "VAP005": "Policy configured with failurePolicy Ignore",
    "VAP006": "Policy has no binding",
    "VAP007": "Binding parameter reference is unresolved",
    "VAP008": "oldObject consumed on CREATE",
    "VAP009": "Denial message may disclose request fields",
    "VAP010": "Match constraints are unbounded",
    "VAP011": "Equivalent group alias is unverified",
    "VAP012": "Policy was not exercised by any fixture",
    "VAP013": "Expression returned a non-boolean value",
    "VAP014": "Policy variables form an invalid dependency graph",
    "VAP015": "Bindings shadow each other",
    "VAP018": "paramKind declared without paramRef",
    "VAP019": "Binding references unknown policy",
    "VAP020": "Duplicate resource name",
    "VAP021": "Policy has no validations",
    "VAP022": "Binding supplies a parameter to a policy without paramKind",
}


def _clip(text: str, limit: int = 320) -> str:
    return text if len(text) <= limit else f"{text[: limit - 3]}..."


class Analyzer:
    """Analyze ValidatingAdmissionPolicy programs against concrete requests."""

    def __init__(self, engine: CelEngine | None = None) -> None:
        self.engine = engine or CelEngine()

    @staticmethod
    def _finding(
        rule_id: str,
        level: str,
        message: str,
        *,
        source: str = "",
        line: int = 1,
        policy: str = "",
        binding: str = "",
        fixture: str = "",
        evidence: str = "",
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            level=level,
            message=message,
            source=source,
            line=line,
            policy=policy,
            binding=binding,
            fixture=fixture,
            evidence=_clip(evidence),
        )

    def _resolve_param(
        self,
        binding: Binding,
        policy: Policy,
        params: Sequence[ParamObject],
    ) -> ParamObject | None:
        ref = binding.param_ref or {}
        name = str(ref.get("name", ""))
        namespace = str(ref.get("namespace", ""))
        kind = str(ref.get("kind", policy.param_kind or ""))
        if not name:
            return None
        for param in params:
            if param.name != name:
                continue
            if param.kind != kind:
                continue
            if namespace and param.namespace != namespace:
                continue
            return param
        return None

    @staticmethod
    def _unbounded(policy: Policy) -> bool:
        if policy.namespace_selector or policy.object_selector:
            return False
        for rule in policy.rules:
            if not rule.resources or "*" in rule.resources:
                return True
        return False

    @staticmethod
    def _groups_for_fixture(policy: Policy, fixture: Fixture) -> set[str]:
        groups: set[str] = set()
        for rule in policy.rules:
            if resource_matches(rule.resources, fixture.kind):
                groups.update(rule.api_groups)
        return groups

    def _report_message_leak(
        self, policy: Policy, binding: Binding, result: CheckResult
    ) -> None:
        for validation in policy.validations:
            targets = [validation.message, *validation.audit_annotations.values()]
            if any(_OBJECT_FIELD_REF.search(target) for target in targets):
                result.findings.append(
                    self._finding(
                        "VAP009",
                        "WARNING",
                        "denial metadata interpolates request object fields",
                        source=policy.source,
                        line=policy.line,
                        policy=policy.name,
                        binding=binding.name,
                        evidence=validation.message,
                    )
                )

    def _register_duplicates(
        self,
        policies: Sequence[Policy],
        bindings: Sequence[Binding],
        result: CheckResult,
    ) -> None:
        seen: set[tuple[str, str]] = set()
        for item in [*policies, *bindings]:
            key = (type(item).__name__, item.name)
            if key in seen:
                result.findings.append(
                    self._finding(
                        "VAP020",
                        "ERROR",
                        f"duplicate resource name '{item.name}'",
                        source=item.source,
                        line=item.line,
                        policy=item.name if isinstance(item, Policy) else "",
                        binding=item.name if isinstance(item, Binding) else "",
                    )
                )
            seen.add(key)

    def analyze(
        self,
        policies: Iterable[Policy],
        bindings: Iterable[Binding],
        fixtures: Iterable[Fixture],
        params: Iterable[ParamObject] = (),
    ) -> CheckResult:
        """Evaluate every applicable policy/binding/fixture triple."""
        policy_list = tuple(policies)
        binding_list = tuple(bindings)
        fixture_list = tuple(fixtures)
        param_list = tuple(params)
        result = CheckResult(
            policies=len(policy_list),
            bindings=len(binding_list),
            fixtures=len(fixture_list),
        )
        self._register_duplicates(policy_list, binding_list, result)

        policy_names = {policy.name for policy in policy_list}
        for binding in binding_list:
            if binding.policy_name not in policy_names:
                result.findings.append(
                    self._finding(
                        "VAP019",
                        "ERROR",
                        f"binding targets unknown policy '{binding.policy_name}'",
                        source=binding.source,
                        line=binding.line,
                        binding=binding.name,
                    )
                )

        for policy in policy_list:
            self._analyze_policy(
                policy, binding_list, fixture_list, param_list, result
            )
        result.findings = self._sorted_findings(result.findings)
        return result

    @staticmethod
    def _sorted_findings(findings: list[Finding]) -> list[Finding]:
        unique = {
            (
                item.rule_id,
                item.level,
                item.source,
                item.line,
                item.policy,
                item.binding,
                item.fixture,
                item.message,
            ): item
            for item in findings
        }
        return sorted(
            unique.values(),
            key=lambda item: (
                item.source,
                item.line,
                item.rule_id,
                item.policy,
                item.binding,
                item.fixture,
                item.message,
            ),
        )

    def _analyze_policy(
        self,
        policy: Policy,
        bindings: Sequence[Binding],
        fixtures: Sequence[Fixture],
        params: Sequence[ParamObject],
        result: CheckResult,
    ) -> None:
        base = dict(source=policy.source, line=policy.line, policy=policy.name)
        if not policy.validations:
            result.findings.append(
                self._finding(
                    "VAP021", "ERROR", "policy declares no validations", **base
                )
            )
        if not policy.rules:
            result.findings.append(
                self._finding(
                    "VAP010",
                    "ERROR",
                    "policy declares no matchConstraints rules",
                    **base,
                )
            )
        elif self._unbounded(policy):
            result.findings.append(
                self._finding(
                    "VAP010",
                    "WARNING",
                    "wildcard kinds without namespace or object selector",
                    **base,
                )
            )
        if policy.failure_policy == "Ignore":
            result.findings.append(
                self._finding(
                    "VAP005",
                    "WARNING",
                    "failurePolicy Ignore permits requests on evaluation error",
                    **base,
                )
            )
        own_bindings = [item for item in bindings if item.policy_name == policy.name]
        if not own_bindings:
            result.findings.append(
                self._finding("VAP006", "ERROR", "policy has no binding", **base)
            )
        if policy.param_kind and not any(item.param_ref for item in own_bindings):
            result.findings.append(
                self._finding(
                    "VAP018",
                    "ERROR",
                    f"paramKind {policy.param_kind} has no binding paramRef",
                    **base,
                )
            )
        try:
            for validation in policy.validations:
                self.engine.compile(validation.expression)
            self.engine.validate_variables(policy)
        except VariableCycleError as exc:
            result.findings.append(
                self._finding(
                    "VAP014", "ERROR", str(exc), evidence=str(policy.variables), **base
                )
            )
            return
        except ExpressionError as exc:
            result.findings.append(
                self._finding("VAP001", "ERROR", str(exc), **base)
            )
            return

        seen_binding_shapes: set[str] = set()
        for binding in own_bindings:
            self._analyze_binding(
                policy, binding, fixtures, params, result, seen_binding_shapes
            )

    def _analyze_binding(
        self,
        policy: Policy,
        binding: Binding,
        fixtures: Sequence[Fixture],
        params: Sequence[ParamObject],
        result: CheckResult,
        seen_binding_shapes: set[str],
    ) -> None:
        base = dict(source=binding.source, line=binding.line, binding=binding.name)
        if binding.param_ref and not policy.param_kind:
            result.findings.append(
                self._finding(
                    "VAP022",
                    "WARNING",
                    "binding parameter ignored: policy declares no paramKind",
                    **base,
                    policy=policy.name,
                )
            )
        shape = repr(
            (binding.namespace_selector, binding.object_selector, binding.param_ref)
        )
        if shape in seen_binding_shapes:
            result.findings.append(
                self._finding(
                    "VAP015",
                    "WARNING",
                    "binding selectors and parameters duplicate another binding",
                    **base,
                    policy=policy.name,
                )
            )
        seen_binding_shapes.add(shape)

        param = None
        if policy.param_kind or binding.param_ref:
            param = self._resolve_param(binding, policy, params)
            if param is None:
                result.findings.append(
                    self._finding(
                        "VAP007",
                        "ERROR",
                        "paramRef does not resolve to a supplied parameter object",
                        **base,
                        policy=policy.name,
                        evidence=str(binding.param_ref),
                    )
                )
                return
        self._report_message_leak(policy, binding, result)

        denials: dict[int, int] = {item.index: 0 for item in policy.validations}
        evaluations: dict[int, int] = {item.index: 0 for item in policy.validations}
        error_counts: dict[int, int] = {item.index: 0 for item in policy.validations}
        matched = 0
        for fixture in fixtures:
            applicable, equivalent = is_applicable(policy, binding, fixture)
            if not applicable:
                continue
            matched += 1
            if equivalent:
                groups = self._groups_for_fixture(policy, fixture)
                group, _version = split_api_version(fixture.api_version)
                if group and group not in groups:
                    result.findings.append(
                        self._finding(
                            "VAP011",
                            "WARNING",
                            "Equivalent policy covers an aliased API group "
                            "without a verified conversion path",
                            source=policy.source,
                            line=policy.line,
                            policy=policy.name,
                            binding=binding.name,
                            fixture=fixture.name,
                            evidence=fixture.api_version,
                        )
                    )
            for validation in policy.validations:
                if (
                    _OLDOBJECT_REF.search(validation.expression)
                    and fixture.operation == "CREATE"
                ):
                    result.findings.append(
                        self._finding(
                            "VAP008",
                            "ERROR",
                            "expression reads oldObject on CREATE, where it is null",
                            source=policy.source,
                            line=policy.line,
                            policy=policy.name,
                            binding=binding.name,
                            fixture=fixture.name,
                            evidence=validation.expression,
                        )
                    )
                evaluation = self.engine.evaluate_validation(
                    policy, validation, fixture, param
                )
                result.evaluations += 1
                evaluations[validation.index] += 1
                if evaluation.outcome == "allow":
                    result.allowed += 1
                elif evaluation.outcome == "deny":
                    result.denied += 1
                    denials[validation.index] += 1
                else:
                    result.errors += 1
                    error_counts[validation.index] += 1
                    non_boolean = evaluation.detail.startswith(
                        "expression returned"
                    )
                    rule_id = (
                        "VAP013"
                        if non_boolean
                        else (
                            "VAP002"
                            if policy.failure_policy == "Ignore"
                            else "VAP003"
                        )
                    )
                    level = (
                        "ERROR"
                        if rule_id in {"VAP002", "VAP013"}
                        else "WARNING"
                    )
                    result.findings.append(
                        self._finding(
                            rule_id,
                            level,
                            f"CEL evaluation error ({policy.failure_policy}): "
                            f"{evaluation.detail}",
                            source=policy.source,
                            line=policy.line,
                            policy=policy.name,
                            binding=binding.name,
                            fixture=fixture.name,
                            evidence=validation.expression,
                        )
                    )
        result.matched += matched
        if matched == 0:
            result.findings.append(
                self._finding(
                    "VAP012",
                    "WARNING",
                    "policy binding was not exercised by any supplied fixture",
                    **base,
                    policy=policy.name,
                )
            )
        for validation in policy.validations:
            if (
                evaluations[validation.index] >= 2
                and denials[validation.index] == 0
                and error_counts[validation.index] == 0
            ):
                result.findings.append(
                    self._finding(
                        "VAP004",
                        "WARNING",
                        "validation allowed every evaluated fixture",
                        source=policy.source,
                        line=policy.line,
                        policy=policy.name,
                        binding=binding.name,
                        evidence=validation.expression,
                    )
                )


def analyze(
    policies: Iterable[Policy],
    bindings: Iterable[Binding],
    fixtures: Iterable[Fixture],
    params: Iterable[ParamObject] = (),
    engine: CelEngine | None = None,
) -> CheckResult:
    """Convenience wrapper around Analyzer.analyze."""
    return Analyzer(engine).analyze(policies, bindings, fixtures, params)


def rule_title(rule_id: str) -> str:
    """Return the stable human-readable title for a rule identifier."""
    return _RULE_TITLES.get(rule_id, "Unclassified policy defect")
