# Changelog — baysoz-admissioncel

Baysöz Labs <baysozlabs@proton.me>

## 1.0.0 — 2026-11-25

- Initial release by Baysöz Labs <baysozlabs@proton.me>.
- Real CEL evaluation of `ValidatingAdmissionPolicy` validations and ordered
  variables using `cel-python`.
- Kubernetes resource-rule, scope, operation, and label-selector matching.
- Bounded deterministic adversarial fixture forge.
- 20 stable finding rules covering fail-open, fail-closed, dead policy,
  `oldObject` misuse, parameter drift, equivalent-group ambiguity, and
  message disclosure.
- Deterministic text, JSON, and SARIF 2.1.0 reporting.
- `check`, `forge`, and `rules` CLI commands with attributed help/version.
- Supreme Grand Jury verification: 5/5 unanimous PASS on live adversarial
  inputs; zero findings from pytest, ruff, and semgrep.

Baysöz Labs <baysozlabs@proton.me>
