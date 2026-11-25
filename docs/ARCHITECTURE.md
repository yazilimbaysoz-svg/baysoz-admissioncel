# Architecture — baysoz-admissioncel

Baysöz Labs <baysozlabs@proton.me>

## 1. System boundary

`baysoz-admissioncel` is an offline CLI and importable library. It reads
YAML/JSON policy documents, bindings, parameter objects, and admission
fixtures from disk. It never contacts a Kubernetes API server and never
executes shell commands from policy content.

```
files -> loader -> model -> selector -> cel_engine -> analyzer -> report
                                 ^             |
                                 |             v
                              forge ------- fixtures
```

## 2. Components

- `loader.py` — safe multi-document YAML parsing (`yaml.safe_load_all`),
  provenance tracking, and normalization into immutable dataclasses. It
  rejects non-mapping documents and missing required metadata.
- `model.py` — typed representations of `ValidatingAdmissionPolicy`,
  `ValidatingAdmissionPolicyBinding`, fixtures, parameter objects, findings,
  and execution statistics.
- `selector.py` — Kubernetes resource-rule and label-selector semantics:
  plural resource mapping (`Pod` -> `pods`), wildcard handling, scope,
  operations, resourceNames, and `matchPolicy: Equivalent` approximation.
- `cel_engine.py` — compiles and evaluates real CEL expressions using
  `cel-python`. It builds the standard admission activation (`object`,
  `oldObject`, `request`, `params`, `variables`), orders policy variables by
  dependency, detects cycles, and classifies evaluation errors.
- `forge.py` — deterministic, bounded fixture generation derived from the
  policy's own `object.*` field paths: nulls, type confusion, unicode names,
  and CREATE/UPDATE divergence.
- `analyzer.py` — evaluates every applicable policy/binding/fixture triple,
  emits stable rule IDs, and aggregates measurable counts.
- `report.py` — deterministic text, JSON, and SARIF 2.1.0 renderers.
- `cli.py` — `check`, `forge`, and `rules` subcommands with attribution in
  `--help` and `--version`.

## 3. Data flow

1. Load policies, bindings, parameters, and fixtures.
2. Optionally forge additional fixtures up to `--max-fixtures`.
3. For each policy, compile validations and validate the variable graph.
4. For each binding, resolve `paramRef` and enforce selector constraints.
5. For each fixture, evaluate applicability via `selector.is_applicable`.
6. For each validation, run the compiled CEL program against a concrete
   activation. Outcomes are `allow`, `deny`, or `error` — never guessed.
7. Convert observed defects into findings and render the requested format.

## 4. Evaluation fidelity and explicit limits

- CEL execution is genuine: expressions are compiled and evaluated by
  `cel-python` 0.5.0. Non-boolean results and runtime errors are reported
  from the evaluator.
- `cel-python` performs dynamic evaluation, not the full Kubernetes
  compile-time type check against OpenAPI schemas. The tool therefore
  reports runtime errors and type-confusion behavior; it does not claim to
  reproduce `kubectl` static type checking bit-for-bit.
- `matchPolicy: Equivalent` coverage is conservative: an aliased group is
  treated as potentially covered and reported as `VAP011` when no verified
  conversion path is supplied. This favors caution over false assurance.
- Fixture forging is bounded and deterministic; it cannot prove absence of
  all defects, but it finds a reproducible class of null/type/CREATE errors.
- Parameter objects are resolved from local documents only; cluster-side
  dynamic state is intentionally out of scope.

## 5. Exit semantics

- `0` — no ERROR findings (and, with `--strict`, no findings at all).
- `1` — at least one ERROR finding, or any finding under `--strict`.
- `2` — input/IO error.

## 6. Determinism guarantees

- Findings are deduplicated and sorted by source, line, rule ID, policy,
  binding, fixture, and message.
- JSON and SARIF use stable key ordering and UTF-8 output.
- Generated fixture names and request UIDs are derived from hashes of their
  inputs, not from clocks or randomness.

Baysöz Labs <baysozlabs@proton.me>
