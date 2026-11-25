# baysoz-admissioncel

[![ci](https://github.com/yazilimbaysoz-svg/baysoz-admissioncel/actions/workflows/ci.yml/badge.svg)](https://github.com/yazilimbaysoz-svg/baysoz-admissioncel/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.13%2B-blue)](https://www.python.org/downloads/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![sarif](https://img.shields.io/badge/output-SARIF%202.1.0-purple)](docs/ARCHITECTURE.md)

**Baysöz Labs <baysozlabs@proton.me>**

Offline Kubernetes `ValidatingAdmissionPolicy` CEL conformance oracle with
adversarial fixture forging and deterministic SARIF CI gates. It compiles and
executes real CEL expressions — no simulation, no cluster, no webhook server,
no heavy services, no local LLM.

## Why it exists

Platform teams are replacing admission webhooks with declarative CEL
policies. A typo can silently fail open (`failurePolicy: Ignore`), block every
workload (`failurePolicy: Fail`), or produce a policy that never denies
anything. This tool finds those defects before merge. See
[market research](docs/MARKET_RESEARCH.md) for live GitHub evidence.

## Install

```bash
git clone https://github.com/yazilimbaysoz-svg/baysoz-admissioncel.git
cd baysoz-admissioncel
uv venv
uv pip install -e .
```

Requires Python 3.13+. Runtime dependencies: `cel-python` and `PyYAML`.

## Architecture

```text
files -> loader -> model -> selector -> cel_engine -> analyzer -> report
                                 ^             |
                                 |             v
                              forge ------- fixtures
```

- `loader` — safe multi-document YAML normalization
- `selector` — Kubernetes resourceRules, scope, operations, label selectors
- `cel_engine` — real CEL compilation, activation, ordered variables
- `forge` — bounded null/type-confusion/unicode/UPDATE fixtures
- `analyzer` — 20 stable rule IDs and measurable outcomes
- `report` — text, JSON, and SARIF 2.1.0

Full design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Usage

```bash
baysoz-admissioncel check \
  --policy examples/policy.yaml \
  --binding examples/policy.yaml \
  --fixtures examples/fixtures.yaml \
  --params examples/params.yaml \
  --forge --max-fixtures 12
```

### Real CLI output

```text
$ baysoz-admissioncel --version
baysoz-admissioncel 1.0.0 | Baysöz Labs <baysozlabs@proton.me>

$ baysoz-admissioncel check --policy examples/policy.yaml \
    --binding examples/policy.yaml --fixtures examples/fixtures.yaml \
    --params examples/params.yaml --forge --max-fixtures 12
baysoz-admissioncel 1.0.0 | Baysöz Labs <baysozlabs@proton.me>
policies=1 bindings=1 fixtures=12 evaluations=24 matched=12
outcomes: allow=17 deny=1 error=6
findings: error=0 warning=4
[WARNING] VAP003 CEL evaluation error (Fail): variable 'privileged' evaluation failed: ("None with type: '<class 'NoneType'>' does not support field selection", <class 'TypeError'>, None) (examples/policy.yaml:2)
    policy=deny-privileged-workloads binding=deny-privileged-workloads-binding
    fixture=deny-privileged-workloads-r0-v1-Pod-CREATE-null-spec
    evidence=object.spec.containers.all(c, c.image.startsWith(params.allowedRegistry))
[WARNING] VAP003 CEL evaluation error (Fail): CEL evaluation error: ("StringType('all') with type: '<class 'celpy.celtypes.StringType'>' does not support field selection", <class 'TypeError'>, None) (examples/policy.yaml:2)
    policy=deny-privileged-workloads binding=deny-privileged-workloads-binding
    fixture=deny-privileged-workloads-r0-v1-Pod-CREATE-type-confusion-spec-containers-all
    evidence=object.spec.containers.all(c, c.image.startsWith(params.allowedRegistry))
[WARNING] VAP003 CEL evaluation error (Fail): variable 'privileged' evaluation failed: ("None with type: '<class 'NoneType'>' does not support field selection", <class 'TypeError'>, None) (examples/policy.yaml:2)
    policy=deny-privileged-workloads binding=deny-privileged-workloads-binding
    fixture=deny-privileged-workloads-r0-v1-Pod-UPDATE-null-spec
    evidence=object.spec.containers.all(c, c.image.startsWith(params.allowedRegistry))
[WARNING] VAP003 CEL evaluation error (Fail): CEL evaluation error: ("StringType('all') with type: '<class 'celpy.celtypes.StringType'>' does not support field selection", <class 'TypeError'>, None) (examples/policy.yaml:2)
    policy=deny-privileged-workloads binding=deny-privileged-workloads-binding
    fixture=deny-privileged-workloads-r0-v1-Pod-UPDATE-type-confusion-spec-containers-all
    evidence=object.spec.containers.all(c, c.image.startsWith(params.allowedRegistry))
```

CI gates:

```bash
baysoz-admissioncel check ... --format sarif --output admission.sarif
baysoz-admissioncel check ... --strict   # fail on any finding
baysoz-admissioncel rules                # stable rule catalog
baysoz-admissioncel forge --policy examples/policy.yaml --format json
```

Exit codes: `0` clean, `1` ERROR finding (or any finding with `--strict`),
`2` input/IO error.

## Detected defect classes

Fail-open evaluation errors, fail-closed evaluation errors, dead validations,
unbound policies, unresolved `paramRef`, `oldObject` on CREATE, denial-message
field disclosure, unbounded match constraints, unverified Equivalent group
aliases, non-boolean expressions, variable cycles, shadowed bindings,
duplicate names, and missing validations.

## Quality gates

```bash
uv venv && uv pip install -e . && uv pip install pytest
uv run pytest -q
ruff check --select E,F,W,S,B .
semgrep --config p/default --error .
```

## Documentation

- [Market research](docs/MARKET_RESEARCH.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Plan](PLAN.md)
- [Security](SECURITY.md)
- [Changelog](CHANGELOG.md)

Baysöz Labs <baysozlabs@proton.me>
