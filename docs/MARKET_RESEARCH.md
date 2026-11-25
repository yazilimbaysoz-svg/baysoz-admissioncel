# Market Research — baysoz-admissioncel

Baysöz Labs <baysozlabs@proton.me>

Research performed 2026-11-25 against the 32-repository Baysöz Labs catalogue
(`/home/runner/work/_temp/existing-repos.json`) and live GitHub search.

## 1. Live ecosystem evidence

`gh search repos` and `gh repo view` returned:

| Project | Stars | Relevance |
| --- | ---: | --- |
| `kubernetes/kubernetes` | 129,287 | Upstream admission APIs and CEL implementation |
| `cert-manager/cert-manager` | 14,174 | Actively migrating webhook validation to ValidatingAdmissionPolicy |
| `kubescape/kubescape` | 11,982 | Security platform requesting CEL rule-engine support |
| `appvia/krane` | 749 | RBAC static analysis — adjacent, not admission-expression semantics |
| `kubescape/cel-admission-library` | 86 | Curated VAP policies needing correctness verification |

`gh search issues` surfaced concrete, unsolved production pain:

- `cert-manager/cert-manager#7514` — "Replace some of the webhook
  functionality with `ValidatingAdmissionPolicy` & CEL".
- `kubernetes/kubernetes#131197` — CEL type checking fails with `all` macro
  and `notAComprehension`.
- `kubernetes/kubernetes#118230` — CEL validation rules do not expand
  Kubernetes-specific variables as expected.
- `kubescape/kubescape#2001` — "CEL rule engine support (evaluate
  ValidatingAdmissionPolicy rules alongside OPA/Rego)".
- `kubescape/kubescape#2002` — migration of Rego library controls to CEL.
- `kubescape/cel-admission-library#172` — AppArmor field test without
  annotation synthesis.
- `cilium/cilium#49828` — CRD schema `maxItems` mismatch, showing that
  declarative policy/schema drift remains a live class of cluster incidents.

The direction is unambiguous: platform teams are replacing admission
webhooks with declarative CEL policies, but they lack offline, CI-native
verification that those expressions actually behave as intended before the
policy is bound to a cluster.

## 2. Failure modes with real operational cost

1. **Fail-open errors.** With `failurePolicy: Ignore`, a mistyped field or
   missing key silently admits the very request the policy was written to
   stop. This is a security control failure with no runtime signal.
2. **Fail-closed availability incidents.** With `failurePolicy: Fail`, the
   same mistake blocks all matching workloads, including recovery paths.
3. **Dead policies.** A syntactically valid expression that never denies any
   realistic request gives a false sense of enforcement.
4. **Null `oldObject` on CREATE.** Expressions written for UPDATE crash on
   CREATE; the defect only appears when the first create reaches the API
   server.
5. **Parameter drift.** A binding can reference a `paramRef` that does not
   exist in the deployed namespace, converting a policy into a permanent
   evaluation error.
6. **Equivalent-group assumptions.** `matchPolicy: Equivalent` silently
   broadens coverage to aliased API groups; without conversion evidence the
   effective policy surface is unknown.
7. **Information disclosure in denials.** Interpolating `object.*` into a
   denial message can echo secrets or PII to end users and audit logs.
8. **Unbounded match constraints.** Wildcard resources without selectors can
   deny cluster-critical controllers.

## 3. Gap analysis against the existing Baysöz portfolio

The existing catalogue already covers Docker Compose readiness, SSRF
canonicalization, PostgreSQL DDL, trace propagation, GraphQL cost,
Alertmanager routing, CSP, MCP contracts, Python reachability, Kubernetes
disruption reachability, GraphQL authorization, NetworkPolicy reachability,
OpenTelemetry collector config, PromQL, Gateway API routes, JOSE confusion,
BOLA planning, GitHub Actions pinning, SLO burn rates, cardinality, Terraform
plan blast radius, and environment drift.

None of these tools compiles and executes **Kubernetes CEL admission
expressions** against adversarial request fixtures. `baysoz-otelgate` and
`baysoz-routegate` are static config linters; `baysoz-disruption-oracle` and
`baysoz-netpol-oracle` model Kubernetes scheduling/network behavior, not
admission-language semantics. `baysoz-actionlock` protects workflow
dependencies, not admission controls. A CEL admission oracle is therefore a
new capability, not a rebrand of an existing one.

Adjacent third-party work also stops short: `cel-admission-library` ships
policies rather than verifying bindings and parameters against concrete
requests; `krane` analyzes RBAC; Kubescape issues explicitly request CEL
evaluation alongside Rego. No offline CI gate in this landscape emits
deterministic SARIF from real CEL execution with forged adversarial requests.

## 4. Why this project is production-grade rather than a toy

- Uses a real CEL implementation (`cel-python` 0.5) rather than string
  matching or simulated results.
- Models the full admission activation: `object`, `oldObject`, `request`,
  `params`, and ordered `variables` with cycle detection.
- Implements Kubernetes `resourceRules` plural-resource matching, scope and
  operation filtering, `matchLabels`/`matchExpressions`, subresources, and
  conservative `matchPolicy: Equivalent` coverage analysis.
- Forges bounded, deterministic adversarial fixtures derived from the
  expression's own field paths (nulls, type confusion, unicode, UPDATE
  divergence) instead of relying on hand-written happy paths.
- Emits stable rule IDs and deterministic SARIF 2.1.0 suitable for GitHub
  code scanning and CI gating.
- Runs fully offline with no cluster, webhook server, database, or local LLM.

## 5. Technology choice

Python 3.13 with `uv` is selected because CEL execution is supplied by a
mature library and because deterministic YAML/SARIF tooling integrates
cleanly with existing CI. The project deliberately avoids service
dependencies and model inference: correctness must be reproducible from the
policy text and fixtures alone.

Baysöz Labs <baysozlabs@proton.me>
