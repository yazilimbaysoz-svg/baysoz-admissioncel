# Security Policy — baysoz-admissioncel

Baysöz Labs <baysozlabs@proton.me>

## Scope

This tool analyzes Kubernetes admission policies offline. It is a defensive
CI gate and does not require cluster credentials.

## Threat model

- **Untrusted policy YAML** — parsed only with `yaml.safe_load_all`; no
  arbitrary tags, no object construction, no shell execution.
- **Hostile CEL expressions** — compiled and evaluated by `cel-python`, an
  in-process library with no I/O capability. Evaluation is bounded by the
  supplied fixtures and `--max-fixtures`.
- **Hostile fixtures** — treated strictly as data. Field paths and unicode
  payloads are never interpolated into shell commands.
- **Secret leakage** — the tool does not read environment secrets or cluster
  kubeconfigs. `VAP009` warns when denial metadata interpolates request
  object fields, which may echo sensitive data.
- **Supply chain** — dependencies are pinned by compatible ranges in
  `pyproject.toml` and installed through `uv` in CI.

## Non-goals

- No cluster mutation, webhook serving, or remote calls.
- No local LLM inference or model downloads.
- No storage of analyzed manifest contents outside the process.

## Reporting

Report security concerns to Baysöz Labs <baysozlabs@proton.me>. Include a
minimal reproducer and the stable rule ID, if applicable.

Baysöz Labs <baysozlabs@proton.me>
