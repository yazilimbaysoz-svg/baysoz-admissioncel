"""Loader tests. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from pathlib import Path

import pytest

from baysoz_admissioncel.loader import (
    LoadError,
    load_bindings,
    load_fixtures,
    load_param_objects,
    load_policies,
)

POLICY = """\
# Baysöz Labs <baysozlabs@proton.me>
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: check-images
spec:
  failurePolicy: Fail
  paramKind:
    apiVersion: example.dev/v1
    kind: AdmissionPolicyParams
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
        scope: Namespaced
  variables:
    - name: trusted
      expression: "object.spec.containers.all(c, true)"
  validations:
    - expression: "variables.trusted"
      message: "untrusted workload"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: check-images-binding
spec:
  policyName: check-images
  paramRef:
    name: params
    namespace: default
"""


def test_load_policy_and_binding(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY, encoding="utf-8")
    policies = load_policies([path])
    bindings = load_bindings([path])
    assert len(policies) == 1
    assert policies[0].rules[0].resources == ("pods",)
    assert policies[0].variables == (
        ("trusted", "object.spec.containers.all(c, true)"),
    )
    assert policies[0].param_kind == "AdmissionPolicyParams"
    assert bindings[0].policy_name == "check-images"
    assert bindings[0].param_ref is not None
    assert bindings[0].param_ref["name"] == "params"


def test_load_fixtures_expands_list_and_raw_objects(tmp_path: Path) -> None:
    path = tmp_path / "fixtures.yaml"
    path.write_text(
        """\
# Baysöz Labs <baysozlabs@proton.me>
apiVersion: v1
kind: List
items:
  - apiVersion: admission.baysozlabs.dev/v1
    kind: AdmissionFixture
    metadata:
      name: explicit
    spec:
      apiVersion: v1
      kind: Pod
      operation: UPDATE
      object:
        metadata:
          name: pod
          namespace: default
      oldObject:
        metadata:
          name: pod
          namespace: default
  - apiVersion: v1
    kind: ConfigMap
    metadata:
      name: raw
      namespace: default
""",
        encoding="utf-8",
    )
    fixtures = load_fixtures([path])
    assert [item.name for item in fixtures] == ["explicit", "raw"]
    assert fixtures[0].operation == "UPDATE"
    assert fixtures[0].old_object is not None
    assert fixtures[1].operation == "CREATE"


def test_load_param_objects_ignores_policy_kinds(tmp_path: Path) -> None:
    path = tmp_path / "params.yaml"
    path.write_text(
        """\
# Baysöz Labs <baysozlabs@proton.me>
apiVersion: example.dev/v1
kind: AdmissionPolicyParams
metadata:
  name: params
  namespace: default
allowedRegistry: "registry.example.invalid/"
""",
        encoding="utf-8",
    )
    params = load_param_objects([path])
    assert len(params) == 1
    assert params[0].data["allowedRegistry"] == "registry.example.invalid/"


def test_invalid_yaml_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("kind: [unterminated\n", encoding="utf-8")
    with pytest.raises(LoadError):
        load_policies([path])


def test_missing_metadata_name_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(
        """\
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata: {}
spec: {}
""",
        encoding="utf-8",
    )
    with pytest.raises(LoadError):
        load_policies([path])
