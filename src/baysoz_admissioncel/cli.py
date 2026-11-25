"""Command-line interface for the Baysöz Labs admission-policy oracle.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

from . import __author__, __version__
from .analyzer import analyze, rule_title
from .cel_engine import CelEngine
from .forge import forge_fixtures
from .loader import (
    LoadError,
    load_bindings,
    load_fixtures,
    load_param_objects,
    load_policies,
)
from .model import Fixture
from .report import render_json, render_sarif, render_text

_ATTRIBUTION = f"Baysöz Labs <baysozlabs@proton.me> | baysoz-admissioncel {__version__}"
_EPILOG = f"Built by {_ATTRIBUTION}. Offline, deterministic, no services required."


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="baysoz-admissioncel",
        description=(
            "Offline Kubernetes ValidatingAdmissionPolicy CEL conformance oracle "
            f"with adversarial fixture forging and SARIF gates. By {_ATTRIBUTION}."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__} | Baysöz Labs <baysozlabs@proton.me>",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser(
        "check",
        help="evaluate policies against adversarial fixtures",
        description=(
            "Compile and execute real CEL expressions against concrete "
            f"admission requests. By {_ATTRIBUTION}."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    check.add_argument("--policy", action="append", default=[], required=True)
    check.add_argument("--binding", action="append", default=[])
    check.add_argument("--fixtures", action="append", default=[])
    check.add_argument("--params", action="append", default=[])
    check.add_argument("--forge", action="store_true")
    check.add_argument("--max-fixtures", type=int, default=64)
    check.add_argument(
        "--format", choices=("text", "json", "sarif"), default="text"
    )
    check.add_argument("--output", default="")
    check.add_argument("--strict", action="store_true")
    check.set_defaults(handler=_handle_check)

    forge = subparsers.add_parser(
        "forge",
        help="emit bounded adversarial admission fixtures",
        description=f"Forge deterministic adversarial fixtures. By {_ATTRIBUTION}.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    forge.add_argument("--policy", action="append", default=[], required=True)
    forge.add_argument("--max-fixtures", type=int, default=32)
    forge.add_argument("--format", choices=("json", "yaml"), default="yaml")
    forge.set_defaults(handler=_handle_forge)

    rules = subparsers.add_parser(
        "rules",
        help="list stable rule identifiers and descriptions",
        description=f"Show the deterministic rule catalog. By {_ATTRIBUTION}.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    rules.set_defaults(handler=_handle_rules)
    return parser


def _fixture_payload(fixture: Fixture) -> dict[str, Any]:
    return {
        "apiVersion": "admission.baysozlabs.dev/v1",
        "kind": "AdmissionFixture",
        "metadata": {"name": fixture.name},
        "spec": {
            "apiVersion": fixture.api_version,
            "kind": fixture.kind,
            "operation": fixture.operation,
            "object": fixture.object,
            "oldObject": fixture.old_object,
            "namespaceLabels": fixture.namespace_labels,
        },
    }


def _handle_check(args: argparse.Namespace) -> int:
    policies = load_policies(args.policy)
    bindings = load_bindings(args.binding)
    params = load_param_objects(args.params)
    fixtures = list(load_fixtures(args.fixtures))
    if args.forge:
        fixtures.extend(forge_fixtures(policies, args.max_fixtures))
    result = analyze(policies, bindings, fixtures, params, CelEngine())
    if args.format == "sarif":
        rendered = render_sarif(result)
    elif args.format == "json":
        rendered = render_json(result)
    else:
        rendered = render_text(result)
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    failed = result.error_count > 0 or (
        args.strict and bool(result.findings)
    )
    return 1 if failed else 0


def _handle_forge(args: argparse.Namespace) -> int:
    policies = load_policies(args.policy)
    fixtures = forge_fixtures(policies, args.max_fixtures)
    documents = [_fixture_payload(item) for item in fixtures]
    if args.format == "json":
        payload = {
            "attribution": __author__,
            "tool": "baysoz-admissioncel",
            "version": __version__,
            "fixtures": documents,
        }
        sys.stdout.write(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)
            + "\n"
        )
    else:
        sys.stdout.write(
            "# Baysöz Labs <baysozlabs@proton.me>\n"
            + yaml.safe_dump_all(documents, sort_keys=True, allow_unicode=True)
        )
    return 0


def _handle_rules(_args: argparse.Namespace) -> int:
    rule_ids = (
        "VAP001",
        "VAP002",
        "VAP003",
        "VAP004",
        "VAP005",
        "VAP006",
        "VAP007",
        "VAP008",
        "VAP009",
        "VAP010",
        "VAP011",
        "VAP012",
        "VAP013",
        "VAP014",
        "VAP015",
        "VAP018",
        "VAP019",
        "VAP020",
        "VAP021",
        "VAP022",
    )
    sys.stdout.write(f"# {_ATTRIBUTION}\n")
    for rule_id in rule_ids:
        sys.stdout.write(f"{rule_id} {rule_title(rule_id)}\n")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return its process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except LoadError as exc:
        sys.stderr.write(f"error: {exc}\n{_ATTRIBUTION}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
