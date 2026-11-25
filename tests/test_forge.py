"""Adversarial forge tests. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

from baysoz_admissioncel.forge import forge_fixtures

from .factories import make_policy


def test_forge_is_deterministic_and_bounded() -> None:
    policy = make_policy(
        expression="object.spec.containers.all(c, c.image.startsWith('reg/'))"
    )
    first = forge_fixtures((policy,), 64)
    second = forge_fixtures((policy,), 64)
    assert first == second
    assert 0 < len(first) <= 64
    names = [item.name for item in first]
    assert len(names) == len(set(names))


def test_forge_includes_null_type_confusion_unicode_and_updates() -> None:
    policy = make_policy(expression="object.spec.containers.all(c, true)")
    fixtures = forge_fixtures((policy,), 64)
    names = {item.name for item in fixtures}
    assert any("null-spec" in name for name in names)
    assert any("type-confusion" in name for name in names)
    assert any("unicode-name" in name for name in names)
    assert any(item.operation == "UPDATE" and item.old_object for item in fixtures)


def test_forge_respects_zero_limit() -> None:
    assert forge_fixtures((make_policy(),), 0) == ()
