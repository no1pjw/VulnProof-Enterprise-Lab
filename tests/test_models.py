from vulnproof.models import Evidence


def test_evidence_digest_is_deterministic() -> None:
    first = Evidence.capture("test", "same", {"b": 2, "a": 1})
    second = Evidence.capture("test", "same", {"a": 1, "b": 2})

    assert first.sha256 == second.sha256
    assert len(first.sha256) == 64
