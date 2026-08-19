from __future__ import annotations
import pytest
from tests.conftest import FakeSession
from uet.v1_client import V1Client, V1ApiError


def test_pagination_follows_nextlink():
    s = FakeSession([
        (200, {"items": [{"endpointName": "a"}], "nextLink": "https://api/next?skip=1"}),
        (200, {"items": [{"endpointName": "b"}]}),
    ])
    c = V1Client("https://api", "tok", session=s, sleep=lambda _: None)
    out = c.list_endpoints()
    assert [e["endpointName"] for e in out] == ["a", "b"]
    assert s.calls[1][1] == "https://api/next?skip=1"
    assert s.calls[0][2]["headers"]["Authorization"] == "Bearer tok"


def test_retry_on_429_then_success():
    s = FakeSession([
        (429, {"error": "slow down"}),
        (200, {"items": []}),
    ])
    c = V1Client("https://api", "tok", session=s, sleep=lambda _: None)
    assert c.list_endpoints() == []
    assert len(s.calls) == 2


def test_hard_4xx_raises():
    s = FakeSession([(403, {"error": "nope"})])
    c = V1Client("https://api", "tok", session=s, sleep=lambda _: None)
    with pytest.raises(V1ApiError) as ei:
        c.list_endpoints()
    assert ei.value.status == 403
