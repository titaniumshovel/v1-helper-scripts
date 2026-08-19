from __future__ import annotations
import pytest
from tests.conftest import FakeSession
from uet.swp_client import SwpClient, SwpApiError


def test_list_computers_pages_by_id():
    page1 = {"computers": [{"ID": 1, "hostName": "a"}, {"ID": 7, "hostName": "b"}]}
    page2 = {"computers": []}
    s = FakeSession([(200, page1), (200, page2)])
    c = SwpClient("https://swp", "sek", session=s, sleep=lambda _: None)
    out = c.list_computers()
    assert [x["ID"] for x in out] == [1, 7]
    # second request asks for IDs greater than 7
    body2 = s.calls[1][2]["json"]
    assert body2["searchCriteria"][0]["idValue"] == 7
    assert body2["searchCriteria"][0]["idTest"] == "greater-than"
    assert s.calls[0][2]["headers"]["api-secret-key"] == "sek"
    assert "expand=computerStatus" in s.calls[0][1]


def test_delete_computer():
    s = FakeSession([(204, {})])
    c = SwpClient("https://swp", "sek", session=s, sleep=lambda _: None)
    c.delete_computer(42)
    method, url, _ = s.calls[0]
    assert method == "DELETE" and url.endswith("/api/computers/42")


def test_generate_deployment_script():
    s = FakeSession([(200, {"scriptBody": "#!/bin/bash\nACTIVATIONURL='dsm://h:443/'"})])
    c = SwpClient("https://swp", "sek", session=s, sleep=lambda _: None)
    body = c.generate_deployment_script("linux")
    assert body.startswith("#!/bin/bash")
    assert s.calls[0][2]["json"]["platform"] == "linux"


def test_error_raises():
    s = FakeSession([(401, {"error": "bad key"})])
    c = SwpClient("https://swp", "sek", session=s, sleep=lambda _: None)
    with pytest.raises(SwpApiError):
        c.list_computers()
