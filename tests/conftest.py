from __future__ import annotations


class FakeResp:
    def __init__(self, status: int, body: object):
        self.status_code = status
        self._body = body
        self.text = str(body)

    def json(self):
        return self._body


class FakeSession:
    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        status, body = self.script.pop(0)
        return FakeResp(status, body)
