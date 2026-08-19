from __future__ import annotations

import time

import requests

MAX_TRIES = 5


class V1ApiError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"V1 API error {status}: {body[:300]}")
        self.status = status


class V1Client:
    def __init__(self, base_url: str, token: str, session=None, sleep=time.sleep):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"}
        self.session = session or requests.Session()
        self.sleep = sleep

    def _request(self, method: str, url: str, **kwargs):
        for attempt in range(MAX_TRIES):
            resp = self.session.request(
                method, url, headers=self.headers, timeout=60, **kwargs
            )
            if resp.status_code in (429, 500, 502, 503, 504):
                self.sleep(min(2 ** attempt, 30))
                continue
            if resp.status_code >= 400:
                raise V1ApiError(resp.status_code, resp.text)
            return resp
        raise V1ApiError(resp.status_code, resp.text)

    def list_endpoints(self) -> list[dict]:
        url = f"{self.base_url}/v3.0/endpointSecurity/endpoints"
        params: dict | None = {"top": 200}
        items: list[dict] = []
        while url:
            resp = self._request("GET", url, params=params)
            data = resp.json()
            items.extend(data.get("items", []))
            url = data.get("nextLink") or ""
            params = None  # nextLink already carries query params
        return items
