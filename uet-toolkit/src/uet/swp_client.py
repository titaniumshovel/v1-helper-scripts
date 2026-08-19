from __future__ import annotations

import time

import requests

MAX_TRIES = 5
PAGE_SIZE = 1000


class SwpApiError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"SWP API error {status}: {body[:300]}")
        self.status = status


class SwpClient:
    def __init__(self, base_url: str, secret: str, session=None, sleep=time.sleep):
        self.base_url = base_url.rstrip("/")
        # Header per docs/api-notes.md (Task 0). Adjust there first if it differs.
        self.headers = {"api-secret-key": secret, "api-version": "v1"}
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
                raise SwpApiError(resp.status_code, resp.text)
            return resp
        raise SwpApiError(resp.status_code, resp.text)

    def list_computers(self) -> list[dict]:
        url = f"{self.base_url}/api/computers/search?expand=computerStatus"
        out: list[dict] = []
        last_id = 0
        while True:
            body = {
                "maxItems": PAGE_SIZE,
                "sortByObjectID": True,
                "searchCriteria": [
                    {"fieldName": "ID", "idValue": last_id, "idTest": "greater-than"}
                ],
            }
            resp = self._request("POST", url, json=body)
            computers = resp.json().get("computers", [])
            if not computers:
                return out
            out.extend(computers)
            last_id = computers[-1]["ID"]

    def get_computer(self, cid: int) -> dict:
        url = f"{self.base_url}/api/computers/{cid}?expand=computerStatus"
        return self._request("GET", url).json()

    def delete_computer(self, cid: int) -> None:
        self._request("DELETE", f"{self.base_url}/api/computers/{cid}")

    def generate_deployment_script(self, platform: str) -> str:
        body = {
            "platform": platform,
            "activationRequired": True,
            "validateCertificateRequired": True,
        }
        resp = self._request("POST", f"{self.base_url}/api/agentdeploymentscripts", json=body)
        return resp.json()["scriptBody"]
