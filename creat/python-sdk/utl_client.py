"""Minimal Python SDK for the UTL HTTP gateway.

Usage::

    from utl_client import UtlHttpClient

    client = UtlHttpClient()  # uses UTL_HTTP_BASE or http://127.0.0.1:8080
    health = client.health()
    print(health)

This SDK expects the HTTP gateway (utl_http) to be running in front of utld.
You must install the 'requests' library yourself::

    pip install requests
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests


@dataclass
class HealthResponse:
    status: str


@dataclass
class RootsResponse:
    root_ids: List[int]


@dataclass
class DigSummaryResponse:
    root_id: int
    file_id: int
    merkle_root: str
    record_count: int


@dataclass
class EntropyResponse:
    root_id: int
    bin_id: int
    local_entropy: float


class UtlHttpClient:
    """HTTP client for UTL gateway.

    :param base_url: Override base URL (default from UTL_HTTP_BASE or http://127.0.0.1:8080).
    """

    def __init__(self, base_url: Optional[str] = None) -> None:
        self.base_url = base_url or os.environ.get("UTL_HTTP_BASE", "http://127.0.0.1:8080")
        self._token = os.environ.get("UTL_HTTP_TOKEN")

    def _request(self, method: str, path: str, json: Optional[Dict[str, Any]] = None) -> Any:
        url = self.base_url.rstrip("/") + path
        headers: Dict[str, str] = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        resp = requests.request(method, url, json=json, headers=headers)
        try:
            data = resp.json()
        except ValueError:
            data = resp.text
        if not resp.ok:
            raise RuntimeError(f"{method} {path} failed: {resp.status_code} {data}")
        return data

    # --- High-level methods -------------------------------------------------

    def health(self) -> HealthResponse:
        data = self._request("GET", "/health")
        return HealthResponse(status=data["status"])

    def list_roots(self) -> RootsResponse:
        data = self._request("GET", "/roots")
        return RootsResponse(root_ids=list(map(int, data.get("root_ids", []))))

    def register_root(
        self,
        root_id: int,
        root_hash: str,
        tx_hook: Optional[int] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> None:
        body = {
            "root_id": int(root_id),
            "root_hash": root_hash,
            "tx_hook": int(tx_hook) if tx_hook is not None else None,
            "params": params or {},
        }
        self._request("POST", "/roots", json=body)

    def record_transition(
        self,
        *,
        entity_id: int,
        root_id: int,
        signature: str,
        data: str,
        addr_heap_hash: str,
        hook_hash: str,
        logic_ref: str,
        wall: str,
        params: Optional[Dict[str, str]] = None,
    ) -> None:
        body = {
            "entity_id": int(entity_id),
            "root_id": int(root_id),
            "signature": signature,
            "data": data,
            "addr_heap_hash": addr_heap_hash,
            "hook_hash": hook_hash,
            "logic_ref": logic_ref,
            "wall": wall,
            "params": params or {},
        }
        self._request("POST", "/transitions", json=body)

    def build_dig(self, *, root_id: int, file_id: int, time_start: int, time_end: int) -> DigSummaryResponse:
        body = {
            "root_id": int(root_id),
            "file_id": int(file_id),
            "time_start": int(time_start),
            "time_end": int(time_end),
        }
        data = self._request("POST", "/dig", json=body)
        return DigSummaryResponse(
            root_id=int(data["root_id"]),
            file_id=int(data["file_id"]),
            merkle_root=str(data["merkle_root"]),
            record_count=int(data["record_count"]),
        )

    def build_entropy(self, *, root_id: int, bin_id: int) -> EntropyResponse:
        body = {"root_id": int(root_id), "bin_id": int(bin_id)}
        data = self._request("POST", "/entropy", json=body)
        return EntropyResponse(
            root_id=int(data["root_id"]),
            bin_id=int(data["bin_id"]),
            local_entropy=float(data["local_entropy"]),
        )
