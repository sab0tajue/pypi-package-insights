"""Async HTTP clients for the four data sources we aggregate.

Sources:
    PyPI JSON API           — package metadata, releases, dependencies declared
    pypistats.org           — download counts (last day/week/month, time series)
    deps.dev                — version graph, transitive dependencies, hashes
    osv.dev                 — vulnerability advisories cross-referenced from
                              GitHub Advisories, PyPA, etc.

Each client wraps a single httpx.AsyncClient with retries and rate-limit
sensitive backoff. Every call returns *parsed JSON* or None on 404.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

import httpx

LOG = logging.getLogger(__name__)
USER_AGENT = "apify-pypi-package-insights/0.1"
DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0)


class _Base:
    """Common retry/backoff behaviour for all four clients."""

    def __init__(self, base_url: str, headers: Optional[Dict[str, str]] = None):
        merged = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if headers:
            merged.update(headers)
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers=merged,
            timeout=DEFAULT_TIMEOUT,
            follow_redirects=True,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _get(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        max_retries: int = 4,
    ) -> Optional[Any]:
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = await self._client.get(path, params=params)
            except httpx.HTTPError as e:
                if attempt > max_retries:
                    raise
                wait = min(2 ** attempt, 20)
                LOG.warning("Network error %s; retry in %ss (attempt %s)", e, wait, attempt)
                await asyncio.sleep(wait)
                continue

            if resp.status_code == 200:
                try:
                    return resp.json()
                except ValueError:
                    return None
            if resp.status_code == 404:
                return None
            if resp.status_code == 429 and attempt <= max_retries:
                retry_after = int(resp.headers.get("Retry-After", "5"))
                LOG.warning("Rate-limited; sleeping %ss", retry_after)
                await asyncio.sleep(retry_after)
                continue
            if resp.status_code in (500, 502, 503, 504) and attempt <= max_retries:
                wait = min(2 ** attempt, 20)
                LOG.warning("Server %s; retry in %ss", resp.status_code, wait)
                await asyncio.sleep(wait)
                continue
            resp.raise_for_status()
            return None

    async def _post(
        self,
        path: str,
        json_body: Dict[str, Any],
        max_retries: int = 4,
    ) -> Optional[Any]:
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = await self._client.post(path, json=json_body)
            except httpx.HTTPError as e:
                if attempt > max_retries:
                    raise
                wait = min(2 ** attempt, 20)
                await asyncio.sleep(wait)
                continue
            if resp.status_code == 200:
                try:
                    return resp.json()
                except ValueError:
                    return None
            if resp.status_code in (500, 502, 503, 504, 429) and attempt <= max_retries:
                await asyncio.sleep(min(2 ** attempt, 20))
                continue
            resp.raise_for_status()
            return None


class PyPIClient(_Base):
    """pypi.org JSON API for package metadata."""

    def __init__(self):
        super().__init__("https://pypi.org")

    async def get_package(self, name: str) -> Optional[Dict[str, Any]]:
        return await self._get(f"/pypi/{name}/json")

    async def search(self, query: str, limit: int = 50) -> List[str]:
        """PyPI dropped the official XML-RPC search a while back. We fall
        back to the JSON-based simple index search via libraries.io style.
        Since that requires a key, we instead use the free pypi.org
        'simple' index combined with substring filtering — fine for
        substring queries, fast enough for moderate result counts.
        """
        # No free official search endpoint; we use the read-only 'simple'
        # repository index which lists every package name. We cache the
        # full list once per process.
        if not hasattr(self, "_index"):
            try:
                resp = await self._client.get(
                    "/simple/", headers={"Accept": "application/vnd.pypi.simple.v1+json"}
                )
                if resp.status_code == 200:
                    j = resp.json()
                    self._index = [p["name"] for p in j.get("projects", [])]
                else:
                    self._index = []
            except Exception as e:
                LOG.warning("Failed to fetch simple index: %s", e)
                self._index = []
        q = query.lower().strip()
        if not q:
            return []
        matches = [n for n in self._index if q in n.lower()]
        # Prefer prefix matches first
        matches.sort(key=lambda n: (not n.lower().startswith(q), len(n)))
        return matches[:limit]


class PyPIStatsClient(_Base):
    """pypistats.org — community download counts derived from the BigQuery
    public dataset."""

    def __init__(self):
        super().__init__("https://pypistats.org")

    async def recent(self, name: str) -> Optional[Dict[str, Any]]:
        j = await self._get(f"/api/packages/{name}/recent")
        return (j or {}).get("data") if j else None

    async def overall(self, name: str) -> Optional[List[Dict[str, Any]]]:
        j = await self._get(f"/api/packages/{name}/overall")
        return (j or {}).get("data") if j else None


class DepsDevClient(_Base):
    """deps.dev — Google's dependency graph database."""

    def __init__(self):
        super().__init__("https://api.deps.dev")

    async def get_package(self, name: str) -> Optional[Dict[str, Any]]:
        return await self._get(f"/v3/systems/PYPI/packages/{name}")

    async def get_version(self, name: str, version: str) -> Optional[Dict[str, Any]]:
        return await self._get(f"/v3/systems/PYPI/packages/{name}/versions/{version}")

    async def get_dependencies(
        self, name: str, version: str
    ) -> Optional[Dict[str, Any]]:
        return await self._get(
            f"/v3/systems/PYPI/packages/{name}/versions/{version}:dependencies"
        )


class OSVClient(_Base):
    """osv.dev — Open Source Vulnerability database."""

    def __init__(self):
        super().__init__("https://api.osv.dev")

    async def query_package(self, name: str) -> Optional[List[Dict[str, Any]]]:
        j = await self._post(
            "/v1/query",
            {"package": {"name": name, "ecosystem": "PyPI"}},
        )
        return (j or {}).get("vulns") if j else None
