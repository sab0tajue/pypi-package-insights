"""Apify Actor entry point for PyPI Package Insights."""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

from apify import Actor

from .clients import DepsDevClient, OSVClient, PyPIClient, PyPIStatsClient
from .insights import assemble

LOG = logging.getLogger("pypi-insights")


def _normalize_name(raw: str) -> str:
    s = (raw or "").strip().lower()
    if s.startswith("https://pypi.org/project/"):
        s = s[len("https://pypi.org/project/") :].strip("/")
    if s.startswith("pypi.org/project/"):
        s = s[len("pypi.org/project/") :].strip("/")
    # PyPI normalizes underscores to hyphens; we keep the original form for
    # display but use the input as is — pypi.org accepts both.
    return s


async def _process_one(
    name: str,
    *,
    pypi: PyPIClient,
    pypistats: PyPIStatsClient,
    deps_dev: DepsDevClient,
    osv: OSVClient,
    include_downloads: bool,
    include_vulnerabilities: bool,
    include_dependencies: bool,
) -> Optional[Dict[str, Any]]:
    pypi_data = await pypi.get_package(name)
    if not pypi_data:
        Actor.log.warning("Package %s not found on PyPI.", name)
        return None
    latest_version = (pypi_data.get("info") or {}).get("version")

    # Now run the optional sub-fetches concurrently.
    tasks = []
    keys: List[str] = []
    if include_downloads:
        tasks.append(pypistats.recent(name))
        keys.append("recent")
        tasks.append(pypistats.overall(name))
        keys.append("overall")
    if include_vulnerabilities:
        tasks.append(osv.query_package(name))
        keys.append("osv")
    if include_dependencies and latest_version:
        tasks.append(deps_dev.get_package(name))
        keys.append("dd_pkg")
        tasks.append(deps_dev.get_dependencies(name, latest_version))
        keys.append("dd_deps")

    bag: Dict[str, Any] = {}
    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for k, r in zip(keys, results):
            if isinstance(r, Exception):
                Actor.log.warning("[%s] sub-call %s failed: %s", name, k, r)
                bag[k] = None
            else:
                bag[k] = r

    return assemble(
        name=name,
        pypi_data=pypi_data,
        pypistats_recent=bag.get("recent"),
        pypistats_overall=bag.get("overall"),
        osv_vulns=bag.get("osv"),
        deps_dev_pkg=bag.get("dd_pkg"),
        deps_dev_dependencies=bag.get("dd_deps"),
    )


async def main() -> None:
    async with Actor:
        raw_input = await Actor.get_input() or {}
        Actor.log.info("Run input: %s", raw_input)

        mode = raw_input.get("mode", "list")
        max_results = int(raw_input.get("maxResults") or 25)
        include_downloads = bool(raw_input.get("includeDownloads", True))
        include_vulnerabilities = bool(raw_input.get("includeVulnerabilities", True))
        include_dependencies = bool(raw_input.get("includeDependencies", True))

        pypi = PyPIClient()
        pypistats = PyPIStatsClient()
        deps_dev = DepsDevClient()
        osv = OSVClient()

        try:
            if mode == "list":
                names = [_normalize_name(p) for p in (raw_input.get("packages") or [])]
                names = [n for n in names if n]
                if not names:
                    raise ValueError(
                        "Mode is 'list' but no packages were provided. "
                        "Add package names like 'requests', 'numpy' or paste pypi.org URLs."
                    )
                names = names[:max_results]
                Actor.log.info("List mode: %d packages.", len(names))
            else:  # search
                q = (raw_input.get("query") or "").strip()
                if not q:
                    raise ValueError(
                        "Mode is 'search' but no query was provided. "
                        "Set 'query' to a substring like 'http' or 'machine learning'."
                    )
                Actor.log.info("Search mode: query=%r", q)
                names = await pypi.search(q, limit=max_results)
                Actor.log.info("Search returned %d candidate packages.", len(names))

            sem = asyncio.Semaphore(8)
            pushed = 0
            errors = 0

            async def worker(pkg: str) -> None:
                nonlocal pushed, errors
                async with sem:
                    try:
                        record = await _process_one(
                            pkg,
                            pypi=pypi,
                            pypistats=pypistats,
                            deps_dev=deps_dev,
                            osv=osv,
                            include_downloads=include_downloads,
                            include_vulnerabilities=include_vulnerabilities,
                            include_dependencies=include_dependencies,
                        )
                    except Exception as e:  # noqa: BLE001
                        errors += 1
                        Actor.log.exception("Failed on %s: %s", pkg, e)
                        return
                    if record is None:
                        return
                    await Actor.push_data(record)
                    try:
                        await Actor.charge("package-analyzed")
                    except Exception:
                        pass
                    pushed += 1
                    if pushed % 5 == 0 or pushed == len(names):
                        Actor.log.info("Progress: %d/%d", pushed, len(names))

            await asyncio.gather(*(worker(n) for n in names))

            Actor.log.info(
                "Run finished. Pushed %d records, %d errors.", pushed, errors
            )

        finally:
            await asyncio.gather(
                pypi.aclose(),
                pypistats.aclose(),
                deps_dev.aclose(),
                osv.aclose(),
            )
