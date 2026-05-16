"""Compute supply-chain insights from raw payloads.

Risk Score 0-100. Higher = more risky to depend on.
The formula is intentionally simple, transparent, and lives here so users
can re-weigh it for their own threat model.
"""
from __future__ import annotations

import datetime as dt
from typing import Any, Dict, List, Optional


def _parse_iso(value: Optional[str]) -> Optional[dt.datetime]:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _days_since(value: Optional[str]) -> Optional[int]:
    when = _parse_iso(value)
    if not when:
        return None
    return (dt.datetime.now(dt.timezone.utc) - when).days


def severity_from_osv(advisory: Dict[str, Any]) -> str:
    """Reduce CVSS string into HIGH/MEDIUM/LOW/UNKNOWN."""
    sev_list = advisory.get("severity") or []
    for entry in sev_list:
        score = entry.get("score") or ""
        # CVSS v3: e.g. "CVSS:3.1/.../H/H/H" — parse base score keyword
        if isinstance(score, (int, float)):
            n = float(score)
        elif "/" in score:
            # Try to find a base score in the database_specific
            db = advisory.get("database_specific") or {}
            n = db.get("cvss_score")
            if not n:
                # Heuristic: if vector includes ":H/" markers
                ups = score.upper()
                if "C:H" in ups or "I:H" in ups or "A:H" in ups:
                    n = 7.5
                elif "C:M" in ups or "I:M" in ups or "A:M" in ups:
                    n = 5
                else:
                    n = 3
        else:
            try:
                n = float(score)
            except Exception:
                n = None
        if n is not None:
            if n >= 7.0:
                return "HIGH"
            if n >= 4.0:
                return "MEDIUM"
            return "LOW"
    db = advisory.get("database_specific") or {}
    if db.get("severity"):
        return str(db["severity"]).upper()
    return "UNKNOWN"


def vulnerability_summary(
    vulns: Optional[List[Dict[str, Any]]],
) -> Dict[str, Any]:
    if not vulns:
        return {
            "total_vulnerabilities": 0,
            "open_vulnerabilities": 0,
            "high_severity_count": 0,
            "advisories": [],
        }
    out: List[Dict[str, Any]] = []
    high = 0
    open_count = 0
    for v in vulns:
        sev = severity_from_osv(v)
        if sev == "HIGH":
            high += 1
        # OSV uses 'withdrawn' to indicate withdrawn advisories
        if not v.get("withdrawn"):
            open_count += 1
        out.append({
            "id": v.get("id"),
            "summary": (v.get("summary") or "")[:200],
            "severity": sev,
            "published": v.get("published"),
            "modified": v.get("modified"),
            "withdrawn": bool(v.get("withdrawn")),
            "aliases": v.get("aliases") or [],
            "url": (v.get("references") or [{}])[0].get("url") if v.get("references") else None,
        })
    return {
        "total_vulnerabilities": len(vulns),
        "open_vulnerabilities": open_count,
        "high_severity_count": high,
        "advisories": out[:20],  # cap to keep records sane
    }


def release_cadence(releases: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """`releases` is the `releases` field of pypi/<pkg>/json — keys are
    versions, values are list of distribution files with upload_time."""
    if not releases:
        return {
            "release_count": 0,
            "first_release_at": None,
            "last_release_at": None,
            "last_release_age_days": None,
            "avg_days_between_releases": None,
        }
    times: List[dt.datetime] = []
    for files in releases.values():
        for f in files or []:
            t = _parse_iso(f.get("upload_time_iso_8601") or f.get("upload_time"))
            if t:
                times.append(t)
                break  # one date per version is enough
    times.sort()
    if not times:
        return {
            "release_count": len(releases),
            "first_release_at": None,
            "last_release_at": None,
            "last_release_age_days": None,
            "avg_days_between_releases": None,
        }
    avg_gap = None
    if len(times) >= 2:
        gaps = [(times[i + 1] - times[i]).days for i in range(len(times) - 1)]
        if gaps:
            avg_gap = round(sum(gaps) / len(gaps), 1)
    last_age = (dt.datetime.now(dt.timezone.utc) - times[-1]).days
    return {
        "release_count": len(times),
        "first_release_at": times[0].isoformat(),
        "last_release_at": times[-1].isoformat(),
        "last_release_age_days": last_age,
        "avg_days_between_releases": avg_gap,
    }


def dependency_summary(
    direct: Optional[List[str]],
    deps_dev_resp: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """`direct` = `requires_dist` raw strings from PyPI.
    `deps_dev_resp` = response from deps.dev :dependencies endpoint —
    contains a flat `nodes` list of all transitive deps."""
    direct_count = len(direct or [])
    transitive_count = 0
    if deps_dev_resp:
        nodes = deps_dev_resp.get("nodes") or []
        # First node is the package itself; everything else is a dep.
        transitive_count = max(len(nodes) - 1, 0)
    return {
        "direct_dependencies_declared": direct_count,
        "total_resolved_dependencies": transitive_count,
        "direct_dependencies": list(direct or [])[:30],
    }


def downloads_summary(
    recent: Optional[Dict[str, Any]],
    overall: Optional[List[Dict[str, Any]]],
) -> Dict[str, Any]:
    out = {
        "downloads_last_day": None,
        "downloads_last_week": None,
        "downloads_last_month": None,
        "downloads_last_year": None,
        "downloads_alltime": None,
    }
    if recent:
        out["downloads_last_day"] = recent.get("last_day")
        out["downloads_last_week"] = recent.get("last_week")
        out["downloads_last_month"] = recent.get("last_month")
    if overall:
        # 'with_mirrors' rows include all mirrors; sum monthly by date back
        by_date = {}
        for row in overall:
            if row.get("category") in ("with_mirrors", "without_mirrors"):
                by_date[row["date"]] = by_date.get(row["date"], 0) + (row.get("downloads") or 0)
        if by_date:
            sorted_dates = sorted(by_date.keys(), reverse=True)
            # last 365 entries (pypistats overall is monthly, so this is "all time" within their window)
            year_cut = sorted_dates[: min(12, len(sorted_dates))]
            out["downloads_last_year"] = sum(by_date[d] for d in year_cut)
            out["downloads_alltime"] = sum(by_date.values())
    return out


def risk_score(
    info: Dict[str, Any],
    cadence: Dict[str, Any],
    vulns: Dict[str, Any],
    deps: Dict[str, Any],
    downloads: Dict[str, Any],
) -> int:
    """0-100, higher = more risky.

    Components (max 100):
        +25  if any open HIGH severity advisory
        +10  per additional open advisory (cap +25)
        +15  if last release > 365 days ago
        +10  if last release 180-365 days ago
        +10  if no license declared
        +10  if no homepage / source URL
        +10  if total resolved dependencies > 50
        +5   if 25-50
        -10  if downloads_last_month > 1,000,000  (heavily used = scrutinized)
        -5   if 100,000-1,000,000
    Anything else: starts at base 10.
    """
    score = 10.0

    if vulns.get("high_severity_count", 0) > 0:
        score += 25
    extra = max(0, vulns.get("open_vulnerabilities", 0) - vulns.get("high_severity_count", 0))
    score += min(extra * 5, 25)

    age = cadence.get("last_release_age_days")
    if age is not None:
        if age > 365:
            score += 15
        elif age > 180:
            score += 10

    if not info.get("license"):
        score += 10

    has_url = bool(
        info.get("home_page")
        or (info.get("project_urls") or {}).get("Source")
        or (info.get("project_urls") or {}).get("Homepage")
        or (info.get("project_urls") or {}).get("Repository")
    )
    if not has_url:
        score += 10

    total_deps = deps.get("total_resolved_dependencies", 0)
    if total_deps > 50:
        score += 10
    elif total_deps > 25:
        score += 5

    monthly = downloads.get("downloads_last_month") or 0
    if monthly > 1_000_000:
        score -= 10
    elif monthly > 100_000:
        score -= 5

    return max(0, min(100, int(round(score))))


def assemble(
    name: str,
    pypi_data: Dict[str, Any],
    pypistats_recent: Optional[Dict[str, Any]],
    pypistats_overall: Optional[List[Dict[str, Any]]],
    osv_vulns: Optional[List[Dict[str, Any]]],
    deps_dev_pkg: Optional[Dict[str, Any]],
    deps_dev_dependencies: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    info = pypi_data.get("info") or {}
    releases = pypi_data.get("releases") or {}

    cadence = release_cadence(releases)
    vulns = vulnerability_summary(osv_vulns)
    deps = dependency_summary(info.get("requires_dist"), deps_dev_dependencies)
    downloads = downloads_summary(pypistats_recent, pypistats_overall)
    score = risk_score(info, cadence, vulns, deps, downloads)

    project_urls = info.get("project_urls") or {}
    return {
        "name": info.get("name") or name,
        "latest_version": info.get("version"),
        "summary": info.get("summary"),
        "description_short": (info.get("description") or "")[:500],
        "license": info.get("license"),
        "author": info.get("author"),
        "author_email": info.get("author_email"),
        "requires_python": info.get("requires_python"),
        "homepage": info.get("home_page") or project_urls.get("Homepage"),
        "source_url": project_urls.get("Source")
            or project_urls.get("Repository")
            or project_urls.get("Code"),
        "documentation_url": project_urls.get("Documentation"),
        "pypi_url": f"https://pypi.org/project/{info.get('name') or name}/",
        "classifiers_count": len(info.get("classifiers") or []),
        "yanked": info.get("yanked", False),
        "release_cadence": cadence,
        "release_count": cadence.get("release_count", 0),
        "downloads": downloads,
        "downloads_last_day": downloads.get("downloads_last_day"),
        "downloads_last_week": downloads.get("downloads_last_week"),
        "downloads_last_month": downloads.get("downloads_last_month"),
        "vulnerabilities": vulns,
        "open_vulnerabilities": vulns.get("open_vulnerabilities", 0),
        "high_severity_vulnerabilities": vulns.get("high_severity_count", 0),
        "dependencies": deps,
        "risk_score": score,
    }
