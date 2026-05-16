# PyPI Package Insights

> Bulk supply-chain analytics for Python packages. Download trends, version cadence, dependency depth, license, **known vulnerabilities (OSV)**, and a transparent **Risk Score 0–100**.

**Source code:** [github.com/sab0tajue/pypi-package-insights](https://github.com/sab0tajue/pypi-package-insights) (MIT)

## Why

Most package "insight" tools tell you stars and downloads. Real supply-chain decisions need more:

- Are there **open CVEs** for this version?
- How many **transitive dependencies** does it pull in?
- Is the project **still alive** (last release age, release cadence)?
- Does it have a **license**, a **homepage**, an **owner**?

This Actor pulls all of that from four authoritative sources in one call:

| Source | What it gives us |
|---|---|
| **pypi.org JSON API** | metadata, versions, declared dependencies |
| **pypistats.org** | download counts (day, week, month, year) |
| **deps.dev** (Google) | resolved dependency graph (transitive count) |
| **osv.dev** (Google + GitHub) | known vulnerabilities cross-referenced from PyPA, GHSA, NVD |

## Two modes

**List** — provide a fixed list of package names. Best for analysing your `requirements.txt` or a known set.

**Search** — substring search against the full PyPI index. Best for discovery (`"http client"`, `"async orm"`, `"agent framework"`).

## Output (one row per package)

```json
{
  "name": "requests",
  "latest_version": "2.34.2",
  "license": "Apache-2.0",
  "summary": "Python HTTP for Humans.",
  "pypi_url": "https://pypi.org/project/requests/",
  "source_url": "https://github.com/psf/requests",

  "downloads_last_day": 57961455,
  "downloads_last_week": 381134148,
  "downloads_last_month": 1537826508,

  "release_count": 161,
  "release_cadence": {
    "first_release_at": "2011-02-14T...",
    "last_release_at":  "2026-04-...",
    "last_release_age_days": 21,
    "avg_days_between_releases": 31.4
  },

  "open_vulnerabilities": 13,
  "high_severity_vulnerabilities": 4,
  "vulnerabilities": {
    "advisories": [
      {"id": "GHSA-652x-xj99-gmcc", "severity": "HIGH", "summary": "..."}
    ]
  },

  "dependencies": {
    "direct_dependencies_declared": 6,
    "total_resolved_dependencies": 12,
    "direct_dependencies": ["charset-normalizer<4,>=2", "idna<4,>=2.5", "..."]
  },

  "risk_score": 35
}
```

## Risk Score formula (0–100, higher = riskier)

Components:

- **+25** any open HIGH severity advisory
- **+5 each** other open advisory (cap **+25**)
- **+15** last release > 365 days ago
- **+10** last release 180–365 days ago
- **+10** no license declared
- **+10** no source/homepage URL
- **+10** total resolved deps > 50
- **+5** total deps 25–50
- **−10** > 1M downloads/month (heavily scrutinized)
- **−5**  > 100k downloads/month

The full formula is one file: `src/insights.py`. Re-weigh it for your threat model.

## Common use cases

- **Security teams** — bulk-score every package in `requirements.txt`, surface the riskiest ones.
- **DevOps** — block packages with HIGH severity advisories from CI by score threshold.
- **Procurement / OSPO** — vet OSS packages before approving for the org.
- **Founders / VCs** — gauge OSS health for due diligence on Python startups.

## Cost & scaling

Each package costs roughly 4 API calls (PyPI, pypistats, deps.dev, OSV). Toggle off `includeDownloads`, `includeVulnerabilities`, or `includeDependencies` to save calls.
