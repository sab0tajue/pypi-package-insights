# Reddit posts for PyPI Package Insights

## r/Python

**Title:**

```
I scanned the top 100 PyPI packages — they have 1502 open advisories (789 HIGH severity)
```

**Type:** Text post.

**Body:**

```
Source code (MIT, Python): https://github.com/sab0tajue/pypi-package-insights
Write-up with the full table: <DEV.TO LINK once published>

I joined PyPI metadata, pypistats download counts, Google deps.dev (transitive
dependency graph), and OSV.dev (vulnerability advisories) into one row per
Python package, then ran it across 101 of the most-downloaded packages.

Aggregate:

- 1,502 open advisories across the set
- 789 of them HIGH severity
- 48 of 101 have no explicit `license` field on PyPI (LICENSE file usually
  present in the repo, but absent from package metadata)

Most HIGH severity advisories:

- tensorflow — 412 HIGH (676 total)
- Django — 96 HIGH
- pillow — 59 HIGH
- langchain — 28 HIGH
- urllib3 — 16 HIGH
- aiohttp — 16 HIGH
- cryptography — 13 HIGH
- pip — 9 HIGH

Highest composite Risk Score (open vulns + stale release + missing license +
transitive depth, minus eyes-on-it download dampening):

1. Jinja2 — 75 (15 vulns, last release 436d ago)
2. urllib3 — 70 (30 vulns, 16 HIGH)
3. numpy — 70 (16 vulns)
4. cryptography — 70 (28 vulns, 13 HIGH)

The Risk Score formula is in src/insights.py, ~80 lines. Re-weigh it for
your own threat model.

Curious to see riskiest packages from your `requirements.txt` — drop names
in the comments.
```

**Note:** "open advisory" ≠ exploitable in current version. OSV pins ranges.
This is a historical attack-surface signal, not a CVE-of-the-day list.

---

## r/devops

Same body, different title:

```
Top 100 PyPI packages have 1502 open advisories — supply chain audit results
```

DevOps audience cares about CI gating and SBOM generation; mention those use
cases in the first comment if it gets traction.

---

## r/cybersecurity

Same body, different title:

```
Open-source supply chain: 789 HIGH severity advisories across the 100 most-downloaded Python packages
```

This is the most native audience for the post. Highest chance of upvotes.

---

## r/coolgithubprojects

**Type:** Link.
**URL:** `https://github.com/sab0tajue/pypi-package-insights`
**Title:** `[Python] pypi-package-insights: bulk supply-chain risk score for any package`
