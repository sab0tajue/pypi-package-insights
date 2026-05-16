---
title: I scanned the top 100 PyPI packages — they have 1502 open vulnerabilities (789 HIGH severity)
published: true
description: Supply-chain audit of the most-downloaded Python packages. TensorFlow alone has 676 open advisories. Most-used libraries lack a declared license.
tags: python, security, opensource, devops
---

I built a small Apify Actor that joins **PyPI**, **pypistats.org**, **Google deps.dev**, and **OSV.dev** and rolls them into one row per package: download trends, dependency graph depth, release cadence, license, and **known vulnerabilities** with severity. Each package gets a transparent **Risk Score 0–100**.

Then I ran it across **101 of the most-downloaded Python packages**. Aggregate result:

- **1,502 open advisories** across the set
- **789** of them are **HIGH severity**
- Combined **51,110,969,391 downloads / month**
- **48 of 101** packages have no explicit `license` field declared in their PyPI metadata
- Median Risk Score across the set: **20 / 100**

Every Python project on the planet pulls a chunk of these into production. Below are the highlights.

---

## Most HIGH severity advisories (open)

| Package | Latest | HIGH | Open total | Risk |
|---|---|---:|---:|---:|
| tensorflow | 2.21.0 | **412** | 676 | 50 |
| Django | 6.0.5 | **96** | 275 | 60 |
| pillow | 12.2.0 | **59** | 118 | 60 |
| langchain | 1.3.1 | **28** | 37 | 50 |
| urllib3 | 2.7.0 | **16** | 30 | 70 |
| aiohttp | 3.13.5 | **16** | 41 | 50 |
| transformers | 5.8.1 | **15** | 27 | 55 |
| cryptography | 48.0.0 | **13** | 28 | 70 |
| Scrapy | 2.15.2 | **11** | 18 | 65 |
| pip | 26.1.1 | **9** | 18 | 60 |

A few are surprising. `pip` is everyone's bootstrap tool. `cryptography` is the one library you trust by name. Both ship with HIGH severity advisories that have not been resolved across all referenced versions.

---

## Most open advisories regardless of severity

| Package | Open advisories | Downloads / month |
|---|---:|---:|
| tensorflow | 676 | 22,248,213 |
| Django | 275 | 48,919,109 |
| pillow | 118 | 458,766,714 |
| aiohttp | 41 | 568,817,528 |
| langchain | 37 | 242,406,997 |
| urllib3 | 30 | 1,617,997,614 |
| cryptography | 28 | 1,183,622,768 |
| Twisted | 27 | 11,978,196 |
| transformers | 27 | 146,255,058 |
| pip | 18 | 663,706,472 |

Note: an "open advisory" does not mean every version is broken. Most advisories are pinned to specific affected version ranges. The number is a measure of historical attack surface, not current exploitability. Still, it is a useful signal of how heavily a package has been audited and how active its threat model is.

---

## Highest Risk Score (composite)

The Risk Score combines: open vulnerabilities, last-release age, license declared yes/no, source URL declared yes/no, total resolved transitive dependencies, and is dampened by very high download counts (many eyes assumption).

| Package | Risk | Why |
|---|---:|---|
| Jinja2 | **75** | 15 open vulns, last release 436d ago, no license field |
| urllib3 | **70** | 30 vulns (16 HIGH), no license field |
| numpy | **70** | 16 vulns (7 HIGH), no license field |
| cryptography | **70** | 28 vulns (13 HIGH), no license field |
| Scrapy | **65** | 18 vulns, 36 transitive deps |
| Django | **60** | 275 advisories total |
| pip | **60** | 18 vulns, no license field |
| pillow | **60** | 118 advisories |
| Flask | **60** | 8 vulns, 8 deps |

The "no license field" issue keeps popping up. **48 of 101 most-downloaded packages have no `license` field declared** in their PyPI metadata. This does not mean the projects are unlicensed — almost all of them have a `LICENSE` file in the repository — but it does mean automated scanners and SBOM generators may flag them as license-unknown, which causes real procurement headaches at large orgs.

---

## Stalest top packages

| Package | Last release | Open advisories |
|---|---:|---:|
| vine | 923 days ago | 0 |
| sniffio | 810 days ago | 0 |
| python-dateutil | 805 days ago | 0 |
| openpyxl | 686 days ago | 2 |
| webdriver-manager | 660 days ago | 0 |
| six | 527 days ago | 0 |
| Jinja2 | 436 days ago | 15 |
| rsa | 395 days ago | 6 |

`Jinja2` going 436 days without a release while sitting on 15 open advisories is the standout. Some of the others are stable-by-design (six, sniffio) and a long gap is fine.

---

## How to reproduce / run on your own list

I packaged the audit as an Apify Actor — paste your `requirements.txt`, get the analysis as a clean JSON dataset row per package.

[PyPI Package Insights on Apify Store](https://apify.com/kremkov-stanislav/pypi-package-insights)

Source code (MIT): [github.com/sab0tajue/pypi-package-insights](https://github.com/sab0tajue/pypi-package-insights). The Risk Score formula is in `src/insights.py`, around 80 lines, intentionally legible — re-weigh it for your threat model.

If you have a more interesting set of packages to score, drop a comment with the names and I will run it.

Related: I did the same exercise for [200 popular Python repositories on GitHub](https://dev.to/sab0tajue/i-analyzed-200-popular-python-repos-12-of-them-have-a-bus-factor-of-1-fastapi-whisper-3mnq) earlier.
