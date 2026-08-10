# Global APT Threat Hunting

Automated daily open-source intelligence (OSINT) digest focused on **Advanced
Persistent Threats**, nation-state activity, targeted intrusions, and actively
exploited vulnerabilities.

Each day a GitHub Actions workflow aggregates public threat-intel feeds
(CISA advisories + KEV, vendor research blogs, SANS ISC), filters for
APT-relevant items, and has Claude synthesize an analyst-style hunting brief.

**Latest brief:** reports/2026-08-10.md

## How it works

1. `hunt.py` fetches and filters OSINT feeds (see the source list in the script).
2. Relevant items are sent to the Claude API, which writes a sourced brief.
3. The brief is committed as `reports/YYYY-MM-DD.md` and this index is refreshed.

Runs daily via [`.github/workflows/daily-hunt.yml`](.github/workflows/daily-hunt.yml).

## Setup

Add an `ANTHROPIC_API_KEY` repository secret (Settings → Secrets and variables →
Actions). Optionally set a `CLAUDE_MODEL` variable to override the default.

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
python hunt.py            # generate today's brief
python hunt.py --dry-run  # fetch + filter only, no API call
```

## Report archive

- [2026-08-10](reports/2026-08-10.md)

---

*Disclaimer: this is an automated aggregation of public reporting for research and
defensive purposes. Content may be incomplete or inaccurate — verify against
primary sources before acting.*
