# Global APT Threat Hunting

A KQL threat-hunting reference for Microsoft Sentinel & Defender XDR covering 50+
APT groups — plus a **daily automation** that turns fresh open-source intelligence
into candidate KQL detections and appends them to the playbook.

## Contents

- **[`Global-APT-Threat-Hunting/global-apt-threat-hunting-kql.md`](Global-APT-Threat-Hunting/global-apt-threat-hunting-kql.md)**
  — the hand-curated KQL hunting playbook (North Korea · China · Russia · Iran ·
  Middle East · others, MITRE ATT&CK v15).
- **Auto-Generated Daily Detections** — a section at the end of that playbook where
  the automation appends a dated block of new candidate queries each day.

## How the daily automation works

1. `hunt.py` fetches public threat-intel feeds (CISA advisories + KEV catalog,
   Unit 42, Talos, Microsoft, Google TAG/Mandiant, The DFIR Report, SANS ISC,
   Securelist) and filters to APT / nation-state / targeted-intrusion items.
2. Claude (as a detection engineer) writes **candidate KQL detections** grounded
   in and citing that reporting — each with an attributed actor, MITRE technique,
   target table, and tuning note.
3. The queries are structurally linted and **appended** to the playbook under
   `## 🤖 Auto-Generated Daily Detections`. The hand-curated content is never edited.

Runs daily via [`.github/workflows/daily-hunt.yml`](.github/workflows/daily-hunt.yml).

> ⚠️ **The auto-generated queries are CANDIDATES.** They are machine-written from
> open-source reporting and only structurally checked — not semantically validated.
> Review, tune, confirm table/column names against your schema, and test before
> deploying. For true validation, run them against a real Sentinel/Defender
> workspace (requires Azure credentials).

## Setup

Add an `ANTHROPIC_API_KEY` repository secret (Settings → Secrets and variables →
Actions). Optionally set a `CLAUDE_MODEL` Actions *variable* to override the default
(`claude-sonnet-5`).

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
python hunt.py            # generate + append today's detections
python hunt.py --dry-run  # fetch + filter only, no API call, no file change
```

---

*Disclaimer: automated aggregation of public reporting for research and defensive
purposes. All ATT&CK® references © MITRE Corporation. Verify against primary
sources before acting.*
