#!/usr/bin/env python3
"""
Global APT Threat Hunting — daily OSINT aggregator + Claude analyst brief.

Pulls open-source threat intelligence (CISA advisories + KEV, MITRE ATT&CK,
vendor threat-intel RSS), filters to APT-relevant items from the last ~30 hours,
then asks Claude to synthesize an analyst-style brief. The result is written to
reports/YYYY-MM-DD.md and the README index is refreshed.

Environment:
  ANTHROPIC_API_KEY   required — the Claude API key
  CLAUDE_MODEL        optional — defaults to claude-opus-5
  LOOKBACK_HOURS      optional — defaults to 30
"""
from __future__ import annotations

import datetime as dt
import os
import re
import sys
from dataclasses import dataclass

import feedparser
import requests

UTC = dt.timezone.utc
LOOKBACK_HOURS = int(os.environ.get("LOOKBACK_HOURS", "30"))
MODEL = os.environ.get("CLAUDE_MODEL") or "claude-sonnet-5"
USER_AGENT = "Global-APT-Threat-Hunting/1.0 (+https://github.com/4p3Ir0n/Global-APT-Threat-Hunting)"
HTTP_TIMEOUT = 30

# --- Sources -----------------------------------------------------------------

# RSS/Atom feeds. Kept broad; APT-relevance filtering happens after fetch.
RSS_FEEDS: list[tuple[str, str]] = [
    ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("Unit 42 (Palo Alto)", "https://unit42.paloaltonetworks.com/feed/"),
    ("Cisco Talos", "https://blog.talosintelligence.com/rss/"),
    ("Microsoft Security", "https://www.microsoft.com/en-us/security/blog/feed/"),
    ("Google TAG / Mandiant", "https://cloud.google.com/blog/topics/threat-intelligence/rss/"),
    ("The DFIR Report", "https://thedfirreport.com/feed/"),
    ("SANS ISC Diary", "https://isc.sans.edu/rssfeed_full.xml"),
    ("Securelist (Kaspersky)", "https://securelist.com/feed/"),
]

# CISA Known Exploited Vulnerabilities catalog (JSON).
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Keywords that flag an item as likely APT / nation-state / targeted-intrusion
# relevant. Matched case-insensitively against title + summary.
APT_KEYWORDS = [
    "apt", "nation-state", "nation state", "state-sponsored", "state sponsored",
    "threat actor", "threat group", "espionage", "cyber-espionage", "cyberespionage",
    "targeted attack", "targeted intrusion", "advanced persistent",
    "lazarus", "kimsuky", "andariel", "bluenoroff",  # DPRK
    "apt28", "apt29", "fancy bear", "cozy bear", "sandworm", "turla", "gamaredon",  # RU
    "apt10", "apt41", "volt typhoon", "salt typhoon", "silk typhoon", "mustang panda",
    "storm-", "typhoon", "panda", "winnti",  # PRC clusters
    "apt33", "apt34", "apt35", "charming kitten", "muddywater", "oilrig",  # IR
    "sidewinder", "transparent tribe", "patchwork", "bitter",  # IN/PK region
    "unc", "ta4", "fin7", "fin8", "cl-sta", "earth ",
    "backdoor", "implant", "supply chain", "watering hole", "zero-day", "0-day",
    "living off the land", "lotl", "webshell", "cobalt strike",
]
KEYWORD_RE = re.compile("|".join(re.escape(k) for k in APT_KEYWORDS), re.IGNORECASE)


@dataclass
class Item:
    source: str
    title: str
    link: str
    published: dt.datetime | None
    summary: str

    def matches_apt(self) -> bool:
        blob = f"{self.title}\n{self.summary}"
        return bool(KEYWORD_RE.search(blob))


def _now() -> dt.datetime:
    return dt.datetime.now(tz=UTC)


def _entry_datetime(entry) -> dt.datetime | None:
    for attr in ("published_parsed", "updated_parsed"):
        val = getattr(entry, attr, None)
        if val:
            try:
                return dt.datetime(*val[:6], tzinfo=UTC)
            except (TypeError, ValueError):
                continue
    return None


def _clean(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text or "")  # strip HTML tags
    text = re.sub(r"\s+", " ", text).strip()
    return text


def fetch_rss(cutoff: dt.datetime) -> list[Item]:
    items: list[Item] = []
    for name, url in RSS_FEEDS:
        try:
            resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=HTTP_TIMEOUT)
            resp.raise_for_status()
            parsed = feedparser.parse(resp.content)
        except Exception as exc:  # noqa: BLE001 — one bad feed shouldn't kill the run
            print(f"[warn] {name}: failed to fetch/parse ({exc})", file=sys.stderr)
            continue

        for entry in parsed.entries:
            published = _entry_datetime(entry)
            # If a feed omits dates, keep the item (better a false include than a miss).
            if published is not None and published < cutoff:
                continue
            items.append(
                Item(
                    source=name,
                    title=_clean(getattr(entry, "title", "")),
                    link=getattr(entry, "link", ""),
                    published=published,
                    summary=_clean(getattr(entry, "summary", ""))[:1200],
                )
            )
    return items


def fetch_kev(cutoff: dt.datetime) -> list[Item]:
    """Recently ADDED entries to CISA's Known Exploited Vulnerabilities catalog."""
    try:
        resp = requests.get(CISA_KEV_URL, headers={"User-Agent": USER_AGENT}, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        print(f"[warn] CISA KEV: failed to fetch ({exc})", file=sys.stderr)
        return []

    cutoff_date = cutoff.date()
    items: list[Item] = []
    for vuln in data.get("vulnerabilities", []):
        date_added = vuln.get("dateAdded", "")
        try:
            added = dt.date.fromisoformat(date_added)
        except ValueError:
            continue
        if added < cutoff_date:
            continue
        cve = vuln.get("cveID", "")
        name = vuln.get("vulnerabilityName", "")
        vendor = vuln.get("vendorProject", "")
        product = vuln.get("product", "")
        ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")
        items.append(
            Item(
                source="CISA KEV",
                title=f"{cve} — {vendor} {product}: {name}",
                link=f"https://nvd.nist.gov/vuln/detail/{cve}",
                published=dt.datetime.combine(added, dt.time(), tzinfo=UTC),
                summary=(
                    f"{_clean(vuln.get('shortDescription', ''))} "
                    f"[Ransomware use: {ransomware}] "
                    f"Required action: {_clean(vuln.get('requiredAction', ''))}"
                )[:1200],
            )
        )
    return items


def build_context(items: list[Item]) -> str:
    lines: list[str] = []
    for i, it in enumerate(items, 1):
        when = it.published.strftime("%Y-%m-%d") if it.published else "date-unknown"
        lines.append(
            f"[{i}] ({it.source}, {when}) {it.title}\n"
            f"    {it.summary}\n"
            f"    URL: {it.link}"
        )
    return "\n".join(lines)


SYSTEM_PROMPT = """You are a senior cyber threat intelligence analyst specializing in \
Advanced Persistent Threats (APTs) and nation-state / targeted-intrusion activity. \
You produce a concise, sourced daily threat-hunting brief from open-source reporting.

Rules:
- Ground every claim in the provided source items; cite them inline as [n] using the \
item numbers given. Never invent CVEs, group names, or facts not present in the sources.
- Prioritize genuine APT / nation-state / targeted-intrusion and actively-exploited \
vulnerability items. De-emphasize generic commodity crime unless it ties to an APT.
- Be precise and skimmable. An analyst should be able to triage in two minutes.
- If the sources contain little APT-relevant material, say so plainly rather than padding."""

USER_TEMPLATE = """Today is {date}. Below are {count} open-source threat-intel items \
collected in the last {hours} hours. Produce a Markdown threat-hunting brief with these sections:

## Executive Summary
3-6 bullets on the day's most significant APT / targeted-intrusion developments.

## Notable Threat Activity
Per relevant item or cluster: what happened, attributed actor (if any), targeting, \
and why it matters. Cite sources as [n].

## Actively Exploited Vulnerabilities
CVEs under active exploitation (especially CISA KEV additions). Include affected \
products and recommended action. Cite sources as [n].

## Hunting Guidance
Concrete, defensively-useful hunt ideas derived from the reporting — TTPs to look for, \
IOCs/indicators mentioned, log sources to check, and detection angles. Keep it actionable.

## Sources
Numbered list of every item you cited, as `[n] Title — URL`.

Do not include a title heading (it is added automatically). Source items:

{context}"""


def summarize(items: list[Item], today: dt.date) -> str:
    import anthropic  # imported here so --dry-run works without the SDK/key

    client = anthropic.Anthropic()
    context = build_context(items)
    user = USER_TEMPLATE.format(
        date=today.isoformat(),
        count=len(items),
        hours=LOOKBACK_HOURS,
        context=context,
    )
    resp = client.messages.create(
        model=MODEL,
        max_tokens=16000,
        thinking={"type": "adaptive"},
        output_config={"effort": "high"},
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user}],
    )
    if resp.stop_reason == "refusal":
        raise RuntimeError(f"Model refused: {getattr(resp, 'stop_details', None)}")
    return "".join(b.text for b in resp.content if b.type == "text").strip()


def write_report(body: str, items: list[Item], today: dt.date) -> str:
    os.makedirs("reports", exist_ok=True)
    path = os.path.join("reports", f"{today.isoformat()}.md")
    generated = _now().strftime("%Y-%m-%d %H:%M UTC")
    header = (
        f"# Global APT Threat-Hunting Brief — {today.isoformat()}\n\n"
        f"*Generated {generated} · {len(items)} source items · model `{MODEL}`*\n\n"
        f"> Automated open-source intelligence digest. Verify before operational use.\n\n"
        f"---\n\n"
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(header + body + "\n")
    print(f"[ok] wrote {path}")
    return path


def refresh_readme() -> None:
    reports = sorted(
        (f for f in os.listdir("reports") if re.fullmatch(r"\d{4}-\d{2}-\d{2}\.md", f)),
        reverse=True,
    ) if os.path.isdir("reports") else []
    index = "\n".join(f"- [{f[:-3]}](reports/{f})" for f in reports[:60])
    latest = f"reports/{reports[0]}" if reports else "—"

    readme = f"""# Global APT Threat Hunting

Automated daily open-source intelligence (OSINT) digest focused on **Advanced
Persistent Threats**, nation-state activity, targeted intrusions, and actively
exploited vulnerabilities.

Each day a GitHub Actions workflow aggregates public threat-intel feeds
(CISA advisories + KEV, vendor research blogs, SANS ISC), filters for
APT-relevant items, and has Claude synthesize an analyst-style hunting brief.

**Latest brief:** {latest}

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

{index if index else "_No reports yet._"}

---

*Disclaimer: this is an automated aggregation of public reporting for research and
defensive purposes. Content may be incomplete or inaccurate — verify against
primary sources before acting.*
"""
    with open("README.md", "w", encoding="utf-8") as fh:
        fh.write(readme)
    print("[ok] refreshed README.md")


def main() -> int:
    dry_run = "--dry-run" in sys.argv
    today = _now().date()
    cutoff = _now() - dt.timedelta(hours=LOOKBACK_HOURS)

    print(f"[info] collecting OSINT since {cutoff.isoformat()} (lookback {LOOKBACK_HOURS}h)")
    raw = fetch_rss(cutoff) + fetch_kev(cutoff)
    print(f"[info] {len(raw)} items in window")

    # KEV additions are always in-scope; RSS items must match APT keywords.
    relevant = [it for it in raw if it.source == "CISA KEV" or it.matches_apt()]
    # De-dupe by (title, link).
    seen: set[tuple[str, str]] = set()
    items: list[Item] = []
    for it in relevant:
        key = (it.title.lower(), it.link)
        if key in seen:
            continue
        seen.add(key)
        items.append(it)
    items.sort(key=lambda x: x.published or _now(), reverse=True)
    print(f"[info] {len(items)} APT-relevant items after filtering + de-dupe")

    if dry_run:
        for it in items:
            when = it.published.date().isoformat() if it.published else "?"
            print(f"  - ({it.source}, {when}) {it.title}")
        return 0

    if not items:
        # Still produce a brief noting the quiet day, so the archive is continuous.
        body = (
            "## Executive Summary\n\n"
            "- No APT-relevant open-source items were identified in the collection "
            f"window (last {LOOKBACK_HOURS} hours). This may reflect a genuinely quiet "
            "period, feed outages, or filtering thresholds.\n\n"
            "## Hunting Guidance\n\n"
            "- Continue baseline hunts for living-off-the-land activity, anomalous "
            "authentication, and newly published CISA KEV entries.\n"
        )
    else:
        body = summarize(items, today)

    write_report(body, items, today)
    refresh_readme()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
