<div align="center">

# Guard Security Suite

**A seven-skill security toolkit for Claude Code that audits any web project,
finds the holes, and closes them — in plain language, without breaking what works.**

[![License: CC BY-ND 4.0](https://img.shields.io/badge/License-CC%20BY--ND%204.0-lightgrey.svg)](LICENSE)
[![Author: ExcellentMaps](https://img.shields.io/badge/Author-ExcellentMaps-blue.svg)](https://github.com/ExcellentMaps)
[![Skills: 7](https://img.shields.io/badge/Skills-7-green.svg)](#the-seven-skills)

[Русская версия →](README.ru.md)

</div>

---

## What this is

Guard Security Suite is a set of [Agent Skills](https://docs.claude.com/en/docs/agents-and-tools/agent-skills)
for Claude Code. Install it once, then ask in plain words — *"audit my project"*,
*"what's not protected?"*, *"protect my CRM"* — and Claude runs a structured security
review, explains every finding in language a non-engineer understands, and implements
the fixes one at a time with a verification and a rollback for each.

Built for **CRM systems and business applications** — software holding customer records,
orders, phone numbers and staff accounts — but the skills are stack-agnostic and work on
any web project: PHP, Node, Python, Go, Ruby, .NET; PostgreSQL, MySQL, MongoDB;
nginx, Caddy, Apache, Cloudflare; VPS, Docker, managed cloud or shared hosting.

### Three things it does

| | |
|---|---|
| **1. Finds** | Twelve audit blocks over code, git history, database grants, live HTTP surface, dependencies and CRM-specific exposure. Read-only — the audit never changes anything. |
| **2. Explains** | Every finding gets four lines: what is open, what could happen because of it, what closes it, how long it takes. No jargon without a plain-language equivalent. |
| **3. Fixes** | One layer at a time, each with its own verification step and its own written rollback. Nothing is applied without showing the plan first. |

---

## Why "without breaking anything" is rule number one

Security work that takes a production site down is worse than no security work at all —
the owner rolls everything back and never tries again. Every change in this suite follows
the same loop:

```
INSPECT  →  BACK UP  →  CHANGE ONE THING  →  VERIFY  →  RECORD THE ROLLBACK
```

Measures that can lock the owner out of their own system — firewall rules, SSH hardening,
strict CSP, two-factor authentication — are scheduled **last**, and always with a second
terminal session open as a lifeline.

---

## Install

### Recommended — as a plugin

```
/plugin marketplace add ExcellentMaps/lunacy-studio-skills
/plugin install excellentmaps@lunacy-studio-skills
```

That is it. All seven skills are registered at once and stay updatable:

```
/plugin marketplace update lunacy-studio-skills
```

### Alternative — copy the skills by hand

Skills live in `~/.claude/skills/` (available in every project) or `.claude/skills/`
(one project only).

**macOS / Linux**

```bash
git clone https://github.com/ExcellentMaps/lunacy-studio-skills.git
mkdir -p ~/.claude/skills
cp -r lunacy-studio-skills/plugins/excellentmaps/skills/* ~/.claude/skills/
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/ExcellentMaps/lunacy-studio-skills.git
New-Item -ItemType Directory -Force $HOME\.claude\skills | Out-Null
Copy-Item -Recurse lunacy-studio-skills\plugins\excellentmaps\skills\* $HOME\.claude\skills\
```

### Verify

Restart Claude Code, then verify:

```
/skills
```

Seven entries beginning with `security-guard` and `guard-` should be listed.

---

## Use

You never name a skill. You describe what you want; Claude picks the right one.

```
Audit my project for security holes
Protect my CRM — where do I start?
What is not protected in this project?
Set up protection against AI scrapers
Check that my login is safe against brute force
Someone got into the system — what do I do?
```

### The guided run

Say *"secure my project"* and the suite runs a single end-to-end flow — it does the
work, checks each result itself, and tells you what comes next at every point:

| Stage | What happens |
|---|---|
| 0 | Four questions, one at a time, each with the reason attached |
| 1 | Read-only audit — nothing is changed |
| 2 | A plan: what changes, how it is verified, how to undo it, how risky it is |
| 3 | Applied one item at a time, each followed by a four-line result |
| 4 | A checklist of what you must switch on yourself, in your service dashboards |
| 5 | Re-verification — a finding is closed only when the check stops firing |
| 6 | **Final report: before → after → what is protected now, and from what** |

Anything that could lock you out of your own system — firewall, SSH, strict CSP,
two-factor — is scheduled last and never applied unattended.

**Language.** The suite works in English by default and asks once whether you would
rather continue in Russian. Answer in any language at any point and it switches.

---

## The seven skills

| Skill | Layer | Covers |
|---|---|---|
| **`security-guard`** | Entry point | Seven-layer model, implementation plan, owner-facing reporting, glossary |
| **`guard-audit`** | Find | 12 audit blocks, three scripts, severity ranking, incident response |
| **`guard-auth`** | Login & roles | Password hashing, brute-force limits, sessions, TOTP 2FA, RBAC, IDOR |
| **`guard-data`** | Database | Grants, RLS, `SECURITY DEFINER`, SQL injection, PII, audit log, backups |
| **`guard-server`** | Perimeter | Ports, firewall, TLS, security headers, CSP, rate limits, SSH, secrets |
| **`guard-frontend`** | Browser | XSS, cookies, storage, CSRF, dependency hygiene, build-time secret leaks |
| **`guard-ai-policy`** | Bots & AI | `llms.txt`, `ai.txt`, `robots.txt`, `security.txt`, bot blocking, honeypots |

---

## The audit

`guard-audit` is the centre of the suite. It ships three read-only scripts:

```bash
bash scripts/audit-code.sh /path/to/project   # secrets, git history, dangerous code, deps
bash scripts/audit-live.sh example.com        # headers, TLS, exposed files, bot handling
psql "$DATABASE_URL" -f scripts/audit-db.sql  # grants, RLS, SECURITY DEFINER, policies
```

Findings are ranked on two axes only — **what is lost** against **how easy it is from
the outside** — so the report leads with the one thing that actually matters rather than
a wall of red. The scripts cover the mechanical checks; the skill covers what requires
reading code.

---

## AI and scraper policy — read this honestly

`guard-ai-policy` publishes `llms.txt`, `/.well-known/ai.txt`, `robots.txt`,
`security.txt` and `tdmrep.json`, sets `X-Robots-Tag` and `noai`, and configures bot
blocking for nginx, Caddy and Cloudflare.

**What these files do:** they state your terms. Major AI crawlers — GPTBot, ClaudeBot,
PerplexityBot, Google-Extended and the rest — honour a stated refusal and leave. A clear,
published statement that a service is private and access is licence-only also removes any
"the data was public" defence, and it is what an AI assistant sees when someone points it
at your site and asks it to copy the system or get past the login.

**What they do not do:** a text file cannot force a program to obey. A custom script will
ignore all of it. That is why the policy files ship *alongside* rate limiting, bot
blocking and — above all — authentication, never instead of them.

The skill states this distinction plainly to the owner. A false sense of security is
worse than none.

---

## Requirements

- Claude Code (any recent version)
- `curl` and `grep` for the audit scripts
- Optional, used if present: `git`, `openssl`, `npm`,
  [`gitleaks`](https://github.com/gitleaks/gitleaks),
  [`osv-scanner`](https://github.com/google/osv-scanner),
  [`semgrep`](https://github.com/semgrep/semgrep),
  [`trivy`](https://github.com/aquasecurity/trivy),
  [`lynis`](https://github.com/CISOfy/lynis)

Scripts are POSIX shell and run on Linux, macOS, WSL and Git Bash on Windows.

---

## Scope and limits

**In scope:** projects you own or are authorised to work on.

**Refused, without exception:** auditing or attacking third-party systems, bypassing
authentication, defeating other people's rate limits or captchas, extracting data from
services you do not control. The skills state this in their own instructions and decline
such requests.

**Not a substitute for:** a penetration test by a human, legal compliance work
(GDPR, HIPAA, 152-ФЗ), or a security programme. This suite raises the cost of an attack
above the value of the data and makes attempts visible. Nothing makes software unbreakable.

---

## Licence and attribution

Copyright © **ExcellentMaps** — <https://github.com/ExcellentMaps>

Released under [Creative Commons Attribution-NoDerivatives 4.0 International](LICENSE)
(CC BY-ND 4.0).

**You may:** use it commercially, on any number of projects, for clients; redistribute
it whole and unmodified with attribution intact.

**You may not:** publish modified or rebranded versions, remove the author attribution,
or present the suite as your own work.

Every `SKILL.md` carries the author in its YAML front matter and an HTML notice in the
body. [`NOTICE`](NOTICE) records the attribution requirement in full.
Run [`verify-integrity.sh`](verify-integrity.sh) to check a copy against the published
checksums.

---

<div align="center">
<sub>Guard Security Suite · © ExcellentMaps · <a href="https://github.com/ExcellentMaps">github.com/ExcellentMaps</a></sub>
</div>
