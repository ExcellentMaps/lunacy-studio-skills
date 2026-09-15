# Guided Setup — the end-to-end run

Guard Security Suite © ExcellentMaps — github.com/ExcellentMaps

---

This is what happens when someone installs the suite and says **"secure my project"**.
It is one continuous, staged run: the agent does the work, checks each result itself,
tells the person what stage comes next, and finishes with a written summary of what
changed.

The person is not expected to know any of this. They are expected to answer four
questions at the start and press Enter a few times.

---

## Language

**Default working language: English.**

At the very first message, ask once — one line, nothing else:

> Working language: **English** or **Russian**? (default: English)

Then use that language for everything: questions, explanations, the final report.
Switch immediately if the person switches mid-run. Never ask twice.

If the person's first message is already in another language, adopt it and skip
the question entirely.

---

## The rules that apply to every stage

1. **Nothing is applied without showing it first.** Show the change, say what it does,
   then apply.
2. **One stage at a time.** Never batch two risky changes into one step.
3. **Verify before moving on.** A stage is not done because the file was written.
   It is done because a check proved it works.
4. **Every stage records its rollback** in one line.
5. **Every message ends with `Next:`** — one concrete action, not a menu.
6. **Anything that can lock the owner out goes last** — firewall, SSH, strict CSP, 2FA.

---

## Stage 0 — Four questions

Ask them one at a time, each with the reason attached. Do not dump all four at once.

| # | Question | Why you ask |
|---|---|---|
| 1 | Where is the project on disk? | To read the code and configs |
| 2 | Is it live? What is the domain? | To check the real surface from outside |
| 3 | What is the worst thing that could be lost? | That is what the attacker wants — it sets priorities |
| 4 | Is anyone using it right now? | Decides whether changes go in now or in a quiet window |

If the project is not live yet, skip every external check and say so — do not pretend
to have tested something you could not reach.

**Next:** run the audit.

---

## Stage 1 — Audit (read-only)

Hand off to `guard-audit`. Run what is available:

```
bash scripts/audit-code.sh <path>     # secrets, git history, dangerous code, deps
bash scripts/audit-live.sh <domain>   # headers, TLS, exposed files, bot handling
psql "$DATABASE_URL" -f scripts/audit-db.sql   # grants, RLS, policies
```

Then read the code for what scripts cannot see: permission logic, access to other
people's records, who can export the customer base.

Report findings ranked on two axes only — **what is lost** × **how easy from outside**.

Say plainly how many findings are red, orange, yellow. Do not read the whole list aloud.

**Next:** present the plan.

---

## Stage 2 — The plan

One table. One row per change. Show it and wait for a yes.

| # | What changes | Verified by | Rollback | Risk |
|---|---|---|---|---|
| 1 | Rotate the leaked API key | Old key rejected by the service | Keep old key active until new one works | Low |
| 2 | Bind Postgres to 127.0.0.1 | Port does not answer from outside | Restore previous compose file | Low |
| … | | | | |

Default order, cheapest and safest first:

```
1. Secrets and keys          (a leaked key cancels every other layer)
2. Perimeter: ports, TLS
3. Database grants
4. Login: brute-force limits, sessions
5. Security headers
6. CSP                       (can break layout — Report-Only first)
7. Bot and AI policy
8. Audit log and backups
9. Firewall, SSH, 2FA        (can lock the owner out — always last)
```

Say out loud which items are risky and why. Let the owner drop any of them — that is
their call, not yours.

**Next:** start with item 1.

---

## Stage 3 — Apply, one item at a time

For each item, the same five beats:

```
INSPECT   read the file you are about to change, in full
BACK UP   copy it with a date in the name; dump the database before a migration
APPLY     one change
VERIFY    prove it works — and prove the site still works
RECORD    write the rollback line
```

After each item, report in four lines and nothing more:

> **Done:** service ports are no longer reachable from the internet.
> **Protects from:** scanners finding an open database and grinding passwords against it.
> **Verified:** port 5432 does not answer from an outside machine; the site still loads.
> **Undo:** restore `docker-compose.yml.bak-2026-09-15` and restart.
>
> **Next:** item 2 — renew the TLS certificate automatically.

### When the person has to run something themselves

Some steps cannot be done for them: generating a key, opening a terminal, pasting a
value into a hosting panel.

Give **one command at a time**, say what they will see afterwards, and wait.
Never dump a list of ten commands.

Exact step-by-step wording — how to open a terminal on each OS, how to generate keys,
where to put them, and why md5 must never be used for passwords — is in
`terminal-howto.md`.

If a check fails: **stop, roll back, say so.** Do not continue down the plan with a
broken step behind you. A failed step is normal; hiding it is not.

---

## Stage 4 — Owner actions

Some protection cannot be switched on from the code. It needs the person with access
to the service dashboards.

Produce a short list, ordered, each item one line with a reason:

- Cloudflare: block AI crawlers; enable bot protection.
- Hosting panel: scheduled snapshots; cloud firewall.
- GitHub: enable 2FA on the account; enable secret scanning.
- Domain email: SPF, DKIM, DMARC records.
- The account holding all of the above: enable 2FA.

⚠️ **Before dictating any click path, open that service's current official
documentation and check the menu names.** Dashboards get redesigned every few months.
A person who cannot find the step you named assumes they did something wrong and
gives up. Never dictate from memory.

Offer to walk through them one by one, at the person's pace.

**Next:** re-run the audit.

---

## Stage 5 — Prove it

Re-run the exact checks that produced the findings. A finding is closed only when the
check that found it stops firing.

Then run one obvious sanity pass on the live system:

- the site opens;
- login works;
- data is visible;
- file upload and download work;
- integrations still receive their webhooks.

The last one is the one that gets missed. Bot blocking kills webhooks silently, and
the connection is usually discovered weeks later.

**Next:** the final report.

---

## Stage 6 — Final report

This is the deliverable. Written for the owner, not for an engineer.

```markdown
# Security work — <project>, <date>

## In two sentences
<What was found, what was done, what the owner should still do themselves.>

## Before → After

| Area | Before | After |
|---|---|---|
| Database port | Open to the internet | Reachable only by the server itself |
| Login | Unlimited password attempts | Locks after 5 tries; separate limit on unknown logins |
| Sessions | Never expired | 30 days; revoking access ends them immediately |
| Backups | Manual, same server | Nightly, off-server, restore tested |
| AI and scrapers | No policy | Policy published; AI crawlers and scanners refused |

## What is now protected, and from what

**Service ports are closed.**
The database is not reachable from the internet at all.
*Without this:* automated scanners find an open database within the hour and grind
passwords against it around the clock.
*Check it yourself:* from another computer, the port does not answer.

<one block per measure, same four lines>

## What was already in good shape
<Mandatory section. Name what the previous work got right.>

## Still open — and why
<Anything not done, with the reason: owner declined, needs a paid service,
needs a maintenance window. Never quietly omit it.>

## What you must do yourself
<The dashboard actions from Stage 4, as a checklist.>

## How to undo anything
<One line per change.>
```

### Two rules for the report

**Do not inflate.** A missing `Referrer-Policy` header is not a critical vulnerability.
An owner who is shown everything in red stops believing reports — and then misses the
one that mattered.

**Do not promise.** Never write "now you are secure" or "this cannot be hacked".
Write what the cost of an attack now is, and what would be noticed if someone tried.

---

## If the person says "just do everything, I do not understand any of this"

That is the common case and it is fine. Do this:

1. Run stages 1–3 for everything in the **low-risk** group without stopping at each item.
2. Stop before anything that can lock them out (firewall, SSH, 2FA) and explain in one
   sentence why that one needs their attention.
3. Give the final report.
4. Offer the owner-action checklist as a separate, slower walkthrough.

Never use "they said just do it" as licence to apply a change that could take the
system down or lock the owner out unattended.
