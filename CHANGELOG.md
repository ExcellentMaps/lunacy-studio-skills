# Changelog

All notable changes to Guard Security Suite are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2026-09-15

First public release.

### Added

**Seven skills**

- `security-guard` — entry point. Seven-layer security model, the guided
  end-to-end run, rollout planning, owner-facing reporting, glossary, and a
  step-by-step terminal guide for people who have never opened one.
- `guard-audit` — twelve audit blocks, three read-only scripts, severity
  ranking on two axes, report template, incident response, tool directory.
- `guard-auth` — password hashing, two-counter brute-force protection,
  sessions and device revocation, TOTP with recovery codes, roles, IDOR.
- `guard-data` — grants and least privilege, RLS, `SECURITY DEFINER` and
  `search_path`, SQL injection, personal data, audit log, verified backups.
- `guard-server` — ports and firewall, TLS and renewal, security headers and
  CSP, rate limits, SSH hardening, secrets and rotation, updates and logs.
- `guard-frontend` — XSS, cookies and storage, CSRF, dependency hygiene,
  build-time secret leaks, uploads and third-party widgets, and the myths
  section (obfuscation, disabled right-click, hidden buttons).
- `guard-ai-policy` — AI and scraper policy, bot blocking, honeypots, and an
  honest account of what stops a program versus what merely states terms.

**Audit scripts** (read-only, they never change anything)

- `audit-code.sh` — secrets in code and git history, dangerous constructs,
  configuration, dependencies.
- `audit-live.sh` — TLS, security headers, exposed service files, policy
  files, bot handling, and the reverse check that real browsers still pass.
- `audit-db.sql` — PostgreSQL grants, RLS, `SECURITY DEFINER`, policies,
  views, extensions. Every block explains what its result means.

**Templates**

- `llms.txt`, `/.well-known/ai.txt`, `robots.txt`, `/.well-known/security.txt`,
  `/.well-known/tdmrep.json`, `X-Robots-Tag` headers, `noai` meta tags.
- nginx bot-blocking map with webhook, ACME and search-engine exemptions.
- Production `nginx-security.conf` and `Caddyfile-security`, commented line
  by line, each with a "what to replace" block.
- PostgreSQL `lock-down-grants.sql` with a mandatory pre-flight warning.

### Notes

- Distributed as a plugin marketplace: `/plugin marketplace add
  ExcellentMaps/lunacy-studio-skills`, then `/plugin install
  excellentmaps@lunacy-studio-skills`. Manual copying still works.
- English is the default working language; the suite asks once whether to
  continue in Russian and switches at any point on request.
- Documentation ships in English (`README.md`) and Russian (`README.ru.md`).
- Licensed CC BY-ND 4.0. `SHA256SUMS` and `verify-integrity.sh` let anyone
  confirm a copy is the unmodified original.

[1.0.0]: https://github.com/ExcellentMaps/lunacy-studio-skills/releases/tag/v1.0.0
