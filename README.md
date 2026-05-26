<div align="center">

[![Capsule Render](https://capsule-render.vercel.app/api?type=waving&color=240E0E&height=80&section=header&text=gitward&fontSize=52&fontColor=C43333&fontAlignY=72&animation=fadeIn)](https://github.com/tinyopsec/gitward)

<img src="https://raw.githubusercontent.com/tinyopsec/assets/main/gitward/logo.webp" width="160" alt="gitward logo" />

[![Typing SVG](https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=14&pause=1200&color=C43333&center=true&vCenter=true&width=700&lines=Git+repository+OSINT+%26+forensics+scanner;Secrets%2C+authors%2C+IPs%2C+hooks+%2F+all+of+it%2C+fast;Plain+C99.+Zero+runtime+dependencies.+One+binary.)](https://git.io/typing-svg)

</div>

<p align="center">
  <img src="https://img.shields.io/badge/license-MIT-C43333?style=flat&labelColor=240E0E&logo=opensourceinitiative&logoColor=C43333" />
  <img src="https://img.shields.io/badge/C99%20%2F%20POSIX-B44646?style=flat&label=lang&labelColor=240E0E&logo=c&logoColor=B44646" />
  <img src="https://img.shields.io/badge/~700%20lines-C65959?style=flat&label=source&labelColor=240E0E&logo=files&logoColor=C65959" />
  <img src="https://img.shields.io/badge/0.3-D46C6C?style=flat&label=version&labelColor=240E0E&logo=tag&logoColor=D46C6C" />
  &nbsp;
  <img src="https://img.shields.io/badge/Linux-E18080?style=flat&labelColor=240E0E&logo=linux&logoColor=E18080" />
  <img src="https://img.shields.io/badge/OpenBSD-EE9494?style=flat&labelColor=240E0E&logo=openbsd&logoColor=EE9494" />
  <img src="https://img.shields.io/badge/FreeBSD-FBA4A4?style=flat&labelColor=240E0E&logo=freebsd&logoColor=FBA4A4" />
  &nbsp;
  <img src="https://img.shields.io/badge/git-C43333?style=flat&label=requires&labelColor=240E0E&logo=git&logoColor=C43333" />
  <img src="https://img.shields.io/badge/make-B44646?style=flat&label=build&labelColor=240E0E&logo=gnu&logoColor=B44646" />
</p>

---

**gitward** is a command-line git repository scanner for OSINT, forensics, and supply-chain auditing. Point it at any local repo and it extracts everything hiding in the history: secrets, author identities, IP addresses, suspicious hooks, dangling commits, timezone shifts, and more — then scores the repo's overall risk.

It runs entirely through `git` subprocesses. No libraries, no runtime dependencies, no network calls. Just a single binary and a copy of git.

---

## Table of Contents

- [Why gitward](#why-gitward)
- [What It Finds](#what-it-finds)
- [Risk Scoring](#risk-scoring)
- [Installation](#installation)
- [Usage](#usage)
- [Commands](#commands)
- [Output Format](#output-format)
- [Secret Patterns](#secret-patterns)
- [Suspicious Patterns](#suspicious-patterns)
- [Contributing](#contributing)
- [License](#license)

---

## Why gitward

Git history is permanent and honest. Developers rotate secrets in the working tree but forget the commit three months ago that introduced them. Authors use personal emails on work machines. Internal hostnames leak through CI configs. Hooks get added without review.

gitward reads the whole picture: every commit across every ref, the reflog, stashes, notes, submodules, unreachable blobs, and hook scripts — then surfaces what matters.

It's useful for:

- **Red teams** auditing a target's leaked or public repositories
- **Blue teams** running post-incident forensics on internal repos
- **Security engineers** adding a pre-push or CI gate to catch secrets before they leave
- **Developers** who want to know what they've actually committed over the lifetime of a project

---

## What It Finds

gitward collects 15 clue types:

| Type | Description |
|---|---|
| `email` | Author, committer, config, and Signed-off-by emails across all commits |
| `username` | Extracted from emails, `.git/config`, GPG keys, and Signed-off-by trailers |
| `author` | Unique author and committer names from the full log |
| `commit` | Every reachable commit hash with subject and timestamp |
| `refname` | Branches, remotes, tags, reflog entries, and notes |
| `tag` | Annotated and lightweight tags |
| `stash` | All stash entries |
| `url` | Remote URLs, config URLs, and URLs found in diff content |
| `domain` | Domains extracted from URLs, plus internal `.corp`/`.local`/`.internal` hostnames |
| `ip` | IPv4 and IPv6 addresses found anywhere in the diff history |
| `filepath` | Tracked files, with alerts on sensitive filenames like `.env`, `id_rsa`, `.npmrc` |
| `secret` | Credential patterns matched against 30+ regex rules (see below) |
| `suspicious` | Dangerous shell patterns, force-push indicators, dangling commits, hook risk, odd-hour commits, timezone shifts, high-churn deletions, Docker directives, VS Code autorun config |
| `relation` | Submodule paths and GPG-signed commit metadata |
| `timestamp` | Commit timestamps, used for behavioral analysis |

Beyond collection, gitward also inspects:

- **Git hooks** in `.git/hooks`, `.githooks`, and `.husky` — each hook is scored for network calls, `base64 -d`, pipe-to-shell patterns, and other indicators of malicious intent
- **CI configs** — flags `.github/workflows`, `.gitlab-ci.yml`, `.travis.yml`, and `Jenkinsfile`
- **Dangling blobs** — runs `git fsck` and scans unreachable objects for credential patterns that would be invisible to a normal `git log`
- **VS Code workspace config** — catches `runOn: folderOpen` and `allowAutomaticTasks` settings that execute code on repo open
- **Timezone shifts** — detects when a named author commits from multiple timezones across the history
- **Odd-hour commits** — flags commits made between midnight and 6 AM local time

---

## Risk Scoring

Every scan produces a numeric risk score:

| Score | Meaning |
|---|---|
| 0–29 | Low risk |
| 30–99 | Worth reviewing |
| 100+ | High risk — take action |

Scores are additive. Highlights:

- Secret in a reachable commit: **+20**
- Secret in an unreachable blob (deleted, thought to be gone): **+80**
- Force-push indicator in reflog: **+30**
- Dangling commit: **+10**
- Hook with score ≥ 50 (pipe-to-shell, `base64 -d`, network calls): **+100**
- Hook with score ≥ 30: **+30**
- High-churn deletion commit: **+15**
- File deleted then re-added: **+20**
- Odd-hour commits accumulate per commit
- Three or more timezone shifts for the same author: **+10**

---

## Installation

**Requirements:** a C99 compiler, `make`, and `git` in `$PATH`.

```sh
git clone https://github.com/tinyopsec/gitward
cd gitward
make
sudo make install      # copies to /usr/local/bin
```

Or build without installing:

```sh
make
./gitward help
```

To build with explicit flags:

```sh
cc -std=c99 -Wall -Wextra -pedantic -O2 -o gitward main.c scan.c clue.c
```

No external libraries are needed. The binary links only against the C standard library.

---

## Usage

```
gitward <command> [args]
```

All commands accept either the full name or a single-letter alias.

```
gitward scan    [path]              scan a local git repository (default: .)
gitward inspect [path]              scan and print full report
gitward search  <path> <query>      search clues by keyword
gitward save    <path> [outfile]    save results to file
gitward version                     print version
gitward help                        print help

aliases:  s=scan  i=inspect  f=search  o=save
```

Quick examples:

```sh
# Scan the current directory
gitward scan

# Scan a specific repo
gitward scan /path/to/repo

# Search for a domain or string
gitward search /path/to/repo corp.internal

# Save results as plain text
gitward save /path/to/repo results.txt

# Save results as JSON (detected by .json extension)
gitward save /path/to/repo results.json
```

---

## Commands

### `scan` / `s`

Scans the repository at `path` (defaults to `.`) and prints the full inspection report to stdout. Runs all collectors: commits, authors, refs, tags, stashes, reflog, notes, files, remotes, git config, URLs, IPs, internal domains, submodules, GPG signatures, hooks, VS Code config, CI configs, Docker directives, dangling commits and blobs, timezone anomalies, odd-hour commits, churn analysis, signed-off-by trailers, and force-push indicators.

### `inspect` / `i`

Identical to `scan`. Both commands scan and then print the report. The distinction is there if you want to script around explicit intent.

### `search` / `f`

Scans the repository and then filters all collected clues against `query` (case-insensitive substring match against value, author, path, and extra fields). Useful for pivoting: find every clue touching a specific email, hostname, or commit hash.

```sh
gitward search . alice@example.com
gitward search /repos/target sk_live_
```

### `save` / `o`

Scans the repository and writes results to `outfile` (defaults to `gitward.out`). If `outfile` ends in `.json`, results are written in JSON format with full field metadata. Otherwise a flat key=value text format is used, suitable for grep pipelines.

The JSON output includes: `gitward_version`, `repo`, `scanned` (UTC timestamp), `risk_score`, `clue_count`, and a `clues` array with `type`, `value`, `commit`, `author`, `path`, `extra`, and `utc` per entry.

---

## Output Format

The terminal report uses color when stdout is a TTY (green for clean, yellow for warnings, red for secrets and high risk). Sections:

```
── REPOSITORY ─────────────────────────────────────────────
  path:          /path/to/repo
  scanned:       2025-04-12T14:23:01Z
  git-size:      42M
  pack-size:     38M
  commits:       1847
  authors:       12
  refs:          34
  ...
  secrets:       2
  suspicious:    7
  risk-score:    145

── SECRETS ─────────────────────────────────────────────────
  [CRIT] AKIA...  commit=a3f9c1  path=config/deploy.sh  utc=2024-11-03T02:14:00Z

── SUSPICIOUS ──────────────────────────────────────────────
  [WARN] hook:.git/hooks/post-checkout score=75
  [WARN] force-push-indicator:refs/heads/main reset: moving...
```

---

## Secret Patterns

gitward matches 30+ patterns across current working files and unreachable history:

- AWS access keys (`AKIA…`, `ASIA…`)
- GitHub tokens (`ghp_`, `ghs_`, `github_pat_`, classic fine-grained)
- GitLab tokens (`glpat-`)
- Slack tokens (`xox[baprs]-`)
- Private keys (RSA, EC, DSA, OpenSSH, PGP)
- Google API keys (`AIza…`) and OAuth tokens (`ya29.`)
- JWTs (`eyJ…`)
- MongoDB connection strings
- Stripe live keys (`sk_live_`, `rk_live_`)
- SendGrid API keys (`SG.`)
- Twilio credentials (`AC…`, `SK…`)
- Square tokens (`sq0atp-`, `sq0csp-`)
- Generic 64-character hex strings
- Password/secret/token/API key assignment patterns (single- and double-quoted)
- Database password environment variables
- NPM tokens
- Docker and Heroku environment variable assignments
- AWS metadata endpoint (`169.254.169.254`)

---

## Suspicious Patterns

Beyond credential patterns, gitward flags shell and behavioral indicators:

- `curl … | sh`, `wget … | sh`
- `base64 -d` or `base64 --decode`
- `eval $(base64 …)`
- Access to `/etc/passwd`, `/etc/shadow`, `/etc/cron`
- `chmod 777` / `chmod 666`
- `rm -rf /`
- `.onion` addresses
- VS Code `runOn: folderOpen` / `allowAutomaticTasks`

Hook scripts are scored separately with a finer-grained model that looks at `curl`, `wget`, `base64`, `/dev/tcp`, `nc`, `netcat`, `bash -i`, `python -c`, `perl -e`, `ruby -e`, `ncat`, `socat`, `exec`, pipe-to-shell, and comment density.

---

## Contributing

Bug reports and patches are welcome. Keep changes to plain C99, POSIX-compatible, and dependency-free. Run `make` before submitting; the build should produce zero warnings with `-Wall -Wextra -pedantic`.

---

## License

MIT — see [LICENSE](LICENSE).
