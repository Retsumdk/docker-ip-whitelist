# docker-ip-whitelist

[![CI](https://github.com/Retsumdk/docker-ip-whitelist/actions/workflows/ci.yml/badge.svg)](https://github.com/Retsumdk/docker-ip-whitelist/actions/workflows/ci.yml)

Manage an IP whitelist for Docker-published ports through the kernel's `DOCKER-USER`
iptables chain — with real CIDR math, a dry-run plan, drift detection, and rollback.
Zero runtime dependencies, one small binary (`diw`).

## Why

`dockerd` writes its own iptables rules and inserts them ahead of `INPUT`-chain
firewalls, which is why a `ufw deny 5432` does nothing for a `-p 5432:5432`
container. Traffic to published ports is routed through the `FORWARD` chain, where
the only sanctioned hook is the `DOCKER-USER` chain: Docker creates it, never
flushes it, and guarantees it is evaluated first.

The hard parts are not the iptables commands — they are everything around them:

- **CIDR correctness.** "Is `10.0.0.42` inside `10.0.0.0/16`?" is bit math most
  shell scripts get subtly wrong (host bits, /0 overflow, boundary octets).
- **Idempotence.** Re-running a naive `-A` script appends duplicate rules forever.
- **Drift.** A teammate edits the whitelist at 2am; nothing tells you the running
  ruleset no longer matches the file.
- **Rollback.** `iptables -F` in the wrong chain is a lockout story.

`diw` owns all four: canonical CIDR storage, a deterministic command plan,
an applied-state file that detects drift, and one-command rollback to the
previous ruleset.

## Install

```bash
npm install github:Retsumdk/docker-ip-whitelist
# or
bun add github:Retsumdk/docker-ip-whitelist
bun pm trust docker-ip-whitelist   # Bun blocks git-dep prepare scripts by default
```

Both run the `prepare` build and give you the `diw` CLI plus the library import.
Requires Node >= 18.17. Applying rules touches live firewall state and needs
root (or `CAP_NET_ADMIN`); everything else — planning, checking, importing —
is unprivileged.

## Quick start

```bash
$ echo '10.0.0.0/24' > ip-whitelist.txt
$ echo '203.0.113.7' >> ip-whitelist.txt

$ diw check 10.0.0.42 192.0.2.99
ALLOW 10.0.0.42 (matched 10.0.0.0/24)
DENY  192.0.2.99
$ echo "exit=$?"          # any DENY exits 2 — CI-usable
exit=2

$ diw plan
chain: DOCKER-USER
default policy for unmatched traffic: DROP
whitelisted sources (2):
  10.0.0.0/24
  203.0.113.7/32
commands:
  $ iptables -N DOCKER-USER 2>/dev/null || true
  $ iptables -C FORWARD -j DOCKER-USER 2>/dev/null || iptables -I FORWARD 1 -j DOCKER-USER
  $ iptables -F DOCKER-USER
  $ iptables -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  $ iptables -A DOCKER-USER -s 10.0.0.0/24 -j ACCEPT
  $ iptables -A DOCKER-USER -s 203.0.113.7/32 -j ACCEPT
  $ iptables -A DOCKER-USER -j DROP

$ sudo diw sync                       # apply for real (needs root)
$ diw rollback                        # undo: restores the previous ruleset
```

The `plan` is deterministic: the same whitelist always produces the same command
sequence, and `sync` rewrites the whole chain instead of appending — so running it
twice is a no-op the second time. The conntrack rule keeps established flows alive
across syncs so you don't cut your own SSH session.

## Commands

| Command | What it does | Exit codes |
|---|---|---|
| `diw add <ip-or-cidr>...` | Add entries to the rules file (canonicalized, deduped) | 0 / 1 |
| `diw remove <ip-or-cidr>...` | Remove entries; unknown ones are ignored | 0 / 1 |
| `diw list` | Print the whitelist with per-rule address counts | 0 / 1 |
| `diw check <ip>...` | Test IPs; prints `ALLOW`/`DENY` per address | 0 allowed · 2 any denied · 1 error |
| `diw import <file>` | Merge a text rules file (comments + invalid lines reported) | 0 / 1 |
| `diw plan` | Print the exact iptables command plan — changes nothing | 0 / 1 |
| `diw sync [--dry-run]` | Apply the plan to the live chain and save state | 0 / 1 |
| `diw rollback` | Re-apply the previous ruleset from the state file | 0 · 2 nothing to roll back · 1 |
| `diw demo` | End-to-end verdicts + plan on an in-memory whitelist | 0 |

Global options: `--file <path>` (rules file, default `./ip-whitelist.txt`;
`.json` files take `{"entries": [...]}`), `--state <path>` (default
`./diw-state.json`), `--iface <name>` (e.g. `eth0`), `--policy drop|return`
(default `drop`), `--chain <name>` (default `DOCKER-USER`), `--json`,
`-h/--help`.

## How it works

```
ip-whitelist.txt ──load──▶ Whitelist (canonical CIDR set)
                               │
                          buildPlan()
                               ▼
   iptables -N DOCKER-USER              (idempotent bootstrap)
   iptables -C FORWARD -j DOCKER-USER   (hook guarantee)
   iptables -F DOCKER-USER              (rewrite, never append)
   conntrack RELATED,ESTABLISHED ACCEPT (keep established flows)
   -s <cidr> ACCEPT  × n                (whitelist, sorted)
   -j DROP                              (default policy)
                               │
                            sync() ──▶ state file ──▶ drift + rollback
```

- **CIDR core** (`src/ip.ts`): IPv4 → uint32, host-bit masking, membership,
  range size. `/0` is handled as a plain number (2³²) — the bit-shift idiom
  overflows to 0 there.
- **Whitelist** (`src/whitelist.ts`): ordered, deduped set keyed by canonical
  `a.b.c.d/p`; text parser with `#`/`;` comments that reports invalid lines
  with line numbers instead of aborting.
- **Planner** (`src/iptables.ts`): builds the command list; `applyPlan` stops at
  the first failure; the runner is injectable, which is how the whole engine is
  tested without root.
- **Engine** (`src/engine.ts`): sync = plan → apply → persist. The state file
  stores the applied ruleset *and the previous one*; drift between file and
  state is reported on the next sync.
- **State** (`src/state.ts`): format-tagged, versioned JSON with validation —
  a corrupt or foreign state file is an error, never silently reset.

### Library use

```ts
import { Whitelist } from "docker-ip-whitelist";
import { sync } from "docker-ip-whitelist";

const wl = new Whitelist();
wl.add("10.0.0.0/24", "203.0.113.7");
wl.check("203.0.113.7");   // { allowed: true, matched: {...} }
wl.check("8.8.8.8");       // { allowed: false }

const { report } = await sync(wl, { iface: "eth0", statePath: "/var/lib/diw/state.json" });
report.applied;            // true (throws with the failing command on failure)
```

All types are exported (`IpRule`, `Plan`, `SyncReport`, `StateFile`, `CheckResult`),
the CLI (`src/cli.ts`) is importable for embedding, and every command supports
`--json` for scripting.

## Rules file format

One IPv4 address or CIDR per line; `#` and `;` start comments (full-line or
trailing); blank lines are ignored. Host bits are normalized on load
(`10.1.2.3/8` → `10.0.0.0/8`).

```
# office egress
10.0.0.0/24
# partner VPN gateway
203.0.113.7        # delegated exit node
```

## Operational notes

- `sync` flushes and rewrites the target chain on every run — make the rules
  file the single source of truth and don't hand-edit the chain.
- Scope rules with `--iface` (e.g. `-i eth0`) so whitelists apply to inbound
  traffic on a specific interface only.
- The state file is the rollback anchor; include it in backups alongside the
  rules file (both default to the working directory).
- `--policy return` makes the chain transparent for non-whitelisted traffic
  (useful when another firewall owns the final verdict).

## Development

```bash
bun install
bun run typecheck && bun run typecheck:tests
bun test
bun run build
node dist/cli.js demo
```

## License

MIT — see [LICENSE](LICENSE). Built by [Retsumdk](https://github.com/Retsumdk).
