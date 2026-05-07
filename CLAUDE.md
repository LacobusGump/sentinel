# CLAUDE.md — Sentinel

## What this is

A pure-bash security tool for macOS and Linux. No cloud. No subscriptions. No data leaves the machine. Every check runs locally.

Born from finding port 8080 open for 20 days on a production Mac.

## Architecture

```
sentinel.sh         — Master script. Routes commands to modules.
modules/
  tripwire.sh       — Honeypot decoy files (fake creds, fake keys). Monitors for access.
  selfheal.sh       — Service watchdog. Checks health, restarts if dead.
  portcheck.sh      — Lists listening ports. Compares against whitelist. Flags exposed ports.
  connwatch.sh      — Monitors active connections. Flags new IPs, bad ports, volume spikes.
  firewall.sh       — Checks firewall, stealth mode, SIP, FileVault, Gatekeeper, SSH.
  audit.sh          — Full sweep: all of the above + stale files, permissions, .env secrets, git secrets, LaunchAgents, DNS.
config/
  sentinel.conf     — User config: whitelist ports, services to watch, decoy locations, trusted processes.
  decoys/           — Template directory for honeypot files.
.launchd/
  com.sentinel.plist — macOS LaunchAgent template for continuous monitoring.
```

## Key design decisions

- **Pure bash.** No Python, no Node, no compiled binaries. Runs on any Mac or Linux box with zero setup.
- **fswatch/inotifywait for tripwire** but falls back to polling if neither is installed.
- **Whitelist model for ports.** You define what SHOULD be listening. Everything else is flagged.
- **Baseline model for connections.** First run learns what's normal. Future runs flag deviations.
- **Decoy files look real.** Fake Bitcoin wallets, fake SSH keys, fake .env files, fake AWS credentials. An intruder should believe they found something valuable.
- **No root required** for most operations. Firewall fixes and stealth mode need sudo.

## How to work on this

- Test on macOS first (primary target). Linux second.
- Every module is independently runnable: `bash modules/portcheck.sh`
- Config is sourced by all modules. Add new settings there.
- Output format: `[PASS]`, `[WARN]`, `[FAIL]`, `[INFO]` — parsed by sentinel.sh for summary counts.
- Logs go to `~/.sentinel/sentinel.log`. Baselines go to `~/.sentinel/`.

## What NOT to add

- Network scanning of other machines (stay local)
- Anything that sends data externally
- Binary dependencies
- Anything that requires a paid service
- Antivirus signatures (this is not an AV — it's awareness)

## Integration with loo9

This repo works standalone. It also works as a loo9 project — drop the loo9 CLAUDE.md into the root and the autonomous agents will audit, test, and improve the security checks. The builder adds checks, the destroyer runs them against edge cases, the connector finds gaps between modules.
