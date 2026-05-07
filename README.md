# Sentinel

Your computer is open right now and you don't know it.

Sentinel is a free, local security tool for macOS and Linux. It checks what's listening, who's connecting, whether your firewall is actually on, and plants fake files that tell you when someone is snooping. Everything runs on your machine. No cloud. No subscription. No data leaves your computer.

## Install

```
curl -fsSL https://raw.githubusercontent.com/LacobusGump/sentinel/main/install.sh | bash
```

Or clone it:

```
git clone https://github.com/LacobusGump/sentinel.git
cd sentinel
chmod +x sentinel.sh modules/*.sh install.sh
./sentinel.sh
```

## What it checks

### Ports (`sentinel ports`)
Lists every port listening on your machine. Compares against your whitelist. Anything listening that you didn't explicitly approve gets flagged. This is how we found a Python HTTP server that had been serving an entire project directory to the local network for 20 days.

### Connections (`sentinel connections`)
Snapshots active network connections. Flags new external IPs you've never connected to before, connections to known-bad ports (crypto mining, Metasploit, Tor, IRC botnets), and unusual connection volume. Builds a baseline over time so it learns what's normal for your machine.

### Firewall (`sentinel firewall`)
Checks whether your firewall is actually turned on. On macOS: application firewall, stealth mode, SIP, Gatekeeper, FileVault, SSH. On Linux: UFW/iptables, disk encryption, SSH daemon. Offers to fix what's wrong.

### Honeypot Decoys (`sentinel deploy`)
Creates fake sensitive files in hidden directories on your machine: fake Bitcoin wallets, fake password lists, fake SSH keys, fake AWS credentials, fake .env files with fake API keys. They look real. If any process reads or modifies them, you get an alert. This is your silent alarm.

### Service Watchdog (`sentinel selfheal`)
Define services that should be running. Sentinel checks them on an interval. If one dies, it restarts it and logs the event. No more silent failures.

### Full Audit (`sentinel audit`)
The full sweep:
- Disk encryption status
- Firewall + stealth mode
- SIP + Gatekeeper
- SSH enabled?
- Open ports vs whitelist
- Stale sensitive files in Downloads/Desktop
- Directory permissions
- .env files with secrets
- Git repos with committed secrets
- LaunchAgents/LaunchDaemons inventory
- Crontab review
- DNS configuration (malware blocking?)

## What it does NOT do

- **Not antivirus.** It does not scan for malware signatures. It watches for behavior.
- **Not endpoint detection.** It does not hook into kernel events or install drivers.
- **Not magic.** It runs the checks that any sysadmin would run, just automated and repeating.
- **Not a replacement for patching.** Keep your OS updated.
- **Not cloud-based.** Nothing leaves your machine. No telemetry. No phone-home. No account.

## Commands

```
sentinel              Full security report (runs all checks)
sentinel audit        Deep security audit
sentinel watch        Continuous monitoring (Ctrl+C to stop)
sentinel tripwire     Start honeypot file monitoring
sentinel ports        Check open ports against whitelist
sentinel connections  Monitor active connections
sentinel firewall     Check/fix firewall settings
sentinel selfheal     Start service watchdog
sentinel status       Quick status check
sentinel baseline     Save current state as normal baseline
sentinel deploy       Install honeypot decoys + set up monitoring
sentinel help         Show all commands
```

## Configuration

Edit `config/sentinel.conf` to customize:

- **Port whitelist** — which ports you expect to be listening
- **Services** — what to monitor and how to restart
- **Decoy locations** — where to plant honeypot files
- **Trusted processes** — whose connections to ignore (reduces noise)
- **Bad ports** — known-suspicious ports to flag
- **Scan directories** — where to look for stale sensitive files

## Continuous monitoring

### macOS (LaunchAgent)
```
sentinel deploy
launchctl load ~/Library/LaunchAgents/com.sentinel.plist
```

Sentinel will run in the background, checking ports and connections every 5 minutes.

### Linux (cron)
```
crontab -e
# Add:
*/5 * * * * /path/to/sentinel.sh watch >> ~/.sentinel/sentinel.log 2>&1
```

### Linux (systemd)
Create `/etc/systemd/user/sentinel.service`:
```ini
[Unit]
Description=Sentinel Security Monitor

[Service]
ExecStart=/path/to/sentinel.sh watch
Restart=always

[Install]
WantedBy=default.target
```
Then: `systemctl --user enable --now sentinel`

## Platform support

| Platform | Support |
|----------|---------|
| macOS    | Full. All modules + LaunchAgent. |
| Linux    | Full. All modules. Use cron or systemd instead of LaunchAgent. |
| Windows  | Not supported. Bash-only. Use WSL if you need it on Windows. |

## Dependencies

**Required:** bash, lsof (or ss on Linux), netstat

**Optional but recommended:**
- `fswatch` (macOS) — realtime file monitoring for tripwire. Install: `brew install fswatch`
- `inotifywait` (Linux) — same. Install: `sudo apt install inotify-tools`

Without fswatch/inotifywait, the tripwire falls back to polling (checks every 30 seconds instead of realtime).

## How the decoys work

The honeypot files are designed to fool someone who has already gotten access to your machine. They contain:

- **wallet_backup.dat** — Looks like a real Bitcoin Core wallet dump with private keys
- **passwords.txt** — Looks like someone's actual password file with email, banking, crypto, SSH entries
- **.env.backup** — Looks like a production app's environment file with database URLs, Stripe keys, AWS credentials
- **id_rsa_backup** — Looks like an SSH private key
- **AWS credentials** — Looks like real AWS access keys

None of these are real credentials. They are all fake. But an intruder doesn't know that. The moment they open, copy, or modify any of these files, sentinel alerts you.

The files have staggered modification dates and realistic formatting to avoid looking planted. Sophisticated intruders check for honeypots — these are designed to pass that check.

## Why this exists

We ran a security audit on a Mac that had been running for months. Found a web server open to the network serving an entire project directory. Found a Stripe webhook secret in plaintext in a LaunchAgent plist. Found certificates sitting in Downloads for weeks. Found the connection monitor existed but wasn't running.

Every one of these is a 5-second check. Nobody does them. Now a script does.

## License

MIT. Free. Do whatever you want with it.

Built by [beGump](https://begump.com). Everything free. Everything local.
