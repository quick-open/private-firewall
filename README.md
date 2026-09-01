# PrivateFirewall

A user-mode **control plane and monitoring dashboard on top of the firewall
your OS already has** — Windows Firewall (WFP) on Windows 10/11, **ufw** on
Linux (Quick OS / Ubuntu). It gives you a live view of every active
connection, throughput, and listening port; a kill switch and dynamic
block/allow rules; zero-trust default-deny-outbound lockdown; and an
intrusion/anomaly **alert engine** (port scans, brute-force, new listeners,
plaintext-DNS bypass, host fan-out, upload surges).

Pure Python standard library (+ PowerShell on Windows, ufw/pkexec on Linux).
No drivers, no external packages. The same single-page dashboard on both OSes;
platform differences are surfaced honestly (see the feature map below).

**Notifications are off by default** on both platforms: firewalls see constant
background noise, so popups are strictly opt-in (Settings → Desktop
notifications). Enforcement, alert recording and the dashboard activity view
are always on — the header shows "Protection active — notifications off".

> **100% AI-built and open source**, published on [QuickOpen](https://quickopen.ai/projects/private-firewall). Apache-2.0.

---

## Architecture — read this first

> **The kernel firewall (WFP on Windows, netfilter/ufw on Linux) is the packet
> entry point, not this app.**

It already sits in the kernel as the single choke point for **all** wired and
wireless traffic. PrivateFirewall does **not** re-route packets and does not try
to be a packet filter of its own. That is deliberate:

- **Fail-open.** If the Python engine crashes or is killed, the kernel firewall
  keeps enforcing the configured policy. Your machine is never left unprotected
  because a user-mode process died.
- **Enforced before any app connects.** A user program can never guarantee it
  starts before every outbound connection. The kernel can. So "block before
  anything connects" is implemented by writing a **persistent default-deny
  outbound policy** into the firewall store, which the Base Filtering Engine
  (BFE) applies at boot — before logon, before any user app runs. See
  `Install-PrivateFirewall.ps1 -BootLockdown`.

PrivateFirewall is the **brain and dashboard** on top of that kernel enforcement:
it observes (via the IP Helper API + firewall drop-log), decides (alert engine),
and acts (kill connections, author WFP rules in a dedicated rule group).

```
   ┌────────────────────────── Windows kernel ──────────────────────────┐
   │  WFP / BFE  ── enforces persistent policy for ALL wired+wireless    │
   │      ▲ rules (group "PrivateFirewall")      │ drop-log              │
   └──────┼──────────────────────────────────────┼──────────────────────┘
          │ New/Remove-NetFirewallRule            │ pfirewall.log
   ┌──────┴──────────────────────────────────────▼──────────────────────┐
   │  pfw/server.py  — localhost engine (token-authed, 127.0.0.1 only)   │
   │   • IP Helper API: TCP/UDP tables + PID attribution                 │
   │   • GetIfTable: per-interface throughput                            │
   │   • SetTcpEntry: kill a single TCP connection                       │
   │   • alert engine: scans / brute-force / anomalies                  │
   └──────────────────────────────▲──────────────────────────────────────┘
                                   │ JSON /api/state + POST controls
                        pfw/dashboard.html  (single-page, no build step)
```

---

## Platform architecture (the port, honestly)

Everything platform-specific lives behind ONE interface — `pfw/backend.py`:

```
                    pfw/server.py  (platform-neutral)
        state manager · alert engine · HTTP API · dashboard
                              │ FirewallBackend
        ┌─────────────────────┴──────────────────────┐
 pfw/backend_windows.py                     pfw/backend_linux.py
 WFP via ctypes/iphlpapi + PowerShell       ufw CLI + /proc + ufw.log
 (the original engine, moved intact;        privileged ops via ONE pkexec'd
 runs elevated via UAC at launch)           root helper per session
                                            (pfw/root_helper.py — refuses
                                            ufw enable/disable/reset outright)
```

The dashboard reads the backend's **capability flags** and shows only what the
platform can truly do.

### Windows ↔ Linux feature map

| Feature | Windows | Linux (Quick OS / Ubuntu) |
|---|---|---|
| Enforced by | Windows Firewall (WFP) | ufw / netfilter |
| Live connections + process attribution | IP Helper API | `/proc/net` + inode→pid |
| Per-**application** rules | **yes** (WFP `-Program`) | **no** — netfilter has no per-binary match; use port / app-profile rules |
| Port / range / ufw app-profile rules | via the per-app UI only | **yes** (`allow/deny/limit/reject`, in/out) |
| Block an IP (in+out, auto-expiring) | yes (rule group) | yes (`PFW`-commented rules, prepended) |
| Kill a single TCP connection | IPv4 only (`SetTcpEntry`) | IPv4 **and** IPv6 (`ss -K`) |
| Lockdown (default-deny outbound, DNS+DHCP kept open) | yes | yes (`ufw default deny outgoing`) |
| Network profiles (Public/Private/Domain) | yes | **no equivalent** — pill hidden |
| Block all IPv6 | unbind `ms_tcpip6` from adapters | `disable_ipv6` sysctl |
| Hostnames next to remote IPs | Windows DNS cache | **not available** |
| Blocked-connection feed | `pfirewall.log` | `/var/log/ufw.log` (`[UFW BLOCK]`) |
| Rule list shows | only PrivateFirewall's rules | PrivateFirewall's **and** system ufw rules (system ones read-only, deliberately) |
| Elevation | app runs elevated (UAC) | one polkit (pkexec) authorization per session; read-only if declined, with an "Enable admin" retry button |
| System tray | ctypes Win32 tray | pystray (falls back to headless dashboard) |

Deliberate safety property of the Linux port: the root helper **whitelists ufw
verbs** and refuses `enable`/`disable`/`reset`, so nothing this app does — even
a bug — can switch the OS firewall off, remove the system SSH allow, or change
what Quick OS shipped enabled. Only `PFW`-tagged rules can be removed via the
app.

---

## Install — Linux (Quick OS / Ubuntu)

**Quick OS:** install from the App Store, or double-click the signed `.usi`
one-click installer from the [QuickOpen page](https://quickopen.ai/projects/private-firewall).

**Ubuntu 24.04 (apt repo):**

```sh
sudo curl -fsSL https://r2.quickopen.io/aiquick-apt/aiquick-archive-keyring.gpg -o /usr/share/keyrings/aiquick-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/aiquick-archive-keyring.gpg] https://r2.quickopen.io/aiquick-apt stable main" | sudo tee /etc/apt/sources.list.d/aiquick.list
sudo apt update && sudo apt install quickopen-private-firewall
```

Launch **Private Firewall** from the menu. The engine runs as your user; on
first privileged action it asks for ONE system authorization (polkit prompt —
the UAC analog). Decline it and the dashboard still works read-only. Per-user
state lives in `~/.local/share/PrivateFirewall/` (`config.json` + audit logs).

ufw stays exactly as your OS shipped it: enabled, deny-incoming,
allow-outgoing, SSH allowed. The app coexists with rules you (or the OS) made —
they are listed as *system* and cannot be touched from the app.

**Tray + start at login.** The app puts a shield in the system tray (green dot:
protection active; red: the system firewall is off) with Open Dashboard /
notifications toggle / Quit. After the first successful elevation it registers
an XDG autostart entry (`--tray --no-open`): at login you get the tray only, no
window, and **no password prompt** — the engine starts read-only and the first
action that actually modifies the firewall raises the polkit prompt, once per
session. Toggle in Settings → "start at login". Enforcement never depends on
the app: ufw enforces from boot whether or not the app is running. Launching
the app while it is already running raises the existing dashboard instead of
dying silently.

---

## Install — Windows

### From the QuickOpen signed installer (recommended)

Download **`PrivateFirewall-Setup.exe`** from the
[QuickOpen page](https://quickopen.ai/projects/private-firewall) or the
[GitHub release](https://github.com/quickpod/private-firewall/releases/latest)
and double-click it. It installs the pre-built engine and tooling, adds Desktop
and Start Menu shortcuts, optionally trusts the QuickOpen Root CA, and can
optionally arm boot-time default-deny. Because it controls the Windows firewall,
it requests **administrator** rights. The installer is Authenticode-signed by the
QuickOpen Code Signing CA — verify it at [quickopen.ai/trust](https://quickopen.ai/trust).
Uninstalling reverts every firewall rule, scheduled task and boot lockdown it
added (Add/Remove Programs), and offers to remove the CA.

### From source

**Easiest:** double-click **`Install.cmd`** and approve the UAC prompt. It builds
nothing — it installs the app with a Start Menu shortcut, a desktop shortcut, and
logon auto-start.

**From PowerShell** (for the standalone, Python-free app, build the exe first):

```powershell
.\Build-PrivateFirewall.ps1              # freeze pfw\ into dist\PrivateFirewall.exe
.\Setup-PrivateFirewall.ps1 -Install -Startup -Desktop -BootLockdown
```

`Setup-PrivateFirewall.ps1` self-elevates and:
- installs to `C:\Program Files\PrivateFirewall` (the frozen exe if built, else the
  Python source — runtime then needs `C:\Python313\python.exe`),
- puts logs + saved state under `C:\ProgramData\PrivateFirewall` (never in Program Files),
- creates Start Menu / desktop shortcuts that **launch the tray, elevated**,
- registers an **Add or remove programs** entry,
- enables Windows Firewall drop-logging (saving prior state),
- adds a **scoped Windows Defender exclusion** for the install dir + `PrivateFirewall.exe`
  (a self-built PyInstaller network tool trips Defender heuristics; the exclusion is
  removed again on uninstall so nothing is left behind),
- with `-Startup` / `-BootLockdown`: logon auto-start task (tray mode) and/or the
  persistent default-deny-outbound boot policy.

**Re-running the installer is a repair + update.** It overwrites the installed
files, refreshes the shortcuts / task / Defender exclusion, and **preserves your
settings** — autostart stays on if the logon task exists, and an install never
disarms boot lockdown. If the tray was running it is restarted on the new build.

### System-tray icon

Once installed, a **shield icon** sits in the system tray (it auto-starts at logon
if `-Startup` was used):

- **Double-click** — open the dashboard.
- **Right-click** — Open Dashboard · Enable/Disable lockdown · Mute alert popups ·
  Open logs folder · Copy dashboard link · Exit.
- The icon switches to a **warning glyph and raises a balloon** when a critical or
  serious alert fires (port scan, brute-force, …), unless muted.

The tray runs in-process with the engine (HTTP server on a background thread), so
it reads live state directly. It's pure `ctypes` (`Shell_NotifyIcon`) — no extra
Python packages.

**Permanently resident.** The engine ships as a **windowed exe (no console
window** — nothing to accidentally close and kill it). The installer registers a
logon task that runs elevated (no UAC at logon) with a **5-minute watchdog**: if
the engine ever exits or crashes, the next repetition relaunches it (a named-mutex
guard prevents duplicate instances). So it stays running across reboots and
crashes until you uninstall. The tray's **Exit** is for updates — the watchdog
brings it back within ~5 minutes.

### Update to a new version

```powershell
.\Update-PrivateFirewall.ps1                # git pull, rebuild exe, repair-install
.\Update-PrivateFirewall.ps1 -NoPull        # rebuild + reinstall current source
.\Update-PrivateFirewall.ps1 -Force         # reinstall even if versions match
```

The updater pulls the latest source (if this is a git checkout), rebuilds
`dist\PrivateFirewall.exe`, and re-runs the installer — which preserves autostart
and lockdown as above. Version is tracked in the Add/Remove Programs entry, so it
reports the before/after version and skips work when already current.

### Uninstall (removes all traces)

```powershell
.\Setup-PrivateFirewall.ps1 -Uninstall            # keeps audit logs
.\Setup-PrivateFirewall.ps1 -Uninstall -PurgeData # also deletes C:\ProgramData logs
```

Also available from **Add or remove programs**. Uninstall stops the tray/engine,
then removes: shortcuts, the logon task, the `PFW_LOG_DIR` machine variable, the
Add/Remove Programs entry, the Defender exclusion, all PrivateFirewall firewall
rules, any lockdown (restored to Allow), drop-logging (restored to prior state),
and the install directory. It then **reports anything that could not be removed**
(e.g. a file still in use) so nothing is silently left behind. Audit logs under
`C:\ProgramData\PrivateFirewall` are kept unless `-PurgeData` is given.

## Run without installing

```powershell
.\Start-PrivateFirewall.ps1                 # self-elevates; prefers dist\ exe, else Python
.\Install-PrivateFirewall.ps1 -BootLockdown -Startup   # boot enforcement only
.\Revert-PrivateFirewall.ps1                # read-only status (no elevation)
.\Revert-PrivateFirewall.ps1 -Revert -Uninstall        # undo firewall changes + task
```

The dashboard binds to `127.0.0.1` only and requires a random per-launch token
(embedded in the URL the launcher prints). Nothing is exposed to the network.

Python (for building, or source-mode runtime) is expected at
`C:\Python313\python.exe` — not on PATH by design on this machine, since the bare
`python`/`py` commands resolve to the Store stub.

---

## Features

### Live dashboard
- **Stat tiles:** download / upload (with peak), active connections, connections
  to public IPs, listening ports, blocked-today, open alerts, outbound policy.
- **Throughput chart:** 8-minute inbound/outbound area chart with hover crosshair.
- **Top talkers:** active connections aggregated by process.
- **Connection table:** every TCP/UDP endpoint with process + full image path,
  PID, local/remote, scope tag (public/private/loopback), state; sortable and
  filterable; hide-loopback / established-only toggles.
- **Live event feed:** new connections, firewall drops, and control actions.
- **Aura light & dark:** the QuickOpen design system, same palette and accent
  beam as every other QuickOpen app. Follows the browser/desktop light-dark
  setting by default; the **Theme** button in the header pins
  *System / Dark / Light* (remembered in that browser, never sent to the
  engine).

### Controls (require elevation)
- **Kill** an established TCP/IPv4 connection (`SetTcpEntry` DELETE_TCB).
- **Block IP** — inbound + outbound block rule for an address.
- **Block / Allow app** — outbound rule scoped to a program's exe path.
- **Lockdown toggle** — zero-trust default-deny outbound at runtime (DNS + DHCP
  stay allowed so the network layer keeps working).
- **Rule manager** — every rule PrivateFirewall created, one-click removable.

### Editable profile (`config.json`)

Everything tunable lives in an editable profile at
`C:\ProgramData\PrivateFirewall\config.json`, written with laptop-sensible
defaults on first run. Edit it in the dashboard's **Settings** panel (validates
and applies live) or on disk (the engine hot-reloads it). Missing keys fall back
to defaults, so partial edits and upgrades are safe. It controls:

- **Alert thresholds + which alerts are on** (port-scan ports/window, brute-force,
  fan-out, upload MB/s, and toggles for new-listener / plaintext-DNS /
  suspicious-path / ARP-spoof).
- **Auto-block**: automatically block scanners/brute-forcers for a TTL (default:
  block port-scanners for 60 min, then the rule auto-expires).
- **Notifications**: **off by default (opt-in)** — master enable, popup
  style, minimum severity (default `serious`), and origin categories
  (internet vs local-network sources; local is off by default). Even when
  enabled, link-local / ICMPv6 / multicast background chatter is classified as
  background noise and never alerted — and "port 0" never appears anywhere;
  the protocol name (ICMPv6, IGMP, …) is shown instead.
- **Per-network profiles** (`Public` / `Private` / `Domain`): applied
  automatically when the network category changes. A travelling laptop tightens
  up on untrusted **Public** Wi-Fi (auto-block on, lower notification bar) and
  relaxes at home — editable per category.
- **Trusted IPs / subnets** never alerted on or auto-blocked.

### New laptop-focused capabilities

- **Location-aware hardening** — the active network profile is shown in the
  header and applied on every network change (strictest category wins).
- **Auto-block with expiry** — scanners are blocked automatically and the timed
  rules (`PFW AutoBlock … until <epoch>`) are reaped when they expire; you can
  also block any IP for N minutes.
- **Hostnames** — connections are annotated with the resolved DNS name (from the
  Windows DNS client cache), shown under each remote IP.
- **ARP-spoof / MITM detection** — watches the default gateway's MAC and alerts
  (critical) if it changes or is shared with another host, the classic
  public-Wi-Fi man-in-the-middle signal.

### Alert engine (`pfw/server.py :: AlertEngine`)
Sliding-window heuristics with per-signature cooldown:

| Alert | Trigger | Severity |
|---|---|---|
| **port-scan** | ≥8 distinct dropped inbound ports from one source / 60 s | critical |
| **brute-force** | ≥15 drops to the same port from one source / 5 min | serious |
| **suspicious-path** | network activity from `Temp\`, `Downloads\`, `Public\`, recycle bin | serious |
| **new-listener** | a process starts accepting inbound on a new port | warning |
| **plaintext-dns** | TCP to `:53` on a public IP (bypasses the DoH chain) | warning |
| **fan-out** | one process hits ≥30 distinct public IPs / 5 min (scan/C2/exfil) | warning |
| **upload-surge** | sustained >4 MB/s upstream for ~60 s | warning |

Port-scan and brute-force detection read the Windows Firewall **drop log**, so
they require drop-logging (armed automatically by `Start-PrivateFirewall.ps1`,
or `Revert-PrivateFirewall.ps1 -Apply`). Every alert and event is also written
to `logs/*.jsonl` for an audit trail.

---

## Files

| File | Role |
|---|---|
| `pfw/server.py` | localhost engine: snapshots, stats, controls, alert engine, JSON API, `--tray` |
| `pfw/config.py` | editable profile: defaults, deep-merge loader, validation, hot-reload |
| `pfw/tray.py` | system-tray icon (ctypes `Shell_NotifyIcon`): menu, balloon alerts, live state |
| `pfw/dashboard.html` | single-page dashboard (vanilla JS, inline SVG charts, no build) |
| `Install.cmd` | double-click bootstrap → runs the installer elevated |
| `Setup-PrivateFirewall.ps1` | **installer/uninstaller**: files, shortcuts, ARP entry, Defender exclusion, task, logging; re-run = repair+update |
| `Update-PrivateFirewall.ps1` | **updater**: git pull → rebuild → repair-install, preserving settings |
| `Build-PrivateFirewall.ps1` | freeze the engine into `dist\PrivateFirewall.exe` (PyInstaller) |
| `Start-PrivateFirewall.ps1` | self-elevating launcher; `-Tray` for tray mode; arms drop-logging |
| `Install-PrivateFirewall.ps1` | `-BootLockdown` (persistent default-deny) · `-Startup` (logon task, tray) |
| `Revert-PrivateFirewall.ps1` | status (no switch) · `-Apply` · `-Revert [-Uninstall]` |

All dynamic rules live in the WFP rule group **`PrivateFirewall`**, so revert is
a single group delete and can never touch a rule you authored elsewhere. Revert
restores `DefaultOutboundAction = Allow` unconditionally, so a stale state file
can never strand the machine with outbound blocked.

---

## Roadmap

Design and capability targets tracked in [FEATURES.md](FEATURES.md). Near-term:

- **DNS/domain visibility** — correlate connections to hostnames (ETW DNS
  client events) so blocks and alerts can be by-domain, not only by-IP.
- **GeoIP** on remote addresses + country-based alerting/blocking.
- **Reputation/threat-intel feeds** — match remote IPs against a local blocklist.
- **ETW real-time flow events** (`Microsoft-Windows-Kernel-Network`) to replace
  the 2 s polling loop with push, and to measure per-process byte counts.
- **Signed-binary / reputation** column for the connection table.
- **Optional WFP callout driver** for true per-flow inspection (kernel component;
  currently out of scope to keep this driver-free and fail-open).

## Safety notes

- Read-only monitoring needs no elevation; only kill/block/lockdown do.
- Boot lockdown installs a **starter allowlist** (DNS, DHCP, NLA/NCSI, time)
  before flipping the default, so the network still comes up. Add more with the
  dashboard or `-AllowService`.
- Built on a laptop that travels and hits captive portals; lockdown keeps DNS +
  DHCP open so portals still resolve. Revert needs no network.

## License

Apache-2.0 — see [LICENSE](LICENSE). PrivateFirewall is a 100% AI-built project published on QuickOpen; the only human involvement is testing and guidance.


---

## Troubleshooting (both platforms)

The dashboard's **Help** button (or `F1`) covers all of this in-app, in both
Aura themes. Highlights:

- **Read-only banner** — Windows: relaunch elevated (Start Menu shortcut).
  Linux: click *Enable admin* and authorize the polkit prompt.
- **Rule not taking effect** — already-open connections keep running until
  closed (use *kill*); on Linux the first matching rule wins and PrivateFirewall
  places its blocks at the top.
- **Locked out of SSH (Linux)** — PrivateFirewall never removes the system SSH
  rule and cannot disable ufw; a lockout can only come from a rule you added.
  From the machine's console: `sudo ufw status numbered`, then
  `sudo ufw delete <number>`.
- **"System firewall inactive" (Linux)** — `sudo ufw enable` (Quick OS ships it
  enabled; the app itself will never toggle it).
- **Why blocked "local traffic" in the feed?** — routers/phones/virtual
  adapters constantly announce themselves (IPv6 NDP, multicast, IGMP); a
  deny-incoming firewall drops that chatter as a matter of course. It is shown
  dimmed as background, never counted or alerted as an attack.
- **No popups** — that's the default. Notifications are opt-in: Settings →
  Desktop notifications.
