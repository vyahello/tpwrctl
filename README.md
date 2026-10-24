<div align="center">

# 📡 tpwrctl

**A command-line remote control for the TP-Link TL-WR850N — a router that laughs at the idea of SSH.**

<img src="assets/tl-wr850n.jpg" alt="TP-Link TL-WR850N" width="300"/>

![python](https://img.shields.io/badge/python-3.8+-3776AB?logo=python&logoColor=white)
![platform](https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&logoColor=black)
![target](https://img.shields.io/badge/target-TL--WR850N%20v3-E6322E)
![ssh](https://img.shields.io/badge/SSH-404%20not%20found-critical)
![talks](https://img.shields.io/badge/speaks-HTTP%20%2F%20cgi%20%2B%20telnet-2ea44f)
![license](https://img.shields.io/badge/license-MIT-blue)

</div>

---

## 🤔 Why does this exist?

This little N300 router has **no SSH**, a web UI nobody wants to click through, and a telnet
console that is *not even a real shell*. So `tpwrctl` does the clicking for you: it logs
into the router's web interface, speaks its native (undocumented) `/cgi` protocol, and gives
you clean, scriptable commands. It can also drive the hidden telnet CLI when that's the only
place a setting lives.

> 🔒 Built for **your own** router. It's an N300 running embedded Linux from **2019** — be nice to it.

## 🚀 Quick start

```bash
tpwrctl status        # everything at a glance
tpwrctl devices       # who's on my network?
tpwrctl audit         # am I owned?
```

First run will ask for the admin password (or save it once with `tpwrctl config`).
Credentials resolve from `--password` → `$ROUTER_PASS` → `~/.config/tpwrctl/config.json` → prompt.

## 🧰 Commands

### Over the web UI (the main path — always available)
| Command | What it does |
|---|---|
| `status` | Model, firmware, WAN, public IP, CPU, online devices — one screen |
| `devices [--online]` | Every device: name, IP, MAC, wired/Wi-Fi, signal |
| `wifi` | Show AP config (SSID, security, **password**) + clients |
| `wifi --ssid/--password/--bandwidth/--radio` | **Change Wi-Fi** (confirms first; `--dry-run` to preview) |
| `wan` | Internet connection details (IP, DNS, NAT, firewall) |
| `speed [--interval N]` | Live per-client Wi-Fi throughput |
| `cpu` | CPU usage + approximate uptime |
| `firmware` | Firmware version + update advice |
| `audit` | 🔎 Security audit — port exposure + config findings |
| `reboot [-y]` | Reboot (asks first; `-y` to skip) |
| `oids` | 📖 Catalog of web-API objects you can `get`/`set` |
| `get <OID> [attrs] [--gl] [--stack S] [--json]` | **General read** — any object, friendly or JSON |
| `set <OID> attr=val ... [--stack S]` | **General write** — change any setting |
| `blocklist` | Show Access Control state + blocked devices |
| `block <MAC> [--name N] [--dry-run] [-y]` | **Block a device** by MAC (Access Control blacklist) |
| `unblock <MAC> [--dry-run]` | Remove a device from the block list |
| `config --password ...` | Save host + password (mode 600) |

**Change Wi-Fi over the web** (the web-UI alternative to `telnet wlctl set`):
```bash
tpwrctl wifi --dry-run --ssid MyNet --password 'secret123'   # preview — sends nothing
tpwrctl wifi --password 'secret123'                          # set the key (asks to confirm)
tpwrctl wifi --bandwidth 20M                                 # Auto | 20M | 40M
tpwrctl wifi --radio off                                     # turn the radio off/on
```
> ⚠️ Changing Wi-Fi restarts the radio — connected clients drop for a few seconds.

**Kick / block unknown devices** (Access Control blacklist — works for wired *and* wireless):
```bash
tpwrctl devices --online                       # find the unknown device's MAC
tpwrctl block AA:BB:CC:DD:EE:FF                 # labels it with the device hostname if known
tpwrctl block AA:BB:CC:DD:EE:FF --name "Kitchen TV"   # or give it your own label
tpwrctl blocklist                              # see what's blocked
tpwrctl unblock AA:BB:CC:DD:EE:FF              # let it back on
```
> Tip: if you don't know which clients are legit, rotating the Wi-Fi key (`tpwrctl wifi --password …`) boots everyone at once; blocking is the surgical option. Note that phones with MAC randomization can reappear under a new MAC.

### Over the telnet CLI (for the few settings only it exposes)
| Command | What it does |
|---|---|
| `telnet <cmd...>` | Run a CLI command (quotes optional), output nicely formatted |
| `telnet --list` | 📖 Telnet CLI command reference |
| `telnet --raw <cmd...>` | Show the router's unprocessed text |
| `telnet -y dev reset` | Destructive commands are guarded (`-y` required) |

```bash
tpwrctl telnet dev serial show     # note: 'dev serial' alone isn't complete
tpwrctl telnet wlctl show
```

**Two general tools, two transports:** `get`/`set` (+ `oids`) for the web API, and
`telnet` (+ `telnet --list`) for the CLI. Use `oids` / `telnet --list` to discover what's available.

### Over TR-069 / CWMP (true remote management, from anywhere)
Point the router at a [GenieACS](deploy/genieacs/) server (e.g. on a cloud VM); then manage it
remotely — no LAN access needed. `tpwrctl acs …` drives the ACS's REST API.

| Command | What it does |
|---|---|
| `acs devices` | Devices (CPEs) the ACS manages, last inform, still informing or silent |
| `acs status [--refresh]` | One screen: model, firmware, uptime, WAN, Wi-Fi, clients — each with its age |
| `acs clients [--online] [--refresh]` | LAN hosts: name, IP, MAC, lease left, online |
| `acs wifi [--refresh]` | Wi-Fi: SSID, radio, channel, band, security, **password** |
| `acs wifi --ssid/--password/--channel/--bandwidth/--radio` | Change Wi-Fi (confirms; `--dry-run` previews), then read it back |
| `acs wan [--refresh]` / `acs firmware [--refresh]` | WAN details / model, firmware, serial, uptime |
| `acs reboot [-y]` | Reboot **and wait until the router reports back** (~1 min) |
| `acs get <param>` | Read a parameter — or a whole subtree, e.g. `DeviceInfo.` — fresh from the router (`--cached`: no round trip) |
| `acs set <param> <value>` | Write with the right TR-069 type, then read it back (`--dry-run`; refuses unknown/read-only) |
| `acs params [prefix] [--grep RE] [-l]` | List cached parameters (`-l`: type, rw/ro, age) |
| `acs refresh [--object O]` | Re-read parameters (default: the whole tree) |
| `acs inform [--interval N]` | When the router informs (= when queued tasks run); change the interval |
| `acs tasks [--clear]` | Queued tasks and faults; `--clear` cancels them |

Paths work with or without the root (`DeviceInfo.UpTime` = `InternetGatewayDevice.DeviceInfo.UpTime`).

**How it behaves behind NAT.** The ACS can't reach the router on demand (its connection-request
URL is a private address), so every task runs at the router's **next periodic inform**. Writes
wait for that with a countdown, then confirm: `set`/`wifi`/`inform` read the value back in the
same session, `reboot` waits for the BOOT inform, and a fault the router returns is shown and its
task deleted (so GenieACS doesn't retry it forever). `--no-wait` only queues; Ctrl-C leaves the
task queued (`acs tasks`). Reads show the ACS's cached values with their age; `--refresh` re-reads
first. Use `acs inform --interval 60` so tasks run within a minute (default 300 s).

**Passwords.** TR-069 never reads secrets back (the Wi-Fi key, like every password, reads empty).
`acs wifi --password` therefore remembers the key it set in `~/.config/tpwrctl/acs-secrets.json`
(mode 600) on the ACS host, and `acs wifi` shows it with when it was set. A key changed some other
way (LAN `wifi --password`, the web UI) isn't seen by the ACS — set it once through `acs` again.

**Blocking over TR-069 isn't supported on this router.** Access Control (wired+wireless) isn't in
the data model, and the wireless MAC-filter table faults on writes (`SetParameterValues`→9003,
`DeleteObject`→7501), so a per-MAC block can't be applied remotely.

> ⚠️ **Never `AddObject` on `WLANConfiguration.1.X_TP_MACTableEntry.`** It *succeeds*, but the
> new row can't be filled in or deleted, and one blank row makes the firmware fail every
> Wi-Fi read (`wifi` → error 1). After the next reboot the access point is gone. No API
> (web, TR-069, telnet) can remove the row; the only way out is a factory reset (Reset button,
> or the web UI's Factory Restore — telnet `dev reset` is a no-op), then reconfigure.

Working alternatives:
`acs wifi --password <new>` (rotate the key — kicks all Wi-Fi clients), `acs wifi --radio off`
(turn Wi-Fi off), or the LAN-side `block <MAC>` for targeted wired+wireless blocking.

```bash
tpwrctl set MANAGEMENT_SERVER URL=http://<VM_IP>:7547/   # one-time: aim the router at the ACS
tpwrctl acs inform --interval 60                         # tasks then run within a minute
tpwrctl acs status --refresh
tpwrctl acs reboot
```
Setup and deployment: **[deploy/genieacs/README.md](deploy/genieacs/README.md)**. The NBI is
localhost-only, so run `acs` commands on the ACS host (or set `--acs-url` / `$TPWRCTL_ACS`).

## ✨ Looks like

```
$ tpwrctl status
Model        : TL-WR850N  (hw TL-WR850N v3 00000003)
Firmware     : 3.16.0 0.9.1 v6040.0 Build 191011 Rel.63822n   [built 2019-10-11]
WAN          : Connected  via IP_Routed
Public IP    : 203.0.113.x
CPU usage    : 3%
Devices      : 5 online  (8 known)
   MacBookPro             192.168.1.x     aa:bb:cc:dd:ee:ff Wi-Fi   -52dBm 144Mbps 11n
   ...
```

## 🧬 How it works

No SSH exists, so everything rides the **web admin interface (port 80)**:

- **Login** (reverse-engineered from the router's own JS): salt `ss` from `POST /cgi/getParm`,
  then `POST /cgi/login?UserName=MD5(ss+"admin"+ss)&Passwd=MD5(ss+base64(pw)+ss)`. Success
  yields a `JSESSIONID` cookie + a page token.
- **Data**: `POST /cgi?<act>` with header `TokenID: <token>` and a body of
  `[OID#stack#pstack]<idx>,<n>` lines (`1`=GET, `2`=SET, `5`=list, `7`=reboot). Replies come
  back as `key=value`, parsed into dicts.
- **Telnet** is a bonus transport: a proprietary `TP-Link(conf)#` command tree (not a shell —
  no `cat`/`ls`), one session at a time, plaintext.

## 🛡️ Security notes (from `tpwrctl audit`)

This firmware is old and the box is chatty. Headline findings: 2019 firmware with WR840N-family
CVEs, TR-069/CWMP listening on `:7547`, UPnP on, telnet open. Remote web management is **off**
(good). Run `tpwrctl audit` for the live list. You can harden with `set` (e.g.
`set UPNP_CFG enable=0`).

## ⚠️ Caveats
- The web UI allows **one session at a time** — logging in here may bump a browser session.
- 5 wrong passwords = ~10-minute lockout. Don't brute-force your own router. 🙂
- `reboot`, `set`, and `telnet` write operations change device state — use with intent.
- Telnet is plaintext; `wlctl show` prints your Wi-Fi key. Treat the LAN accordingly.

---

<div align="center">
<sub>Made with ☕ and packet captures · talks to a MIPS box running Linux 2.6-ish · no routers were harmed</sub>
</div>
