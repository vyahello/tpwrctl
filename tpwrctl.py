#!/usr/bin/env python3
"""
tpwrctl - CLI for TP-Link TL-WR850N v3 (and WR840N-family, firmware 3.16.x / "tpweb" UI).

Talks to the router's HTTP admin interface using its native /cgi ACT protocol,
reverse-engineered from the device's own JavaScript:

  login : POST /cgi/login?UserName=MD5(ss+"admin"+ss)&Passwd=MD5(ss+base64(pw)+ss)&Action=1
          (ss = salt from POST /cgi/getParm)  -> JSESSIONID cookie + page token
  data  : POST /cgi?<act>   body: [OID#stack#pstack]<idx>,<n>\r\n<attr>\r\n...
          header TokenID: <token from post-login page>   (acts: 1=GET 2=SET 5=GL 7=OP)

No SSH exists on this model; this uses the always-on web UI (port 80).
"""
import sys, os, re, json, time, argparse, hashlib, base64, socket, getpass, calendar, ipaddress

try:
    import requests
except ImportError:
    sys.exit("requires 'requests'  ->  pip install requests")

ACT_GET, ACT_SET, ACT_ADD, ACT_DEL, ACT_GL, ACT_GS, ACT_OP, ACT_CGI = 1, 2, 3, 4, 5, 6, 7, 8
CONF = os.path.expanduser("~/.config/tpwrctl/config.json")


# ----------------------------------------------------------------------------- client
class Router:
    def __init__(self, host, password, username="admin", timeout=8):
        self.host = host.rstrip("/")
        if not self.host.startswith("http"):
            self.host = "http://" + self.host
        self.password, self.username, self.timeout = password, username, timeout
        self.s = requests.Session()
        self.s.headers.update({"Referer": self.host + "/", "User-Agent": "tpwrctl",
                               "Content-Type": "text/plain"})

    @staticmethod
    def _menc(val, salt):                      # $.md5.encrypt(val, ss) == MD5(ss+val+ss)
        return hashlib.md5((salt + val + salt).encode()).hexdigest()

    def login(self):
        self.s.get(self.host + "/", timeout=self.timeout)
        r = self.s.post(self.host + "/cgi/getParm", timeout=self.timeout)
        m = re.search(r'var ss="(.*?)"', r.text)
        if not m:
            raise RuntimeError("could not read login salt (is the host a TL-WR850N?)")
        ss = m.group(1)
        name = self._menc(self.username, ss)
        auth = self._menc(base64.b64encode(self.password.encode()).decode(), ss)
        lr = self.s.post("%s/cgi/login?UserName=%s&Passwd=%s&Action=1&LoginStatus=0"
                         % (self.host, name, auth), timeout=self.timeout)
        if "$.ret=0" not in lr.text:
            code = (re.search(r"\$\.ret=(\d+)", lr.text) or [None, "?"])[1]
            raise RuntimeError("login failed (code %s) - wrong password or account locked "
                               "(5 bad tries = 10 min lockout)" % code)
        idx = self.s.get(self.host + "/", timeout=self.timeout).text
        t = re.search(r'var token="([A-Za-z0-9]+)"', idx)
        if not t:
            raise RuntimeError("logged in but no session token found")
        self.s.headers["TokenID"] = t.group(1)
        return self

    def logout(self):
        try:
            self.s.post(self.host + "/cgi/logout", timeout=4)
        except Exception:
            pass

    def __enter__(self):
        return self.login()

    def __exit__(self, *a):
        self.logout()

    def cgi(self, ops):
        url = self.host + "/cgi?" + "&".join(str(o["action"]) for o in ops)
        body = ""
        for i, o in enumerate(ops):
            st, ps = o.get("stack") or "0,0,0,0,0,0", o.get("pstack") or "0,0,0,0,0,0"
            at = o.get("attrs")
            if at is None:
                a, n = "", 0
            elif isinstance(at, dict):
                L = ["%s=%s" % (k, v) for k, v in at.items()]; a, n = "\r\n".join(L) + "\r\n", len(L)
            else:
                L = list(at); a, n = "\r\n".join(L) + "\r\n", len(L)
            body += "[%s#%s#%s]%d,%d\r\n%s" % (o["oid"], st, ps, i, n, a)
        r = self.s.post(url, data=body, timeout=self.timeout)
        return self._parse(r.text, ops)

    @staticmethod
    def _parse(text, ops):
        res = [([] if o["action"] in (ACT_GL, ACT_GS) else {}) for o in ops]
        inst, err = None, 0
        for raw in text.split("\n"):
            line = raw.rstrip("\r")
            if not line:
                continue
            if line[0] == "[":
                n = line.find("]"); stack = line[1:n]; tail = line[n + 1:].strip()
                if stack == "error":
                    c = tail.split(",")[0]
                    if c.lstrip("-").isdigit() and int(c) != 0:
                        err = int(c)
                    continue
                j = int(tail.split(",")[0]) if tail and tail.split(",")[0].lstrip("-").isdigit() else 0
                if j < len(res):
                    if isinstance(res[j], list):
                        inst = {"__stack": stack}; res[j].append(inst)
                    else:
                        inst = res[j]; inst["__stack"] = stack
            elif inst is not None:
                k, _, v = line.partition("="); inst[k] = v
        if err:
            raise RuntimeError("router returned error code %d" % err)
        return res

    # convenience
    def get(self, oid, attrs=None, stack=None):
        return self.cgi([{"action": ACT_GET, "oid": oid, "attrs": attrs, "stack": stack}])[0]

    def getlist(self, oid, stack=None):
        return self.cgi([{"action": ACT_GL, "oid": oid, "stack": stack}])[0]

    def op(self, oid):
        return self.cgi([{"action": ACT_OP, "oid": oid}])[0]

    def set(self, oid, attrs, stack=None):
        return self.cgi([{"action": ACT_SET, "oid": oid, "attrs": attrs, "stack": stack}])[0]


# ----------------------------------------------------------------------------- helpers
def _fw_date(ver):
    m = re.search(r"Build (\d{2})(\d{2})(\d{2})", ver or "")
    return "20%s-%s-%s" % (m.group(1), m.group(2), m.group(3)) if m else "?"


def _fmt_uptime(proc):
    """Uptime from PROC_STATUS X_TP_TotalTime (kernel CPU time, 1/100 s), or None."""
    tt = proc.get("X_TP_TotalTime", "")
    if not tt.isdigit():
        return None
    secs = int(tt) // 100
    d, rem = divmod(secs, 86400)
    h, m = divmod(rem, 3600)[0], (rem % 3600) // 60
    return "%dd %dh %dm" % (d, h, m) if d else "%dh %dm" % (h, m)


def _macnorm(m):
    return (m or "").upper().replace("-", ":")


def _confirm(prompt):
    """y/N question; 'y' or 'yes' confirms, anything else (or no TTY) declines."""
    try:
        return input(prompt + " [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


def _wifi_sec(ap):
    """Human-readable Wi-Fi security mode from a LAN_WLAN entry (uses beaconType)."""
    bt = ap.get("beaconType", "")
    enc = ap.get("IEEE11iEncryptionModes", "") or ap.get("WPAEncryptionModes", "")
    cipher = "AES" if ("AES" in enc and "TKIP" not in enc) else ("TKIP+AES" if "AES" in enc else "TKIP")
    psk = "PSKAuthentication" in (ap.get("IEEE11iAuthenticationMode", ""), ap.get("WPAAuthenticationMode", ""))
    kind = "PSK" if psk else "Enterprise"
    if bt == "Basic":
        return "Open (no password)" if ap.get("basicEncryptionModes") == "None" else "WEP"
    if bt == "WPA":
        return "WPA-%s (%s)" % (kind, cipher)
    if "WPAand11i" in bt:
        return "WPA/WPA2-%s (%s)" % (kind, cipher)
    if bt == "11i":
        return "WPA2-%s (%s)" % (kind, cipher)
    return "WPA2-%s (%s)" % (kind, cipher) if psk else "Open/Unknown"


def devices(r):
    hosts = r.getlist("LAN_HOST_ENTRY")
    try:
        assoc = {_macnorm(a.get("associatedDeviceMACAddress")): a
                 for a in r.getlist("LAN_WLAN_ASSOC_DEV")}
    except Exception:
        assoc = {}
    out = []
    for h in hosts:
        mac = _macnorm(h.get("MACAddress"))
        a = assoc.get(mac)
        active = h.get("active") == "1"
        # The router only knows the link type while a host is online (X_TP_ConnType reads 0,
        # i.e. "wired", for every offline host), so don't guess for offline ones.
        if a or (active and h.get("X_TP_ConnType") == "1"):
            conn = "Wi-Fi"
        else:
            conn = "Wired" if active else "-"
        out.append({
            "name": h.get("hostName", "Unknown"),
            "ip": h.get("IPAddress", ""),
            "mac": mac,
            "conn": conn,
            "active": active,
            "signal": (a or {}).get("X_TP_StaSignalStrength", ""),
            "linkrate": (a or {}).get("X_TP_StaConnectionSpeed", ""),
            "std": (a or {}).get("X_TP_StaStandard", ""),
            "lease": h.get("leaseTimeRemaining", ""),
        })
    return out


# ----------------------------------------------------------------------------- commands
def cmd_status(r, args):
    info = r.get("IGD_DEV_INFO", ["modelName", "description", "softwareVersion", "hardwareVersion"])
    wan = (r.getlist("WAN_IP_CONN") or [{}])[0]
    try:
        proc = r.get("PROC_STATUS", ["CPUUsage", "X_TP_TotalTime"])
    except Exception:
        proc = {}
    cpu = proc.get("CPUUsage", "?")
    uptime = _fmt_uptime(proc) or "?"
    devs = devices(r)
    on = [d for d in devs if d["active"]]
    print("Model        : %s  (hw %s)" % (info.get("modelName"), info.get("hardwareVersion")))
    print("Firmware     : %s   [built %s]" % (info.get("softwareVersion"), _fw_date(info.get("softwareVersion"))))
    print("Uptime       : %s" % uptime)
    print("WAN          : %s  via %s" % (wan.get("connectionStatus", "?"), wan.get("connectionType", "?")))
    print("Public IP    : %s" % wan.get("externalIPAddress", "?"))
    print("Gateway/DNS  : %s  /  %s" % (wan.get("defaultGateway", "?"), wan.get("DNSServers", "?")))
    print("CPU usage    : %s%%" % cpu)
    print("Devices      : %d online  (%d known)" % (len(on), len(devs)))
    for d in on:
        extra = ("  %sdBm %sMbps %s" % (d["signal"], d["linkrate"], d["std"])) if d["conn"] == "Wi-Fi" else ""
        print("   %-22s %-15s %-17s %-6s%s" % (d["name"][:22], d["ip"], d["mac"], d["conn"], extra))


def cmd_devices(r, args):
    all_devs = devices(r)
    devs = [d for d in all_devs if d["active"]] if args.online else all_devs
    print("%-24s %-15s %-17s %-6s %-7s %-8s %s" % ("NAME", "IP", "MAC", "CONN", "SIGNAL", "LINK", "STATE"))
    for d in sorted(devs, key=lambda x: (not x["active"], x["conn"])):
        print("%-24s %-15s %-17s %-6s %-7s %-8s %s" % (
            d["name"][:24], d["ip"], d["mac"], d["conn"],
            (d["signal"] + "dBm") if d["signal"] else "-",
            (d["linkrate"] + "M") if d["linkrate"] else "-",
            "online" if d["active"] else "offline"))
    print("\n%d online / %d known" % (sum(d["active"] for d in all_devs), len(all_devs)))


def cmd_wan(r, args):
    w = (r.getlist("WAN_IP_CONN") or [{}])[0]
    for k in ["connectionStatus", "connectionType", "addressingType", "externalIPAddress",
              "subnetMask", "defaultGateway", "DNSServers", "MACAddress", "NATEnabled",
              "X_TP_FirewallEnabled", "maxMTUSize", "name"]:
        if k in w:
            print("%-22s %s" % (k, w[k]))


def _wlan_load(r):
    """The main LAN_WLAN entry. Blank wireless MAC-filter rows (e.g. left by a TR-069 AddObject
    on X_TP_MACTableEntry) make the firmware fail every LAN_WLAN read with error 1; say so."""
    try:
        return (r.getlist("LAN_WLAN") or [{}])[0]
    except RuntimeError:
        blank = [e for e in r.getlist("LAN_WLAN_MACTABLEENTRY") if not e.get("MACAddress")]
        if blank:
            raise RuntimeError("router can't load its Wi-Fi config: %d blank wireless MAC-filter "
                               "row(s) (LAN_WLAN_MACTABLEENTRY stack %s) break it"
                               % (len(blank), ", ".join(e["__stack"] for e in blank)))
        raise


def _wifi_set(r, args, changes):
    """Apply changes to the main Wi-Fi radio (LAN_WLAN), using its real stack."""
    ap = _wlan_load(r)
    stack = ap.get("__stack") or "1,1,0,0,0,0"
    print("Wi-Fi changes on SSID '%s' (stack %s):" % (ap.get("SSID", "?"), stack))
    for k, v in changes.items():
        print("  %-18s -> %s" % (k, v))
    print("\n\033[33m! This restarts the radio; Wi-Fi clients will briefly disconnect.\033[0m"
          if sys.stdout.isatty() else "\n! This restarts the radio; Wi-Fi clients will briefly disconnect.")
    if args.dry_run:
        print("(dry-run: nothing sent)")
        return
    if not args.yes and not _confirm("Apply?"):
        print("aborted.")
        return
    r.cgi([{"action": ACT_SET, "oid": "LAN_WLAN", "stack": stack, "attrs": changes}])
    print("applied.")


def cmd_wifi(r, args):
    # If any set-flag was given, change settings instead of showing them.
    changes = {}
    if getattr(args, "ssid", None) is not None:
        changes["SSID"] = args.ssid
    if getattr(args, "psk", None) is not None:
        changes["X_TP_PreSharedKey"] = args.psk
    if getattr(args, "bandwidth", None) is not None:
        changes["X_TP_Bandwidth"] = args.bandwidth
    if getattr(args, "radio", None) is not None:
        changes["enable"] = "1" if args.radio == "on" else "0"
    if changes:
        return _wifi_set(r, args, changes)

    # Otherwise: show access-point config (SSID + security + password) + clients.
    ap = _wlan_load(r)
    print("Access point")
    print("  SSID       : %s" % ap.get("SSID", "?"))
    print("  Status     : %s" % ap.get("status", "?"))
    print("  Band       : %s, channel %s%s" % (
        ap.get("X_TP_Band", "?"), ap.get("channel", "?"),
        " (auto)" if ap.get("autoChannelEnable") == "1" else ""))
    print("  Bandwidth  : %s" % ap.get("X_TP_Bandwidth", "?"))
    print("  Security   : %s" % _wifi_sec(ap))
    print("  Password   : %s" % (ap.get("X_TP_PreSharedKey", "") or "(none/open)"))
    # Associated clients, named from the DHCP host table (same source as `devices`).
    a = r.getlist("LAN_WLAN_ASSOC_DEV")
    hosts = {_macnorm(h.get("MACAddress")): h for h in r.getlist("LAN_HOST_ENTRY")}
    print("\nClients (%d):" % len(a))
    if a:
        print("  %-20s %-15s %-17s %-7s %-8s %-4s %-6s %s" % (
            "NAME", "IP", "MAC", "SIGNAL", "LINK", "STD", "BW", "TX/RX"))
    for d in a:
        mac = _macnorm(d.get("associatedDeviceMACAddress"))
        h = hosts.get(mac, {})
        print("  %-20s %-15s %-17s %-7s %-8s %-4s %-6s %s/%s" % (
            h.get("hostName", "Unknown")[:20], h.get("IPAddress", "-"), mac,
            d.get("X_TP_StaSignalStrength", "") + "dBm",
            d.get("X_TP_StaConnectionSpeed", "") + "M",
            d.get("X_TP_StaStandard", ""), d.get("X_TP_StaBandWidth", "").strip(),
            d.get("X_TP_TxRate", "?"), d.get("X_TP_RxRate", "?")))


def cmd_speed(r, args):
    """Live per-client Wi-Fi throughput, sampled from station byte counters."""
    def snap():
        return {_macnorm(d.get("associatedDeviceMACAddress")):
                (int(d.get("X_TP_TotalBytesSent", 0)), int(d.get("X_TP_TotalBytesReceived", 0)))
                for d in r.getlist("LAN_WLAN_ASSOC_DEV")}
    a = snap(); time.sleep(args.interval); b = snap()
    print("Wi-Fi throughput over %ss (Tx = from router to client):" % args.interval)
    tt = tr = 0.0
    for mac, (s2, r2) in b.items():
        s1, r1 = a.get(mac, (s2, r2))
        tx = max(0, s2 - s1) * 8 / 1e6 / args.interval
        rx = max(0, r2 - r1) * 8 / 1e6 / args.interval
        tt += tx; tr += rx
        print("   %-17s  down %6.2f Mbps   up %6.2f Mbps" % (mac, tx, rx))
    print("   %-17s  down %6.2f Mbps   up %6.2f Mbps" % ("TOTAL", tt, tr))
    print("\nNote: the router can't run an Internet speed test; this is live LAN<->client\n"
          "Wi-Fi traffic. Wired-client byte counters aren't exposed by this firmware.")


def cmd_firmware(r, args):
    info = r.get("IGD_DEV_INFO", ["modelName", "softwareVersion", "hardwareVersion"])
    ver = info.get("softwareVersion", "?")
    built = _fw_date(ver)
    print("Model     : %s" % info.get("modelName"))
    print("Hardware  : %s" % info.get("hardwareVersion"))
    print("Firmware  : %s" % ver)
    print("Built     : %s" % built)
    yr = built[:4]
    print("\nUpdate check:")
    if yr.isdigit() and int(yr) < 2024:
        print("  [!] This build is from %s - no security updates in years." % built)
    print("  * Latest firmware for this model is published per-region at:")
    print("    https://www.tp-link.com/support/download/tl-wr850n/v3/")
    print("  * Upgrade in the UI: System Tools -> Firmware Upgrade (upload the .bin for v3 ONLY).")
    print("  * This WR840N-family codebase has known CVEs (e.g. CVE-2019-15060 'firmware")
    print("    through 0.9.1 3.16' - matches yours; CVE-2021-41653 Ping RCE). Update if a")
    print("    newer v3 build exists; otherwise mitigate (see 'tpwrctl audit').")


def cmd_cpu(r, args):
    p = r.get("PROC_STATUS", ["CPUUsage", "X_TP_TotalTime", "X_TP_IdleTime"])
    print("CPU usage : %s%%" % p.get("CPUUsage", "?"))
    up = _fmt_uptime(p)
    if up:
        print("Uptime    : %s" % up)


def cmd_reboot(r, args):
    if not args.yes:
        if not _confirm("Reboot the router now? Network drops for ~90s."):
            print("aborted."); return
    r.op("ACT_REBOOT")
    print("Reboot command sent. The router will be back in ~90 seconds.")


def cmd_audit(r, args):
    host = re.sub(r"^https?://", "", r.host)
    print("== Port exposure (LAN side: %s) ==" % host)
    ports = {22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP-admin", 443: "HTTPS",
             161: "SNMP", 1900: "UPnP/SSDP", 7547: "TR-069/CWMP"}
    openp = []
    for p, nm in ports.items():
        sk = socket.socket(); sk.settimeout(0.6)
        st = sk.connect_ex((host, p)); sk.close()
        if st == 0:
            openp.append(p)
        print("  %-5d %-13s %s" % (p, nm, "OPEN" if st == 0 else "closed"))
    print("\n== Config findings ==")
    findings = []
    try:
        http = r.get("HTTP_CFG")
        if http.get("httpRemoteEnabled") == "1" or http.get("httpsRemoteEnabled") == "1":
            findings.append(("HIGH", "Remote web management is ENABLED (admin UI reachable from Internet)"))
        else:
            findings.append(("OK", "Remote web management disabled"))
        if http.get("httpsLocalEnabled") == "0":
            findings.append(("LOW", "Admin UI is HTTP-only (no HTTPS) on the LAN"))
    except Exception as e:
        findings.append(("?", "HTTP_CFG read failed: %s" % e))
    try:
        if r.get("UPNP_CFG").get("enable") == "1":
            findings.append(("MED", "UPnP enabled - any LAN device can open WAN ports silently"))
    except Exception:
        pass
    if 23 in openp:
        findings.append(("MED", "Telnet (23) is listening - plaintext admin shell; disable if unused"))
    if 7547 in openp:
        findings.append(("HIGH", "TR-069/CWMP (7547) listening - unmanaged remote-mgmt daemon; "
                                 "disable CWMP if your ISP doesn't require it"))
    try:
        ver = r.get("IGD_DEV_INFO", ["softwareVersion"]).get("softwareVersion", "")
        if (_fw_date(ver)[:4] or "9999") < "2024":
            findings.append(("HIGH", "Firmware from %s - WR840N-family CVEs apply (CVE-2019-15060 etc.)"
                             % _fw_date(ver)))
    except Exception:
        pass
    order = {"HIGH": 0, "MED": 1, "LOW": 2, "OK": 3, "?": 4}
    for sev, msg in sorted(findings, key=lambda x: order.get(x[0], 9)):
        print("  [%-4s] %s" % (sev, msg))


# Reference catalog for the general web read/write commands (the web-API counterpart
# of `telnet --list`). "(gl)" = a list/table, fetch it with `get --gl`.
WEB_OIDS = """Useful web-API objects  (read: 'get OID' | 'get OID --gl' ; write: 'set OID attr=val')

  IGD_DEV_INFO             model, firmware, hardware version
  PROC_STATUS              CPU usage
  WAN_IP_CONN         (gl) Internet status, public IP, gateway, DNS
  WAN_COMMON_INTF_CFG      WAN interface info
  LAN_HOST_ENTRY      (gl) every known LAN device (wired + Wi-Fi)
  LAN_WLAN            (gl) Wi-Fi AP config: SSID, security, password (X_TP_PreSharedKey)
  LAN_WLAN_ASSOC_DEV  (gl) associated Wi-Fi clients + signal/rates
  UPNP_CFG                 UPnP on/off          (set enable=0 to disable)
  CWMP_CFG                 TR-069 / CWMP config
  HTTP_CFG                 web management (local/remote, http/https)
  DHCP_STATIC_ADDR    (gl) DHCP address reservations

Examples:
  tpwrctl get IGD_DEV_INFO
  tpwrctl get WAN_IP_CONN --gl
  tpwrctl get HTTP_CFG --json
  tpwrctl set UPNP_CFG enable=0"""


def cmd_get(r, args):
    """General web read: fetch any object with ACT_GET (or ACT_GL via --gl)."""
    rows = (r.getlist(args.oid, args.stack) if args.gl
            else [r.get(args.oid, args.attrs or None, args.stack)])
    if args.json:
        print(json.dumps(rows, indent=2))
        return
    printed = False
    for i, row in enumerate(rows):
        keys = [k for k in row if k != "__stack"]
        if len(rows) != 1:
            print("[%d]" % i)
        w = max((len(k) for k in keys), default=0)
        for k in keys:
            print("  %-*s : %s" % (w, k, row[k]))
            printed = True
        if len(rows) != 1:
            print()
    if not printed:
        print("  (no data)")


def cmd_set(r, args):
    """General web write: set one or more attr=val on an object."""
    attrs = dict(kv.split("=", 1) for kv in args.attrs)
    r.set(args.oid, attrs, args.stack)
    print("OK: set %s %s" % (args.oid, attrs))


# --- Access Control: block/unblock devices by MAC (wired or wireless) --------------
# Uses the router's Access Control feature: FIREWALL (enable + firewallMode=1 blacklist)
# plus a paired INTERNAL_HOST (the device) and RULE (block action) per blocked MAC.
_MAC_RE = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")


def _fw_state(r):
    return r.get("FIREWALL", ["enable", "firewallMode", "defaultAction"])


def _ac_find(r, mac):
    """Find the (host, rule) access-control entries for a MAC, or (None, None)."""
    mac = _macnorm(mac)
    host = next((h for h in r.getlist("INTERNAL_HOST") if _macnorm(h.get("mac")) == mac), None)
    rule = None
    if host:
        name = host.get("entryName")
        rule = next((x for x in r.getlist("RULE")
                     if x.get("internalHostRef") == name and x.get("isParentCtrl") != "1"), None)
    return host, rule


def _sanitize_name(s):
    """Make a string valid for entryName: drop chars $.isname rejects, <=15 chars, no trailing space."""
    return re.sub(r'[\\/":*?<>|&]', "-", s or "").strip()[:15].rstrip()


def _block_name(r, mac, explicit, existing):
    """Pick the block label: --name, else the device's hostname, else the MAC; kept unique & valid."""
    mac_hex = mac.replace(":", "")
    if explicit:
        name = _sanitize_name(explicit)
    else:
        h = next((x for x in r.getlist("LAN_HOST_ENTRY")
                  if _macnorm(x.get("MACAddress")) == mac), None)
        hn = (h or {}).get("hostName", "")
        name = _sanitize_name(hn) if hn and hn.lower() != "unknown" else ""
    if not name:
        name = mac_hex
    if name in existing:                                  # entryName must be unique
        sfx = "-" + mac_hex[-4:]
        name = name[:15 - len(sfx)] + sfx
    return name


def cmd_block(r, args):
    mac = _macnorm(args.mac)
    if not _MAC_RE.match(mac):
        sys.exit("invalid MAC address: %s" % args.mac)
    host, rule = _ac_find(r, mac)
    if host and rule:
        print("already blocked: %s (%s)" % (mac, host.get("entryName"))); return
    name = _block_name(r, mac, args.name, {h.get("entryName") for h in r.getlist("INTERNAL_HOST")})
    fw = _fw_state(r)
    steps = []
    if fw.get("enable") != "1" or fw.get("firewallMode") != "1":
        steps.append("turn Access Control ON in blacklist mode")
    steps.append("block %s (as '%s') -- it will be disconnected and can't reconnect" % (mac, name))
    print("Plan:")
    for s in steps:
        print("  - " + s)
    if args.dry_run:
        print("(dry-run: nothing sent)"); return
    if not args.yes and not _confirm("Apply?"):
        print("aborted."); return
    r.set("FIREWALL", {"enable": "1"})
    r.set("FIREWALL", {"firewallMode": "1"})          # 1 = blacklist (block listed)
    r.cgi([{"action": ACT_ADD, "oid": "INTERNAL_HOST",
            "attrs": {"type": "1", "entryName": name, "mac": mac}}])
    r.cgi([{"action": ACT_ADD, "oid": "RULE",
            "attrs": {"isParentCtrl": "0", "ruleName": name, "internalHostRef": name,
                      "externalHostRef": "", "scheduleRef": "", "action": "0", "enable": "1"}}])
    print("blocked %s as '%s'" % (mac, name))


def cmd_unblock(r, args):
    mac = _macnorm(args.mac)
    host, rule = _ac_find(r, mac)
    if not host and not rule:
        print("not in the block list: %s" % mac); return
    if args.dry_run:
        print("(dry-run) would remove the block rule + host for %s" % mac); return
    if rule:
        r.cgi([{"action": ACT_DEL, "oid": "RULE", "stack": rule.get("__stack")}])
    if host:
        r.cgi([{"action": ACT_DEL, "oid": "INTERNAL_HOST", "stack": host.get("__stack")}])
    print("unblocked %s" % mac)


def cmd_blocklist(r, args):
    fw = _fw_state(r)
    mode = {"1": "blacklist (listed = blocked)", "0": "whitelist (only listed allowed)"}.get(
        fw.get("firewallMode"), "?")
    print("Access Control : %s   mode: %s" % ("ON" if fw.get("enable") == "1" else "OFF", mode))
    verdict = "blocked" if fw.get("firewallMode") == "1" else "allowed"
    hosts = {h.get("entryName"): h for h in r.getlist("INTERNAL_HOST")}
    rows = []
    for ru in r.getlist("RULE"):
        if ru.get("isParentCtrl") == "1":
            continue
        h = hosts.get(ru.get("internalHostRef"))
        if h:
            rows.append((h.get("entryName", ""), _macnorm(h.get("mac"))))
    if not rows:
        print("  (no device rules)"); return
    status = verdict if fw.get("enable") == "1" else verdict + " (AC off - not enforced)"
    print("  %-18s %-17s %s" % ("NAME", "MAC", "STATUS"))
    for n, m in rows:
        print("  %-18s %-17s %s" % (n[:18], m, status))


# ----------------------------------------------------------------------------- ACS / TR-069
# Manage the router through its TR-069 ACS (GenieACS). These commands talk to the GenieACS
# NBI (REST API), default http://localhost:7557 -- run them on the ACS host (the Oracle VM).
#
# The router sits behind NAT, so the ACS can't reach it on demand: every task runs at the
# router's next periodic inform. Writes wait for that and read the result back (--no-wait
# only queues); reads show the ACS's cached values with their age (--refresh re-reads them).
# TR-069 never reports secrets (the Wi-Fi key reads back empty), so a key set through
# `acs wifi --password` is remembered locally in ACS_SECRETS.
ACS_SECRETS = os.path.expanduser("~/.config/tpwrctl/acs-secrets.json")
ACS_HELP = """Manage the router over TR-069 through the GenieACS ACS (run on the ACS host).

The router is behind NAT, so the ACS can't reach it on demand: each task runs at the
router's next periodic inform ('acs inform' shows when; 'acs inform --interval 60' makes
control snappier). Writes wait for it and read the result back; --no-wait only queues.
Reads show the ACS's cached values with their age; --refresh re-reads them first.
TR-069 never reports secrets, so a Wi-Fi key set with 'acs wifi --password' is
remembered in ~/.config/tpwrctl/acs-secrets.json and shown by 'acs wifi'."""


def _acs_base(args):
    return (getattr(args, "acs_url", None) or os.environ.get("TPWRCTL_ACS")
            or load_conf().get("acs_url") or "http://localhost:7557")


def _q(s):
    from urllib.parse import quote
    return quote(s, safe="")


def _acs_req(base, method, path, timeout=30, **kw):
    r = requests.request(method, base.rstrip("/") + path, timeout=timeout, **kw)
    if r.status_code >= 400:
        raise RuntimeError("ACS %s %s -> HTTP %s %s" % (method, path.split("?")[0], r.status_code,
                                                        r.text.strip()[:200]))
    return r


def _acs_get(base, path):
    return _acs_req(base, "GET", path).json()


def _acs_find(base, coll, query):
    return _acs_get(base, "/%s/?query=%s" % (coll, _q(json.dumps(query))))


def _acs_device(base, did, projection=None):
    # GenieACS has no GET /devices/<id>; query by _id instead.
    path = "/devices/?query=" + _q(json.dumps({"_id": did}))
    if projection:
        path += "&projection=" + _q(",".join(projection))
    devs = _acs_get(base, path)
    if not devs:
        raise RuntimeError("device %s not found on the ACS" % did)
    return devs[0]


def _acs_pick(base, explicit):
    if explicit:
        return explicit
    devs = _acs_get(base, "/devices/?projection=_id")
    if not devs:
        raise RuntimeError("the ACS knows no devices yet - has the router informed? (set its ACS URL)")
    if len(devs) > 1:
        raise RuntimeError("several devices; pass --id (%s)" % ", ".join(d.get("_id", "?") for d in devs))
    return devs[0]["_id"]


def _param(dev, path):
    """Return a parameter's _value by dotted path, or None."""
    n = _node(dev, path)
    return _nval(n)


def _node(dev, path):
    cur = dev
    for p in path.split("."):
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return None
    return cur


def _nval(node):
    return node.get("_value") if isinstance(node, dict) and "_value" in node else None


def _leaves(node, pfx):
    """(path, node) for every parameter under node (node itself if it is one)."""
    if isinstance(node, dict):
        if "_value" in node:
            yield pfx, node
            return
        for k, v in node.items():
            if not k.startswith("_"):
                yield from _leaves(v, (pfx + "." + k) if pfx else k)


def _rows(dev, path):
    """Numbered table instances under path, as (index, subtree), in numeric order."""
    node = _node(dev, path) or {}
    return [(k, v) for k, v in sorted(node.items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 0)
            if k.isdigit() and isinstance(v, dict)]


def _truthy(v):
    return str(v).lower() in ("true", "1", "yes")


def _hms(secs):
    try:
        s = int(secs)
    except (TypeError, ValueError):
        return "?"
    d, r = divmod(s, 86400)
    h, m = r // 3600, (r % 3600) // 60
    return "%dd %dh %dm" % (d, h, m) if d else "%dh %dm" % (h, m)


def _root(dev):  # data model root differs by device
    return "InternetGatewayDevice" if "InternetGatewayDevice" in dev else "Device"


def _full(dev, path):
    """Accept paths with or without the data-model root: DeviceInfo.UpTime works too."""
    return path if path.split(".")[0] in ("InternetGatewayDevice", "Device") else _root(dev) + "." + path


def _epoch(ts):
    """GenieACS timestamp (ISO 8601, UTC) -> epoch seconds, or None."""
    try:
        return calendar.timegm(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
    except (TypeError, ValueError):
        return None


def _utc(ts):
    """'HH:MM:SS UTC' for today's timestamps, else 'YYYY-MM-DD HH:MM:SS UTC'."""
    if not ts:
        return "never"
    return "%s UTC" % (ts[11:19] if ts[:10] == time.strftime("%Y-%m-%d", time.gmtime()) else ts[:19].replace("T", " "))


def _ago(ts):
    e = _epoch(ts)
    if e is None:
        return "?"
    s = max(0, int(time.time() - e))
    return "%ds ago" % s if s < 120 else "%dm ago" % (s // 60) if s < 7200 else "%s ago" % _hms(s)


def _asof(node):
    """'[read HH:MM:SS UTC, 5m ago]' for a cached parameter or object."""
    ts = node.get("_timestamp") if isinstance(node, dict) else None
    return "[read %s, %s]" % (_utc(ts), _ago(ts)) if ts else "[never read]"


def _uptime(dev, path, boot_fallback=True):
    """A cached uptime counter extrapolated to now: (seconds, approximate) or None.
    TR-069 values are snapshots; if the router booted since, estimate from the BOOT inform."""
    n = _node(dev, path)
    v, e = _nval(n), _epoch((n or {}).get("_timestamp"))
    boot, bstrap = _epoch(dev.get("_lastBoot")), _epoch(dev.get("_lastBootstrap"))
    if v is not None and e is not None and (boot or 0) <= e and (bstrap or 0) <= e:
        return int(v) + int(time.time() - e), False
    if boot_fallback and boot and boot >= (bstrap or 0):
        return int(time.time() - boot), True
    return None


def _fmt_up(u):
    return "?  (rebooted since it was read - use --refresh)" if u is None else ("~" if u[1] else "") + _hms(u[0])


def _inform_interval(dev):
    ms = _root(dev) + ".ManagementServer"
    try:
        return int(_param(dev, ms + ".PeriodicInformInterval")) if _truthy(
            _param(dev, ms + ".PeriodicInformEnable")) else None
    except (TypeError, ValueError):
        return None


def _next_inform(dev):
    """Seconds until the router's next periodic inform is due (<= 0: overdue), or None."""
    iv, last = _inform_interval(dev), _epoch(dev.get("_lastInform"))
    return None if iv is None or last is None else last + iv - time.time()


def _progress(msg):
    """One live status line on a TTY; _progress('') clears it."""
    if sys.stdout.isatty():
        sys.stdout.write("\r\033[K" + msg)
        sys.stdout.flush()


# --- tasks: queue, wait for the router to run them, report faults --------------------------
def _acs_post(base, did, body, connreq=True):
    """Queue a task (optionally with a connection request); returns (task, ran_now)."""
    r = _acs_req(base, "POST", "/devices/%s/tasks%s" % (_q(did), "?connection_request&timeout=3000"
                                                        if connreq else ""),
                 data=json.dumps(body), headers={"Content-Type": "application/json"}, timeout=60)
    return r.json(), r.status_code == 200


def _fault_text(f):
    d = f.get("detail") or {}
    sub = "; ".join("%s: %s %s" % (x.get("parameterName"), x.get("faultCode"), x.get("faultString"))
                    for x in d.get("setParameterValuesFault") or [] if isinstance(x, dict))
    return "%s %s%s" % (f.get("code"), f.get("message"), " (%s)" % sub if sub else "")


def _acs_run(base, did, bodies, what, wait=True):
    """Queue tasks (they run in order, in one session) and wait until the router has run them.
    Returns the tasks once done, or None if only queued. A faulted task is deleted together
    with its fault (and the rest of the batch), so GenieACS doesn't retry it forever."""
    tasks, now = [], True
    for i, b in enumerate(bodies):
        t, ran = _acs_post(base, did, b, connreq=(i == len(bodies) - 1))
        tasks.append(t)
        now = now and ran
    if now:
        return tasks
    dev = _acs_device(base, did)
    nxt = _next_inform(dev)
    if not wait:
        print("%s: queued - runs at the router's next inform%s ('acs tasks' to see/cancel)"
              % (what, " (due in %ds)" % nxt if nxt and nxt > 0 else ""))
        return None
    iv = _inform_interval(dev) or 300
    due = time.time() + (nxt if nxt is not None else iv)
    deadline = max(due, time.time()) + iv + 60              # tolerate one missed inform
    pend, said = {t["_id"]: t for t in tasks}, False
    try:
        while pend:
            for tid in list(pend):
                flt = _acs_find(base, "faults", {"_id": "%s:task_%s" % (did, tid)})
                if flt:
                    for other in pend:
                        _acs_req(base, "DELETE", "/tasks/" + other)
                    _acs_req(base, "DELETE", "/faults/" + _q(flt[0]["_id"]))
                    raise RuntimeError("%s: the router rejected %s: %s"
                                       % (what, pend[tid].get("name"), _fault_text(flt[0])))
                if not _acs_find(base, "tasks", {"_id": tid}):
                    del pend[tid]
            if not pend:
                break
            left = int(due - time.time())
            if time.time() > deadline:
                raise RuntimeError("%s: the router hasn't informed since %s; the task is still queued "
                                   "('acs tasks' to see/cancel)" % (what, _utc(dev.get("_lastInform"))))
            msg = "%s: waiting for the router's next inform (%s)" % (
                what, "due in %ds" % left if left > 0 else "overdue %ds" % -left)
            if sys.stdout.isatty():
                _progress(msg + " ... Ctrl-C leaves it queued")
            elif not said:
                print(msg + " ...", flush=True)
                said = True
            time.sleep(2)
    finally:
        _progress("")
    return tasks


def _acs_refresh(base, did, objects, what, wait=True):
    return _acs_run(base, did, [{"name": "refreshObject", "objectName": o} for o in objects], what, wait)


_BOOLS = {"true": True, "1": True, "on": True, "yes": True,
          "false": False, "0": False, "off": False, "no": False}


def _coerce(val, typ):
    """CLI value -> JSON value of a TR-069 type (ValueError if it doesn't fit)."""
    if typ == "xsd:boolean":
        if isinstance(val, bool):
            return val
        if str(val).lower() not in _BOOLS:
            raise ValueError("expected true/false, got %r" % val)
        return _BOOLS[str(val).lower()]
    if typ in ("xsd:int", "xsd:long", "xsd:unsignedInt", "xsd:unsignedLong"):
        try:
            n = int(val)
        except ValueError:
            raise ValueError("expected an integer, got %r" % val)
        if typ.startswith("xsd:unsigned") and n < 0:
            raise ValueError("expected a non-negative integer")
        return n
    return str(val)


def _acs_set(base, did, changes, what, wait=True, secret=(), label=None):
    """SetParameterValues, plus a GetParameterValues of the same names in the same session so
    the result is what the router reads back. changes: [(path, value, type)].
    Returns True/False (all applied / some didn't), or None if only queued."""
    label = label or (lambda p: p.partition(".")[2])
    bodies = [{"name": "setParameterValues", "parameterValues": [[p, v, t] for p, v, t in changes]}]
    readable = [p for p, _, _ in changes if p not in secret]
    if readable:
        bodies.append({"name": "getParameterValues", "parameterNames": readable})
    if _acs_run(base, did, bodies, what, wait) is None:
        return None
    after, ok = _acs_device(base, did), True
    for p, v, _ in changes:
        if p in secret:
            print("  %-30s accepted (write-only: the router never reads it back)" % label(p))
            continue
        got = _param(after, p)
        same = str(got).lower() == str(v).lower()
        ok = ok and same
        print("  %-30s = %s%s" % (label(p), got, "  OK" if same else "   <- asked for %s" % v))
    return ok


# --- remembered secrets (TR-069 never reads them back) --------------------------------------
def _secrets(did):
    try:
        with open(ACS_SECRETS) as f:
            return json.load(f).get(did, {})
    except Exception:
        return {}


def _remember(did, **kv):
    try:
        with open(ACS_SECRETS) as f:
            s = json.load(f)
    except Exception:
        s = {}
    s.setdefault(did, {}).update(kv)
    os.makedirs(os.path.dirname(ACS_SECRETS), exist_ok=True)
    fd = os.open(ACS_SECRETS, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(s, f, indent=1)
    os.chmod(ACS_SECRETS, 0o600)


def _acs_wifi_sec(w):
    """Human-readable Wi-Fi security from a WLANConfiguration subtree."""
    bt = _nval(w.get("BeaconType")) or ""
    enc = _nval(w.get("IEEE11iEncryptionModes")) or _nval(w.get("WPAEncryptionModes")) or ""
    cipher = "AES" if ("AES" in enc and "TKIP" not in enc) else ("TKIP+AES" if "AES" in enc else "TKIP")
    psk = "PSKAuthentication" in (_nval(w.get("IEEE11iAuthenticationMode")) or "",
                                  _nval(w.get("WPAAuthenticationMode")) or "")
    kind = "PSK" if psk else "Enterprise"
    if bt in ("Basic", "None"):
        return "Open" if _nval(w.get("BasicEncryptionModes")) == "None" else "WEP"
    if "11i" in bt and "WPA" in bt:
        return "WPA/WPA2-%s (%s)" % (kind, cipher)
    if bt == "WPA":
        return "WPA-%s (%s)" % (kind, cipher)
    if bt == "11i":
        return "WPA2-%s (%s)" % (kind, cipher)
    return "WPA2-%s (%s)" % (kind, cipher) if psk else "Open/Unknown"


# Convenience path builders (all devices here use the InternetGatewayDevice model).
def _p_wlan(root):
    return root + ".LANDevice.1.WLANConfiguration.1"


def _p_wan(root):
    return root + ".WANDevice.1.WANConnectionDevice.1.WANIPConnection.1"


def _p_hosts(root):
    return root + ".LANDevice.1.Hosts"


def _check_ssid(s):
    if 1 <= len(s.encode()) <= 32:
        return s
    raise argparse.ArgumentTypeError("an SSID is 1-32 bytes")


def _check_psk(k):
    if re.fullmatch(r"[0-9A-Fa-f]{64}", k) or (8 <= len(k) <= 63 and all(32 <= ord(c) < 127 for c in k)):
        return k
    raise argparse.ArgumentTypeError("a WPA key is 8-63 printable ASCII characters (or 64 hex digits)")


def _check_channel(c):
    if c.lower() == "auto":
        return "auto"
    if c.isdigit() and 1 <= int(c) <= 13:
        return int(c)
    raise argparse.ArgumentTypeError("channel is 'auto' or 1-13")


# --- commands ---------------------------------------------------------------------------------
def cmd_acs_devices(base, args):
    devs = _acs_get(base, "/devices/")
    if not devs:
        print("no devices registered yet (waiting for the router to inform the ACS)"); return
    print("%-26s %-11s %-24s %s" % ("ID", "MODEL", "LAST INFORM", "STATE"))
    for d in devs:
        root, iv, last = _root(d), _inform_interval(d) or 300, _epoch(d.get("_lastInform"))
        alive = last is not None and time.time() - last < 2 * iv + 60
        print("%-26s %-11s %-24s %s" % (
            d.get("_id", "?"), _param(d, root + ".DeviceInfo.ModelName") or "?",
            "%s (%s)" % (_utc(d.get("_lastInform")), _ago(d.get("_lastInform"))),
            "online (informs every %ds)" % iv if alive else "SILENT - no inform for %s" % _ago(
                d.get("_lastInform"))[:-4]))


def cmd_acs_status(base, args):
    did = _acs_pick(base, args.id)
    dev = _acs_device(base, did)
    root = _root(dev)
    if args.refresh:
        _acs_refresh(base, did, [root + ".DeviceInfo", _p_wan(root), _p_wlan(root), _p_hosts(root)], "refresh")
        dev = _acs_device(base, did)
    di, wan = root + ".DeviceInfo", _p_wan(root)
    w = _node(dev, _p_wlan(root)) or {}
    hosts = _rows(dev, _p_hosts(root) + ".Host")
    active = sum(1 for _, h in hosts if _truthy(_nval(h.get("Active"))))
    sw = _param(dev, di + ".SoftwareVersion")
    nxt = _next_inform(dev)
    print("Model       : %s  (hw %s)" % (_param(dev, di + ".ModelName"), _param(dev, di + ".HardwareVersion")))
    print("Firmware    : %s   [built %s]" % (sw, _fw_date(sw)))
    print("Uptime      : %s" % _fmt_up(_uptime(dev, di + ".UpTime")))
    print("WAN         : %s   IP %s   %s" % (_param(dev, wan + ".ConnectionStatus"),
                                            _param(dev, wan + ".ExternalIPAddress"),
                                            _asof(_node(dev, wan + ".ConnectionStatus"))))
    print("Wi-Fi       : %s  (%s, ch %s, %s)   %s" % (
        _nval(w.get("SSID")), "on" if _truthy(_nval(w.get("Enable"))) else "off",
        _nval(w.get("Channel")), _acs_wifi_sec(w), _asof(w.get("Enable"))))
    print("Clients     : %d active  (%d known)   %s" % (
        active, len(hosts), _asof(_node(dev, _p_hosts(root) + ".HostNumberOfEntries"))))
    print("Last inform : %s (%s)%s" % (_utc(dev.get("_lastInform")), _ago(dev.get("_lastInform")),
                                       "; next due in %ds" % nxt if nxt and nxt > 0 else ""))


def cmd_acs_clients(base, args):
    did = _acs_pick(base, args.id)
    dev = _acs_device(base, did)
    if args.refresh:
        _acs_refresh(base, did, [_p_hosts(_root(dev))], "refresh")
        dev = _acs_device(base, did)
    hp = _p_hosts(_root(dev))
    hosts = _rows(dev, hp + ".Host")
    rows = []
    for _, h in hosts:
        act = _truthy(_nval(h.get("Active")))
        if args.online and not act:
            continue
        lt = _nval(h.get("LeaseTimeRemaining"))
        dt = time.time() - (_epoch((h.get("LeaseTimeRemaining") or {}).get("_timestamp")) or time.time())
        left = "-" if lt in (None, "", -1) or int(lt) < 0 else _hms(max(0, int(lt) - int(dt)))
        rows.append((_nval(h.get("HostName")) or "Unknown", _nval(h.get("IPAddress")) or "",
                     _macnorm(_nval(h.get("MACAddress"))), _nval(h.get("AddressSource")) or "", left, act))
    print("%-24s %-15s %-17s %-7s %-11s %s" % ("NAME", "IP", "MAC", "SRC", "LEASE LEFT", "STATE"))
    for n, ip, mac, src, left, act in sorted(rows, key=lambda r: not r[5]):
        print("%-24s %-15s %-17s %-7s %-11s %s" % (n[:24], ip, mac, src, left, "online" if act else "offline"))
    print("\n%d active / %d known   %s" % (sum(1 for _, h in hosts if _truthy(_nval(h.get("Active")))),
                                         len(hosts), _asof(_node(dev, hp + ".HostNumberOfEntries"))))


def cmd_acs_wifi(base, args):
    did = _acs_pick(base, args.id)
    dev = _acs_device(base, did)
    wl = _p_wlan(_root(dev))
    w = _node(dev, wl) or {}
    changes, secret = [], []
    if args.ssid is not None:
        changes.append((wl + ".SSID", args.ssid, "xsd:string"))
    if args.psk is not None:
        if (_nval(w.get("BeaconType")) or "Basic") in ("Basic", "None"):    # open network -> WPA2-PSK AES
            changes += [(wl + ".BeaconType", "11i", "xsd:string"),
                        (wl + ".IEEE11iAuthenticationMode", "PSKAuthentication", "xsd:string"),
                        (wl + ".IEEE11iEncryptionModes", "AESEncryption", "xsd:string")]
        changes.append((wl + ".X_TP_PreSharedKey", args.psk, "xsd:string"))
        secret.append(wl + ".X_TP_PreSharedKey")
    if args.channel is not None:
        changes += ([(wl + ".AutoChannelEnable", True, "xsd:boolean")] if args.channel == "auto" else
                    [(wl + ".AutoChannelEnable", False, "xsd:boolean"),
                     (wl + ".Channel", args.channel, "xsd:unsignedInt")])
    if args.bandwidth is not None:
        changes.append((wl + ".X_TP_Bandwidth", args.bandwidth, "xsd:string"))
    if args.radio is not None:
        changes.append((wl + ".Enable", args.radio == "on", "xsd:boolean"))
    short = lambda p: p[len(wl) + 1:]
    if changes:
        print("Wi-Fi changes on '%s' via TR-069:" % _nval(w.get("SSID")))
        for p, v, _ in changes:
            print("  %-26s %s -> %s" % (short(p), "(write-only)" if p in secret else _nval(_node(dev, p)), v))
        print("! The radio restarts; Wi-Fi clients briefly disconnect.")
        if args.dry_run:
            print("(dry-run: nothing sent)"); return
        if not args.yes and not _confirm("Apply?"):
            print("aborted."); return
        ok = _acs_set(base, did, changes, "wifi", wait=not args.no_wait, secret=secret, label=short)
        if ok is None:
            if args.psk is not None:
                print("(the key is remembered only once the router confirms it - run without --no-wait)")
            return
        if args.psk is not None:
            _remember(did, wifi_psk=args.psk, wifi_psk_set=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                      wifi_ssid=args.ssid or _nval(w.get("SSID")))
        if not ok:
            sys.exit("error: the router didn't apply every change (see above)")
        print("wifi: applied")
        return
    if args.refresh:
        _acs_refresh(base, did, [wl], "refresh")
        dev = _acs_device(base, did)
        w = _node(dev, wl) or {}
    # A refresh reads the key back empty; right after a set, GenieACS caches what it sent.
    sec = _secrets(did)
    key = _nval(w.get("X_TP_PreSharedKey")) or sec.get("wifi_psk")
    if key:
        pw = "%s   (as last set through the ACS%s; TR-069 never reads the key back)" % (
            key, " " + _utc(sec.get("wifi_psk_set")) if sec.get("wifi_psk") == key else "")
    else:
        pw = "unknown - TR-069 never reads the key back; set it once with 'acs wifi --password' to remember it"
    print("SSID       : %s" % _nval(w.get("SSID")))
    print("Radio      : %s  (status %s)" % ("on" if _truthy(_nval(w.get("Enable"))) else "off", _nval(w.get("Status"))))
    print("Channel    : %s%s" % (_nval(w.get("Channel")), " (auto)" if _truthy(_nval(w.get("AutoChannelEnable"))) else ""))
    print("Band / BW  : %s / %s, 802.11%s" % (_nval(w.get("X_TP_Band")), _nval(w.get("X_TP_Bandwidth")),
                                             _nval(w.get("Standard"))))
    print("Broadcast  : %s" % ("yes" if _truthy(_nval(w.get("SSIDAdvertisementEnabled"))) else "no (hidden SSID)"))
    print("Security   : %s" % _acs_wifi_sec(w))
    print("Password   : %s" % pw)
    print("%s  ('--refresh' to re-read)" % _asof(w.get("SSID")))


def cmd_acs_wan(base, args):
    did = _acs_pick(base, args.id)
    dev = _acs_device(base, did)
    if args.refresh:
        _acs_refresh(base, did, [_p_wan(_root(dev))], "refresh")
        dev = _acs_device(base, did)
    wan = _p_wan(_root(dev))
    for label, p in [("Status", "ConnectionStatus"), ("Type", "ConnectionType"),
                     ("Addressing", "AddressingType"), ("External IP", "ExternalIPAddress"),
                     ("Subnet mask", "SubnetMask"), ("Gateway", "DefaultGateway"), ("DNS", "DNSServers"),
                     ("MAC", "MACAddress"), ("NAT", "NATEnabled")]:
        print("%-12s: %s" % (label, _param(dev, wan + "." + p)))
    up = _param(dev, wan + ".Uptime")      # this firmware always reports 0 here
    print("%-12s: %s" % ("Uptime", _fmt_up(_uptime(dev, wan + ".Uptime", boot_fallback=False))
                         if up else "not reported by the router"))
    print(_asof(_node(dev, wan + ".ConnectionStatus")))


def cmd_acs_firmware(base, args):
    did = _acs_pick(base, args.id)
    dev = _acs_device(base, did)
    di = _root(dev) + ".DeviceInfo"
    if args.refresh:
        _acs_refresh(base, did, [di], "refresh")
        dev = _acs_device(base, did)
    sw = _param(dev, di + ".SoftwareVersion")
    print("Model    : %s" % _param(dev, di + ".ModelName"))
    print("Hardware : %s" % _param(dev, di + ".HardwareVersion"))
    print("Firmware : %s" % sw)
    print("Built    : %s" % _fw_date(sw))
    print("Serial   : %s" % _param(dev, di + ".SerialNumber"))
    print("Uptime   : %s" % _fmt_up(_uptime(dev, di + ".UpTime")))


def cmd_acs_reboot(base, args):
    did = _acs_pick(base, args.id)
    if not args.yes and not _confirm("Reboot %s via TR-069? Internet drops for ~1 min." % did):
        print("aborted."); return
    before = _acs_device(base, did, ["_lastBoot"]).get("_lastBoot") or ""
    if _acs_run(base, did, [{"name": "reboot"}], "reboot", wait=not args.no_wait) is None:
        return
    sent = time.time()
    print("reboot: the router accepted the command; waiting for it to come back ...", flush=True)
    try:
        while time.time() - sent < 300:
            boot = _acs_device(base, did, ["_lastBoot"]).get("_lastBoot") or ""
            if boot > before:
                print("reboot: done - the router was back online after %ds (BOOT inform %s)"
                      % (max(0, (_epoch(boot) or time.time()) - sent), _utc(boot)))
                return
            _progress("reboot: restarting ... %ds" % (time.time() - sent))
            time.sleep(3)
    finally:
        _progress("")
    raise RuntimeError("the router hasn't reported back 5 min after the reboot - check its power/WAN")


def cmd_acs_refresh(base, args):
    did = _acs_pick(base, args.id)
    dev = _acs_device(base, did)
    obj = _full(dev, args.object).rstrip(".") if args.object else ""
    tasks = _acs_refresh(base, did, [obj], "refresh", wait=not args.no_wait)
    if tasks is None:
        return
    t0 = (_epoch(tasks[0].get("timestamp")) or time.time()) - 1
    dev = _acs_device(base, did)
    fresh = [p for p, n in _leaves(_node(dev, obj) if obj else dev, obj) if (_epoch(n.get("_timestamp")) or 0) >= t0]
    print("refresh: %d parameters re-read from the router (%s)" % (len(fresh), obj or "whole tree"))


def cmd_acs_get(base, args):
    did = _acs_pick(base, args.id)
    dev = _acs_device(base, did)
    path = _full(dev, args.param).rstrip(".")
    node = _node(dev, path)
    if node is None and not args.force:
        raise RuntimeError("the ACS doesn't know %s ('acs params --grep ...' to search; --force to ask "
                           "the router anyway)" % path)
    is_param = node is None or "_value" in node
    if not args.cached:
        body = ({"name": "getParameterValues", "parameterNames": [path]} if is_param
                else {"name": "refreshObject", "objectName": path})
        if _acs_run(base, did, [body], "get", wait=not args.no_wait) is not None:
            dev = _acs_device(base, did)
            node = _node(dev, path)
    if node is None:
        raise RuntimeError("the router has no parameter or object %s" % path)
    leaves = list(_leaves(node, path))
    if not leaves:
        print("%s: no value" % path); return
    if is_param and len(leaves) == 1:
        p, n = leaves[0]
        print("%s = %s   (%s, %s)" % (p, n.get("_value"), n.get("_type"), _asof(n)[1:-1]))
        return
    for p, n in leaves:
        print("  %s = %s" % (p, n.get("_value")))
    print("%d parameters  %s" % (len(leaves), _asof(node)))


def cmd_acs_set(base, args):
    did = _acs_pick(base, args.id)
    dev = _acs_device(base, did)
    path = _full(dev, args.param)
    node = _node(dev, path)
    if not args.force:
        if not isinstance(node, dict) or "_value" not in node:
            raise RuntimeError("the ACS doesn't know a parameter %s ('acs params --grep ...' to search; "
                               "--force to send anyway)" % path)
        if node.get("_writable") is False:
            raise RuntimeError("%s is read-only on the router" % path)
    typ = args.type or (node or {}).get("_type") or "xsd:string"
    try:
        val = _coerce(args.value, typ)
    except ValueError as e:
        raise RuntimeError("%s is %s: %s" % (path, typ, e))
    print("%s: %s -> %s   (%s)" % (path, _nval(node), val, typ))
    if (node or {}).get("_writable") is False:
        print("! %s is read-only: GenieACS won't send this write (the read-back shows the real value)" % path)
    if re.search(r"ManagementServer\.(URL|EnableCWMP|PeriodicInformEnable)$", path) and not args.yes:
        print("! This can cut the router off from this ACS.")
        if not _confirm("Send it?"):
            print("aborted."); return
    if args.dry_run:
        print("(dry-run: nothing sent)"); return
    ok = _acs_set(base, did, [(path, val, typ)], "set", wait=not args.no_wait)
    if ok is False:
        sys.exit("error: the router reads back a different value")


def cmd_acs_params(base, args):
    dev = _acs_device(base, _acs_pick(base, args.id))
    pfx = _full(dev, args.prefix).rstrip(".") if args.prefix else ""
    node = _node(dev, pfx) if pfx else dev
    if node is None:
        raise RuntimeError("the ACS has nothing under %s" % pfx)
    rx = re.compile(args.grep, re.I) if args.grep else None
    n = 0
    for p, nd in _leaves(node, pfx):
        if rx and not rx.search(p):
            continue
        n += 1
        if args.long:
            print("  %-78s %-24s %-15s %s %s" % (p, str(nd.get("_value"))[:24], nd.get("_type"),
                                                 "rw" if nd.get("_writable") else "ro", _ago(nd.get("_timestamp"))))
        else:
            print("  %s = %s" % (p, nd.get("_value")))
    print("%d parameters" % n)


def cmd_acs_inform(base, args):
    did = _acs_pick(base, args.id)
    dev = _acs_device(base, did)
    ms = _root(dev) + ".ManagementServer"
    if args.interval is not None:
        if not 30 <= args.interval <= 86400:
            raise RuntimeError("the inform interval must be 30-86400 s")
        print("PeriodicInformInterval: %s -> %d s" % (_param(dev, ms + ".PeriodicInformInterval"), args.interval))
        ok = _acs_set(base, did, [(ms + ".PeriodicInformInterval", args.interval, "xsd:unsignedInt")],
                      "inform", wait=not args.no_wait)
        if ok is False:
            sys.exit("error: the router reads back a different interval")
        return
    iv, nxt = _inform_interval(dev), _next_inform(dev)
    url = _param(dev, ms + ".ConnectionRequestURL") or ""
    host = re.sub(r"^\w+://", "", url).split("/")[0].split(":")[0]
    try:
        private = ipaddress.ip_address(host).is_private
    except ValueError:
        private = False
    print("Periodic inform : %s" % ("every %ds" % iv if iv else "OFF - tasks only run when the router informs"))
    print("Last inform     : %s (%s)" % (_utc(dev.get("_lastInform")), _ago(dev.get("_lastInform"))))
    if nxt is not None:
        print("Next due        : %s" % ("in %ds" % nxt if nxt > 0 else "now (overdue %ds)" % -nxt))
    print("Last boot       : %s (%s)" % (_utc(dev.get("_lastBoot")), _ago(dev.get("_lastBoot"))))
    print("Last bootstrap  : %s (%s)" % (_utc(dev.get("_lastBootstrap")), _ago(dev.get("_lastBootstrap"))))
    print("Conn. request   : %s%s" % (url, "  (private address: the ACS can't reach it, so tasks wait "
                                              "for the next inform)" if private else ""))


def _task_desc(t):
    if t.get("parameterValues"):
        return ", ".join("%s=%s" % (p.partition(".")[2], "***" if re.search(r"(?i)key|pass", p) else v)
                         for p, v, *_ in t["parameterValues"])
    if t.get("parameterNames"):
        return ", ".join(p.partition(".")[2] for p in t["parameterNames"])
    return t.get("objectName", "") if "objectName" in t else ""


def cmd_acs_tasks(base, args):
    did = _acs_pick(base, args.id)
    tasks, faults = _acs_find(base, "tasks", {"device": did}), _acs_find(base, "faults", {"device": did})
    if args.clear:
        if not tasks and not faults:
            print("nothing queued"); return
        if not args.yes and not _confirm("Cancel %d task(s) and clear %d fault(s)?" % (len(tasks), len(faults))):
            print("aborted."); return
        for t in tasks:
            _acs_req(base, "DELETE", "/tasks/" + t["_id"])
        for f in faults:
            _acs_req(base, "DELETE", "/faults/" + _q(f["_id"]))
        print("cancelled %d task(s), cleared %d fault(s)" % (len(tasks), len(faults)))
        return
    if not tasks and not faults:
        print("no queued tasks or faults"); return
    for t in tasks:
        print("task  %s  %-18s %-10s %s" % (t["_id"], t.get("name"), _ago(t.get("timestamp")), _task_desc(t)[:80]))
    for f in faults:
        print("fault %s  %s  retries=%s  %s" % (f.get("channel"), _fault_text(f), f.get("retries"), _ago(f.get("timestamp"))))
    nxt = _next_inform(_acs_device(base, did))
    if tasks and nxt is not None:
        print("\nqueued tasks run at the router's next inform (%s)" % ("in %ds" % nxt if nxt > 0 else "due now"))


def cmd_acs(args):
    base = _acs_base(args)
    handlers = {"devices": cmd_acs_devices, "status": cmd_acs_status, "clients": cmd_acs_clients,
                "wifi": cmd_acs_wifi, "wan": cmd_acs_wan, "firmware": cmd_acs_firmware,
                "reboot": cmd_acs_reboot, "refresh": cmd_acs_refresh, "get": cmd_acs_get,
                "set": cmd_acs_set, "params": cmd_acs_params, "inform": cmd_acs_inform,
                "tasks": cmd_acs_tasks}
    try:
        handlers[args.acs_cmd](base, args)
    except requests.exceptions.RequestException as e:
        why = ("can't connect" if isinstance(e, requests.exceptions.ConnectionError) else
               "timed out" if isinstance(e, requests.exceptions.Timeout) else str(e)[:120])
        sys.exit("cannot reach the ACS at %s (%s)\nRun this on the ACS host, or pass --acs-url / set $TPWRCTL_ACS." % (base, why))
    except RuntimeError as e:
        sys.exit("error: %s" % e)
    except KeyboardInterrupt:
        _progress("")
        sys.exit("\nstopped waiting - anything queued still runs at the next inform ('acs tasks' to see/cancel)")


# ----------------------------------------------------------------------------- telnet
# The TL-WR850N also exposes a restricted proprietary CLI on telnet/23 (password-only).
# It is NOT a Unix shell; it's a small command tree. Only one telnet session is allowed
# at a time, and the channel is plaintext. The web /cgi API is preferred for everything
# else; this wrapper is for the few things the CLI exposes directly.
_IAC, _DONT, _DO, _WONT, _WILL, _SB, _SE = 255, 254, 253, 252, 251, 250, 240
_PROMPT = re.compile(rb"TP-Link(\([^)]*\))?[#>]\s*$")
def _color_enabled():
    """Match argparse (3.14) help coloring: honor NO_COLOR/FORCE_COLOR/PYTHON_COLORS, else TTY."""
    pc = os.environ.get("PYTHON_COLORS")
    if pc == "0":
        return False
    if pc == "1":
        return True
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("TERM") == "dumb":
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


# Telnet CLI reference, as data so it can be rendered plain or colored.
_TN_REF = [
    ("Device info", [
        ("dev version", "firmware version"),
        ("dev show prodName", "model name"),
        ("dev show prodHardVer", "hardware version"),
        ("dev show prodSoftVer", "firmware string (same as 'dev version')"),
        ("dev serial show", "serial number"),
    ]),
    ("Device control", [
        ("dev reboot", "says cmd:SUCC but did nothing here; use 'tpwrctl reboot'"),
        ("dev reset", "factory reset (guarded; needs -y) - also a no-op here"),
    ]),
    ("LAN / DHCP", [
        ("lan show info", "full LAN + DHCP configuration"),
        ("lan show status", "LAN status"),
    ]),
    ("Wireless", [
        ("wlctl show", "SSID, security, key, radio status"),
        ("wlctl set [...]", "change Wi-Fi (run 'wlctl set' alone to list its options)"),
    ]),
    ("Multicast", [
        ("igmp showProxy", "IGMP proxy state"),
        ("igmp showSnoop", "IGMP snooping state"),
    ]),
    ("Session", [
        ("clear | history | help | logout", ""),
    ]),
]
_TN_EXAMPLES = [
    "tpwrctl telnet dev version",
    "tpwrctl telnet dev serial show",
    "tpwrctl telnet lan show info",
    "tpwrctl telnet --raw wlctl show",
]
_TN_NOTES = [
    "Not a shell: cat / ls / ifconfig / enable do NOT exist.",
    "Some commands need a sub-command (e.g. 'dev serial' -> 'dev serial show').",
    "Only one telnet session at a time; close the web UI / other session first.",
    "Plaintext protocol -- prefer the web commands on untrusted networks.",
]


def telnet_help(color=None):
    """Render the telnet CLI reference, colored (matching argparse) when appropriate."""
    if color is None:
        color = _color_enabled()
    head = (lambda s: "\033[1;34m%s\033[0m" % s) if color else (lambda s: s)   # bold blue
    cmd = (lambda s: "\033[1;32m%s\033[0m" % s) if color else (lambda s: s)    # bold green
    title = (lambda s: "\033[1m%s\033[0m" % s) if color else (lambda s: s)     # bold
    out = [title("TP-Link telnet CLI reference  (port 23; quotes optional)"), ""]
    for section, rows in _TN_REF:
        out.append(head(section))
        for name, desc in rows:
            out.append("  " + cmd("%-24s" % name) + ((" " + desc) if desc else ""))
    out += ["", head("Examples")] + ["  " + e for e in _TN_EXAMPLES]
    out += ["", head("Notes")] + ["  * " + n for n in _TN_NOTES]
    return "\n".join(out)


def _tn_negotiate(sock, data):
    out, resp, i = bytearray(), bytearray(), 0
    while i < len(data):
        b = data[i]
        if b == _IAC:
            if i + 1 >= len(data):
                break
            cmd = data[i + 1]
            if cmd in (_DO, _DONT, _WILL, _WONT):
                if i + 2 >= len(data):
                    break
                opt = data[i + 2]; i += 3
                if cmd == _DO:
                    resp += bytes([_IAC, _WONT, opt])
                elif cmd == _WILL:
                    resp += bytes([_IAC, _DONT, opt])
            elif cmd == _SB:
                j = data.find(bytes([_IAC, _SE]), i); i = (j + 2) if j >= 0 else len(data)
            elif cmd == _IAC:
                out.append(_IAC); i += 2
            else:
                i += 2
        else:
            out.append(b); i += 1
    if resp:
        try:
            sock.sendall(bytes(resp))
        except Exception:
            pass
    return bytes(out)


def _tn_read(sock, until=None, idle=1.2, overall=8):
    sock.settimeout(0.4); buf = b""; start = last = time.time()
    while True:
        try:
            c = sock.recv(4096)
            if c:
                buf += _tn_negotiate(sock, c); last = time.time()
                if until and until.search(buf):
                    break
            else:
                break
        except socket.timeout:
            if until and until.search(buf):
                break
            if time.time() - last > idle:
                break
        if time.time() - start > overall:
            break
    return buf


def telnet_exec(host, password, commands, timeout=8):
    ip = re.sub(r"^https?://", "", host).split("/")[0].split(":")[0]
    try:
        s = socket.create_connection((ip, 23), timeout=5)
    except OSError as e:
        raise RuntimeError("telnet connect failed (%s) - port 23 closed, or another "
                           "telnet session is active (only one allowed)." % e)
    try:
        pre = _tn_read(s, until=re.compile(rb"password:"), overall=6)
        if b"password:" not in pre:
            raise RuntimeError("no password prompt (telnet busy with another session?)")
        s.sendall(password.encode() + b"\r\n")
        banner = _tn_read(s, until=_PROMPT, overall=6)
        if not _PROMPT.search(banner):
            raise RuntimeError("telnet login failed (wrong password or busy)")
        results = []
        for cmd in commands:
            s.sendall(cmd.encode() + b"\r\n")
            raw = _tn_read(s, until=_PROMPT, overall=timeout)
            text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", raw.decode(errors="replace"))
            lines = [ln.rstrip("\r") for ln in text.split("\n")]
            if lines and lines[0].strip() == cmd.strip():
                lines = lines[1:]
            while lines and re.search(r"TP-Link(\([^)]*\))?[#>]\s*$", lines[-1]):
                lines = lines[:-1]
            results.append((cmd, "\n".join(lines).strip()))
        try:
            s.sendall(b"logout\r\n")
        except Exception:
            pass
        return results
    finally:
        s.close()


def _tn_skip(k):
    return k.endswith("_BK") or (k.startswith("__") and k != "__ifName") or k == "IPInterfaceNumberOfEn"


def _tn_kv(out):
    """Parse telnet output (cmd:SUCC:k=v / INDEX{...} / plain k=v) into dict + leftover lines."""
    d, extra = {}, []
    for ln in out.splitlines():
        ln = ln.strip()
        if ln in ("{", "}", "cmd:SUCC") or ln.startswith("INDEX="):
            continue
        if ln.startswith("cmd:SUCC:"):
            ln = ln[len("cmd:SUCC:"):]
        if "=" in ln:
            k, v = ln.split("=", 1); d[k] = v
        elif ln:
            extra.append(ln)
    return d, extra


def _tn_friendly(cmd, out):
    """Render a telnet command's raw output in a clean, web-UI-like style."""
    out = (out or "").strip()
    c = cmd.strip().lower()
    if not out or out == "(no output)":
        return "  (no data / not configured)"
    if out.startswith("valid sub cmd:"):
        subs = [l.strip() for l in out.splitlines()[1:] if l.strip()]
        return "  needs a sub-command -> %s" % ", ".join(subs)
    if out.startswith("Command not found"):
        return "  (unknown command)"
    d, extra = _tn_kv(out)

    def row(lbl, val):
        return "  %-15s %s" % (lbl + ":", val if val not in (None, "") else "-")

    if c == "wlctl show":
        return "\n".join(["Wireless",
                          row("SSID", d.get("SSID", "?")),
                          row("Status", d.get("Status", "?")),
                          row("Bandwidth", d.get("bandWidth", "?")),
                          row("Security", d.get("SecMode", "?")),
                          row("WPS (QSS)", d.get("QSS", "?")),
                          row("Wi-Fi key", d.get("Key", "?"))])
    if c.startswith("lan show"):
        lease = d.get("DHCPLeaseTime", "")
        lease_s = "%s s (%dh)" % (lease, int(lease) // 3600) if lease.isdigit() else lease or "-"
        lines = ["LAN / DHCP",
                 row("LAN IP", d.get("IPInterfaceIPAddress") or d.get("X_TP_DefaultIp")),
                 row("Subnet mask", d.get("IPInterfaceSubnetMask") or d.get("subnetMask")),
                 row("LAN MAC", d.get("X_TP_MACAddress")),
                 row("Interface", d.get("__ifName")),
                 row("DHCP server", "on" if d.get("DHCPServerEnable") == "1" else "off"),
                 row("DHCP range", "%s  ->  %s" % (d.get("minAddress", "?"), d.get("maxAddress", "?")))]
        if lease:
            lines.append(row("Lease time", lease_s))
        if d.get("DNSServers"):
            lines.append(row("DNS servers", d.get("DNSServers")))
        if d.get("IPRouters"):
            lines.append(row("Gateway", d.get("IPRouters")))
        if d.get("domainName"):
            lines.append(row("Domain", d.get("domainName")))
        return "\n".join(lines)
    if c == "dev serial show":
        return "  Serial number: %s" % d.get("serialNumber", "?")
    if c == "dev version" or c.startswith("dev show prod"):
        if d:
            k, v = next(iter(d.items()))
            lbl = {"softwareVersion": "Firmware", "hardwareVersion": "Hardware",
                   "modelName": "Model", "X_TP_DevModelVersion": "Model version"}.get(k, k)
            return "  %s: %s" % (lbl, v)
    # generic fallback: aligned key/value, noise filtered
    clean = {k: v for k, v in d.items() if not _tn_skip(k)}
    if clean:
        w = max(len(k) for k in clean)
        return "\n".join("  %-*s : %s" % (w, k, v if v else "-") for k, v in clean.items())
    if extra:
        return "\n".join("  " + e for e in extra)
    return "  " + out


def cmd_telnet(host, password, args):
    if args.list or not args.commands:
        print(telnet_help())
        if not args.list:
            print("\n(no command given)")
        return
    # Join all words into a single command, so quotes are optional:
    #   tpwrctl telnet dev serial show   ==   tpwrctl telnet "dev serial show"
    command = " ".join(args.commands)
    if "reset" in command.lower() and not args.yes:
        sys.exit("refusing '%s' (looks like a factory reset). Re-run with -y to force." % command)
    for cmd, out in telnet_exec(host, password, [command]):
        print("\033[1m$ %s\033[0m" % cmd if sys.stdout.isatty() else "$ %s" % cmd)
        print(out if args.raw else _tn_friendly(cmd, out))
        print()


# ----------------------------------------------------------------------------- config / main
def load_conf():
    try:
        with open(CONF) as f:
            return json.load(f)
    except Exception:
        return {}


def cmd_config(r_unused, args):
    os.makedirs(os.path.dirname(CONF), exist_ok=True)
    pw = args.password or getpass.getpass("Router admin password: ")
    with open(CONF, "w") as f:
        json.dump({"host": args.host, "password": pw}, f)
    os.chmod(CONF, 0o600)
    print("Saved %s (mode 600). WARNING: password stored in plaintext on disk." % CONF)


def resolve_creds(args):
    conf = load_conf()
    host = args.host or conf.get("host") or "192.168.1.1"
    pw = args.password or os.environ.get("ROUTER_PASS") or conf.get("password")
    if not pw:
        pw = getpass.getpass("Router admin password: ")
    return host, pw


def main():
    ap = argparse.ArgumentParser(prog="tpwrctl", description="TP-Link TL-WR850N CLI")
    ap.add_argument("--host", help="router IP/URL (default 192.168.1.1 or saved config)")
    ap.add_argument("--password", help="admin password (else $ROUTER_PASS, config, or prompt)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="one-screen overview").set_defaults(fn=cmd_status)
    d = sub.add_parser("devices", help="list connected devices"); d.set_defaults(fn=cmd_devices)
    d.add_argument("--online", action="store_true", help="only currently-connected devices")
    sub.add_parser("wan", help="WAN/Internet connection details").set_defaults(fn=cmd_wan)
    wf = sub.add_parser("wifi", help="show Wi-Fi (SSID/security/password/clients); flags change it")
    wf.set_defaults(fn=cmd_wifi)
    wf.add_argument("--ssid", help="set the network name (SSID)")
    # dest=psk so this does NOT clobber the global --password (admin login)
    wf.add_argument("--password", dest="psk", type=_check_psk, help="set the WPA2 pre-shared key")
    wf.add_argument("--bandwidth", choices=["Auto", "20M", "40M"], help="set channel width")
    wf.add_argument("--radio", choices=["on", "off"], help="turn the Wi-Fi radio on/off")
    wf.add_argument("--dry-run", action="store_true", help="show what would change, send nothing")
    wf.add_argument("-y", "--yes", action="store_true", help="skip the confirmation prompt")
    sp = sub.add_parser("speed", help="live per-client Wi-Fi throughput"); sp.set_defaults(fn=cmd_speed)
    sp.add_argument("--interval", type=float, default=2.0)
    sub.add_parser("firmware", help="firmware version + update advice").set_defaults(fn=cmd_firmware)
    sub.add_parser("cpu", help="CPU usage + approx uptime").set_defaults(fn=cmd_cpu)
    rb = sub.add_parser("reboot", help="reboot the router"); rb.set_defaults(fn=cmd_reboot)
    rb.add_argument("-y", "--yes", action="store_true", help="skip confirmation")
    sub.add_parser("audit", help="security audit (ports + config)").set_defaults(fn=cmd_audit)
    g = sub.add_parser("get", help="general web read: any OID (--gl for a list/table)")
    g.set_defaults(fn=cmd_get)
    g.add_argument("oid"); g.add_argument("attrs", nargs="*")
    g.add_argument("--gl", action="store_true", help="fetch a list/table (ACT_GL)")
    g.add_argument("--stack", help="object stack, e.g. 1,1,0,0,0,0 (for nested objects)")
    g.add_argument("--json", action="store_true", help="raw JSON output")
    st = sub.add_parser("set", help="general web write: set OID attrs (attr=val ...)")
    st.set_defaults(fn=cmd_set); st.add_argument("oid"); st.add_argument("attrs", nargs="+")
    st.add_argument("--stack", help="object stack, e.g. 1,1,0,0,0,0 (for nested objects)")
    sub.add_parser("oids", help="list useful web-API objects (web counterpart of 'telnet --list')")
    bl = sub.add_parser("block", help="block a device by MAC (Access Control blacklist)")
    bl.set_defaults(fn=cmd_block)
    bl.add_argument("mac", help="MAC address of the device to block")
    bl.add_argument("--name", help="label for the entry (default: the device's hostname, else its MAC)")
    bl.add_argument("--dry-run", action="store_true", help="show the plan, send nothing")
    bl.add_argument("-y", "--yes", action="store_true", help="skip the confirmation prompt")
    ubl = sub.add_parser("unblock", help="remove a device from the block list")
    ubl.set_defaults(fn=cmd_unblock)
    ubl.add_argument("mac", help="MAC address to unblock")
    ubl.add_argument("--dry-run", action="store_true", help="show what would be removed")
    sub.add_parser("blocklist", help="show Access Control state + blocked devices").set_defaults(fn=cmd_blocklist)
    acs = sub.add_parser("acs", help="manage the router remotely via TR-069 (GenieACS ACS)",
                         description=ACS_HELP, formatter_class=argparse.RawDescriptionHelpFormatter)
    acs.add_argument("--acs-url", help="GenieACS NBI base URL (default http://localhost:7557 / $TPWRCTL_ACS)")
    asub = acs.add_subparsers(dest="acs_cmd", required=True, metavar="COMMAND")
    a_id = argparse.ArgumentParser(add_help=False)
    a_id.add_argument("--id", help="device ID (default: the only device on the ACS)")
    a_rd = argparse.ArgumentParser(add_help=False)
    a_rd.add_argument("--refresh", action="store_true", help="re-read from the router first (waits for its next inform)")
    a_wr = argparse.ArgumentParser(add_help=False)
    a_wr.add_argument("--no-wait", action="store_true", help="only queue the task; don't wait for the router to run it")
    a_y = argparse.ArgumentParser(add_help=False)
    a_y.add_argument("-y", "--yes", action="store_true", help="skip the confirmation prompt")
    asub.add_parser("devices", help="list devices (CPEs) the ACS manages, and whether they still inform")
    asub.add_parser("status", parents=[a_id, a_rd], help="one-screen overview (model, uptime, WAN, Wi-Fi, clients)")
    acl = asub.add_parser("clients", parents=[a_id, a_rd], help="LAN hosts: name, IP, MAC, lease, online")
    acl.add_argument("--online", action="store_true", help="only hosts that are online")
    awf = asub.add_parser("wifi", parents=[a_id, a_rd, a_wr, a_y], help="show Wi-Fi (incl. password); flags change it")
    awf.add_argument("--ssid", type=_check_ssid, help="set the network name")
    awf.add_argument("--password", dest="psk", type=_check_psk,
                     help="set the WPA2 key (remembered here: TR-069 never reads it back)")
    awf.add_argument("--channel", type=_check_channel, help="'auto' or 1-13")
    awf.add_argument("--bandwidth", choices=["Auto", "20M", "40M"], help="set channel width")
    awf.add_argument("--radio", choices=["on", "off"], help="turn the radio on/off")
    awf.add_argument("--dry-run", action="store_true", help="show what would change, send nothing")
    asub.add_parser("wan", parents=[a_id, a_rd], help="WAN/Internet details")
    asub.add_parser("firmware", parents=[a_id, a_rd], help="model, firmware, serial, uptime")
    apm = asub.add_parser("params", parents=[a_id], help="list the cached TR-069 parameters")
    apm.add_argument("prefix", nargs="?", help="only this subtree, e.g. DeviceInfo (root optional)")
    apm.add_argument("--grep", metavar="REGEX", help="only paths matching REGEX (case-insensitive)")
    apm.add_argument("-l", "--long", action="store_true", help="also show type, rw/ro and age")
    ag = asub.add_parser("get", parents=[a_id, a_wr], help="read a parameter (or subtree) fresh from the router")
    ag.add_argument("param", help="e.g. DeviceInfo.UpTime (root optional; a subtree reads all below it)")
    ag.add_argument("--cached", action="store_true", help="print the ACS's cached value; don't ask the router")
    ag.add_argument("--force", action="store_true", help="ask even if the ACS doesn't know the parameter")
    aset = asub.add_parser("set", parents=[a_id, a_wr, a_y], help="write a parameter and read it back")
    aset.add_argument("param", help="e.g. ManagementServer.PeriodicInformInterval (root optional)")
    aset.add_argument("value")
    aset.add_argument("--type", choices=["xsd:string", "xsd:boolean", "xsd:int", "xsd:unsignedInt",
                                         "xsd:long", "xsd:unsignedLong", "xsd:dateTime"],
                      help="TR-069 type (default: the parameter's known type)")
    aset.add_argument("--force", action="store_true", help="send even if unknown or read-only")
    aset.add_argument("--dry-run", action="store_true", help="show what would change, send nothing")
    asub.add_parser("reboot", parents=[a_id, a_wr, a_y], help="reboot, and wait until the router is back")
    arf = asub.add_parser("refresh", parents=[a_id, a_wr], help="re-read parameters from the router")
    arf.add_argument("--object", default="", help="subtree to re-read, e.g. DeviceInfo (default: everything - slow)")
    ain = asub.add_parser("inform", parents=[a_id, a_wr], help="inform schedule (when queued tasks run); --interval")
    ain.add_argument("--interval", type=int, metavar="SEC", help="set the periodic inform interval (30-86400 s)")
    atk = asub.add_parser("tasks", parents=[a_id, a_y], help="queued tasks and faults; --clear cancels them")
    atk.add_argument("--clear", action="store_true", help="cancel every queued task and clear faults")
    tn = sub.add_parser(
        "telnet",
        help="run a command in the router's telnet CLI",
        description=(
            "Drive the router's built-in telnet CLI (port 23).\n"
            "It is a restricted, proprietary command tree -- NOT a Unix shell\n"
            "(no cat/ls/ifconfig). Only one telnet session is allowed at a time,\n"
            "and the channel is plaintext. All words are joined into a single\n"
            "command, so quotes are optional:  tpwrctl telnet dev serial show"
        ),
        epilog=telnet_help(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    tn.add_argument("commands", nargs="*", metavar="CMD",
                    help="CLI command words, e.g. dev serial show (quotes optional)")
    tn.add_argument("--list", action="store_true",
                    help="print the full CLI command reference and exit")
    tn.add_argument("--raw", action="store_true",
                    help="show the router's unformatted output instead of the tidy view")
    tn.add_argument("-y", "--yes", action="store_true",
                    help="allow a destructive command (dev reset) without the safety stop")
    cf = sub.add_parser("config", help="save host+password to ~/.config/tpwrctl"); cf.set_defaults(fn=cmd_config)
    cf.add_argument("--host", default="192.168.1.1"); cf.add_argument("--password")

    args = ap.parse_args()
    if args.cmd == "config":
        return args.fn(None, args)
    if args.cmd == "oids":                       # reference only, no login needed
        print(WEB_OIDS); return
    if args.cmd == "acs":                        # talks to the ACS, not the router web UI
        return cmd_acs(args)
    if args.cmd == "telnet" and args.list and not args.commands:
        print(telnet_help()); return
    host, pw = resolve_creds(args)
    if args.cmd == "telnet":
        try:
            return cmd_telnet(host, pw, args)
        except RuntimeError as e:
            sys.exit("error: %s" % e)
    try:
        with Router(host, pw) as r:
            args.fn(r, args)
    except RuntimeError as e:
        sys.exit("error: %s" % e)
    except requests.exceptions.RequestException as e:
        sys.exit("network error: %s" % e)


if __name__ == "__main__":
    main()
