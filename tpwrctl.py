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
import sys, os, re, json, time, argparse, hashlib, base64, socket, getpass

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
        out.append({
            "name": h.get("hostName", "Unknown"),
            "ip": h.get("IPAddress", ""),
            "mac": mac,
            "conn": "Wi-Fi" if a else "Wired",
            "active": h.get("active") == "1",
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


def _wifi_set(r, args, changes):
    """Apply changes to the main Wi-Fi radio (LAN_WLAN), using its real stack."""
    ap = (r.getlist("LAN_WLAN") or [{}])[0]
    stack = ap.get("__stack") or "1,1,0,0,0,0"
    print("Wi-Fi changes on SSID '%s' (stack %s):" % (ap.get("SSID", "?"), stack))
    for k, v in changes.items():
        print("  %-18s -> %s" % (k, v))
    print("\n\033[33m! This restarts the radio; Wi-Fi clients will briefly disconnect.\033[0m"
          if sys.stdout.isatty() else "\n! This restarts the radio; Wi-Fi clients will briefly disconnect.")
    if args.dry_run:
        print("(dry-run: nothing sent)")
        return
    if not args.yes and input("Apply? [y/N] ").strip().lower() != "y":
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
    ap = (r.getlist("LAN_WLAN") or [{}])[0]
    print("Access point")
    print("  SSID       : %s" % ap.get("SSID", "?"))
    print("  Status     : %s" % ap.get("status", "?"))
    print("  Band       : %s, channel %s%s" % (
        ap.get("X_TP_Band", "?"), ap.get("channel", "?"),
        " (auto)" if ap.get("autoChannelEnable") == "1" else ""))
    print("  Bandwidth  : %s" % ap.get("X_TP_Bandwidth", "?"))
    print("  Security   : %s" % _wifi_sec(ap))
    print("  Password   : %s" % (ap.get("X_TP_PreSharedKey", "") or "(none/open)"))
    # Associated clients.
    a = r.getlist("LAN_WLAN_ASSOC_DEV")
    print("\nClients (%d):" % len(a))
    if a:
        print("  %-17s %-7s %-8s %-4s %-6s %s" % ("MAC", "SIGNAL", "LINK", "STD", "BW", "TX/RX"))
    for d in a:
        print("  %-17s %-7s %-8s %-4s %-6s %s/%s" % (
            _macnorm(d.get("associatedDeviceMACAddress")),
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
        if input("Reboot the router now? Network drops for ~90s. [y/N] ").strip().lower() != "y":
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
    if not args.yes and input("Apply? [y/N] ").strip().lower() != "y":
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
def _acs_base(args):
    return (getattr(args, "acs_url", None) or os.environ.get("TPWRCTL_ACS")
            or load_conf().get("acs_url") or "http://localhost:7557")


def _q(s):
    from urllib.parse import quote
    return quote(s, safe="")


def _acs_get(base, path):
    r = requests.get(base.rstrip("/") + path, timeout=30)
    if r.status_code >= 400:
        raise RuntimeError("ACS GET %s -> HTTP %s" % (path, r.status_code))
    return r.json()


def _acs_device(base, did):
    # GenieACS has no GET /devices/<id>; query by _id instead.
    devs = _acs_get(base, "/devices/?query=" + _q(json.dumps({"_id": did})))
    if not devs:
        raise RuntimeError("device %s not found on the ACS" % did)
    return devs[0]


def _acs_task(base, did, body):
    """POST a task with a connection request; report whether it ran now or was queued."""
    r = requests.post(base.rstrip("/") + "/devices/%s/tasks" % _q(did),
                      params={"connection_request": ""}, data=json.dumps(body),
                      headers={"Content-Type": "application/json"}, timeout=40)
    if r.status_code >= 400:
        raise RuntimeError("task %s -> HTTP %s %s" % (body.get("name"), r.status_code, r.text[:200]))
    return "applied now" if r.status_code == 200 else "queued (runs on the next inform, <=5 min)"


def _acs_pick(base, explicit):
    if explicit:
        return explicit
    devs = _acs_get(base, "/devices/")
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


def _acs_wifi_sec(w):
    """Human-readable Wi-Fi security from a WLANConfiguration subtree."""
    bt = _nval(w.get("BeaconType")) or ""
    enc = _nval(w.get("IEEE11iEncryptionModes")) or _nval(w.get("WPAEncryptionModes")) or ""
    cipher = "AES" if ("AES" in enc and "TKIP" not in enc) else ("TKIP+AES" if "AES" in enc else "TKIP")
    psk = "PSKAuthentication" in (_nval(w.get("IEEE11iAuthenticationMode")) or "",
                                  _nval(w.get("WPAAuthenticationMode")) or "")
    kind = "PSK" if psk else "Enterprise"
    if bt == "Basic":
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
    return root + ".LANDevice.1.Hosts.Host"


def cmd_acs_devices(base, args):
    devs = _acs_get(base, "/devices/")
    if not devs:
        print("no devices registered yet (waiting for the router to inform the ACS)"); return
    print("%-34s %-12s %-21s %s" % ("ID", "MODEL", "LAST INFORM (UTC)", "FIRMWARE"))
    for d in devs:
        root = _root(d)
        print("%-34s %-12s %-21s %s" % (
            d.get("_id", "?"),
            _param(d, root + ".DeviceInfo.ModelName") or "?",
            (d.get("_lastInform", "?") or "?")[:19],
            _param(d, root + ".DeviceInfo.SoftwareVersion") or "?"))


def cmd_acs_reboot(base, args):
    did = _acs_pick(base, args.id)
    if not args.yes and input("Reboot %s via TR-069? [y/N] " % did).strip().lower() != "y":
        print("aborted."); return
    print("reboot: " + _acs_task(base, did, {"name": "reboot"}))


def cmd_acs_refresh(base, args):
    did = _acs_pick(base, args.id)
    print("refresh: " + _acs_task(base, did, {"name": "refreshObject", "objectName": args.object}))


def cmd_acs_get(base, args):
    did = _acs_pick(base, args.id)
    status = _acs_task(base, did, {"name": "getParameterValues", "parameterNames": [args.param]})
    val = _param(_acs_device(base, did), args.param)
    print("%s = %s   [refresh %s]" % (args.param, val, status))


def cmd_acs_set(base, args):
    did = _acs_pick(base, args.id)
    body = {"name": "setParameterValues", "parameterValues": [[args.param, args.value]]}
    print("set %s = %s : %s" % (args.param, args.value, _acs_task(base, did, body)))


def cmd_acs_params(base, args):
    dev = _acs_device(base, _acs_pick(base, args.id))
    def walk(o, pfx=""):
        if isinstance(o, dict):
            if "_value" in o:
                print("  %s = %s" % (pfx, o["_value"])); return
            for k, v in o.items():
                if not k.startswith("_"):
                    walk(v, (pfx + "." + k) if pfx else k)
    walk(dev)


def _inform(dev):
    return (dev.get("_lastInform", "?") or "?")[:19]


def cmd_acs_status(base, args):
    dev = _acs_device(base, _acs_pick(base, args.id))
    root = _root(dev); di = root + ".DeviceInfo"
    wan = _p_wan(root); w = _node(dev, _p_wlan(root)) or {}
    hosts = _rows(dev, _p_hosts(root))
    active = sum(1 for _, h in hosts if _truthy(_nval(h.get("Active"))))
    print("Model       : %s  (hw %s)" % (_param(dev, di + ".ModelName"), _param(dev, di + ".HardwareVersion")))
    print("Firmware    : %s" % _param(dev, di + ".SoftwareVersion"))
    print("Uptime      : %s" % _hms(_param(dev, di + ".UpTime")))
    print("WAN         : %s   IP %s" % (_param(dev, wan + ".ConnectionStatus"), _param(dev, wan + ".ExternalIPAddress")))
    print("Wi-Fi       : %s  (%s, ch %s, %s)" % (
        _nval(w.get("SSID")), "on" if _truthy(_nval(w.get("Enable"))) else "off",
        _nval(w.get("Channel")), _acs_wifi_sec(w)))
    print("Clients     : %d active  (%d known)" % (active, len(hosts)))
    print("Last inform : %s UTC" % _inform(dev))


def cmd_acs_clients(base, args):
    dev = _acs_device(base, _acs_pick(base, args.id))
    hosts = _rows(dev, _p_hosts(_root(dev)))
    active_total = sum(1 for _, h in hosts if _truthy(_nval(h.get("Active"))))
    rows = []
    for _, h in hosts:
        act = _truthy(_nval(h.get("Active")))
        if args.online and not act:
            continue
        rows.append((_nval(h.get("HostName")) or "Unknown", _nval(h.get("IPAddress")) or "",
                     _macnorm(_nval(h.get("MACAddress"))), _nval(h.get("AddressSource")) or "", act))
    print("%-24s %-15s %-17s %-6s %s" % ("NAME", "IP", "MAC", "SRC", "STATE"))
    for n, ip, mac, src, act in sorted(rows, key=lambda r: not r[4]):
        print("%-24s %-15s %-17s %-6s %s" % (n[:24], ip, mac, src, "online" if act else "offline"))
    print("\n%d active / %d known  [last inform %s UTC]" % (active_total, len(hosts), _inform(dev)))


def cmd_acs_wifi(base, args):
    did = _acs_pick(base, args.id)
    dev = _acs_device(base, did); wl = _p_wlan(_root(dev))
    changes = {}
    if args.ssid is not None:
        changes[wl + ".SSID"] = args.ssid
    if args.psk is not None:
        changes[wl + ".X_TP_PreSharedKey"] = args.psk
    if args.radio is not None:
        changes[wl + ".Enable"] = (args.radio == "on")
    if changes:
        print("Wi-Fi changes (via TR-069):")
        for k, v in changes.items():
            print("  %s = %s" % (k.split(".WLANConfiguration.1.")[-1], v))
        if args.dry_run:
            print("(dry-run: nothing sent)"); return
        if not args.yes and input("Apply? [y/N] ").strip().lower() != "y":
            print("aborted."); return
        body = {"name": "setParameterValues", "parameterValues": [[k, v] for k, v in changes.items()]}
        print("set: " + _acs_task(base, did, body)); return
    w = _node(dev, wl) or {}
    print("SSID       : %s" % _nval(w.get("SSID")))
    print("Status     : %s" % ("on" if _truthy(_nval(w.get("Enable"))) else "off"))
    print("Channel    : %s" % _nval(w.get("Channel")))
    print("Band / BW  : %s / %s" % (_nval(w.get("X_TP_Band")), _nval(w.get("X_TP_Bandwidth"))))
    print("Security   : %s" % _acs_wifi_sec(w))
    key = _nval(w.get("X_TP_PreSharedKey"))
    print("Password   : %s" % (key if key else "(write-only over TR-069 - read with local 'tpwrctl wifi')"))
    print("[cached from last inform %s UTC; 'acs refresh' to update]" % _inform(dev))


def cmd_acs_wan(base, args):
    dev = _acs_device(base, _acs_pick(base, args.id)); wan = _p_wan(_root(dev))
    for label, p in [("Status", "ConnectionStatus"), ("External IP", "ExternalIPAddress"),
                     ("Gateway", "DefaultGateway"), ("DNS", "DNSServers"),
                     ("MAC", "MACAddress"), ("Uptime", "Uptime")]:
        v = _param(dev, wan + "." + p)
        print("%-12s: %s" % (label, _hms(v) if p == "Uptime" else v))


def cmd_acs_firmware(base, args):
    dev = _acs_device(base, _acs_pick(base, args.id)); di = _root(dev) + ".DeviceInfo"
    print("Model    : %s" % _param(dev, di + ".ModelName"))
    print("Hardware : %s" % _param(dev, di + ".HardwareVersion"))
    print("Firmware : %s" % _param(dev, di + ".SoftwareVersion"))
    print("Uptime   : %s" % _hms(_param(dev, di + ".UpTime")))


def cmd_acs(args):
    base = _acs_base(args)
    handlers = {"devices": cmd_acs_devices, "status": cmd_acs_status, "clients": cmd_acs_clients,
                "wifi": cmd_acs_wifi, "wan": cmd_acs_wan, "firmware": cmd_acs_firmware,
                "reboot": cmd_acs_reboot, "refresh": cmd_acs_refresh,
                "get": cmd_acs_get, "set": cmd_acs_set, "params": cmd_acs_params}
    try:
        handlers[args.acs_cmd](base, args)
    except requests.exceptions.RequestException as e:
        sys.exit("cannot reach the ACS at %s (%s)\nRun this on the ACS host, or pass --acs-url / set $TPWRCTL_ACS." % (base, e))
    except RuntimeError as e:
        sys.exit("error: %s" % e)


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
        ("dev reboot", "reboot the router"),
        ("dev reset", "FACTORY RESET  (guarded; needs -y)"),
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
    wf.add_argument("--password", dest="psk", help="set the WPA2 pre-shared key")
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
    acs = sub.add_parser("acs", help="manage the router remotely via TR-069 (GenieACS ACS)")
    acs.add_argument("--acs-url", help="GenieACS NBI base URL (default http://localhost:7557 / $TPWRCTL_ACS)")
    asub = acs.add_subparsers(dest="acs_cmd", required=True)
    asub.add_parser("devices", help="list devices (CPEs) known to the ACS")
    ast_ = asub.add_parser("status", help="one-screen overview over TR-069"); ast_.add_argument("--id")
    acl = asub.add_parser("clients", help="connected LAN hosts over TR-069"); acl.add_argument("--id"); acl.add_argument("--online", action="store_true")
    awf = asub.add_parser("wifi", help="show Wi-Fi, or change it (--ssid/--password/--radio)"); awf.add_argument("--id")
    awf.add_argument("--ssid"); awf.add_argument("--password", dest="psk"); awf.add_argument("--radio", choices=["on", "off"])
    awf.add_argument("--dry-run", action="store_true"); awf.add_argument("-y", "--yes", action="store_true")
    awn = asub.add_parser("wan", help="WAN/Internet details over TR-069"); awn.add_argument("--id")
    asub.add_parser("firmware", help="firmware/model over TR-069").add_argument("--id")
    ap_ = asub.add_parser("params", help="dump the device's TR-069 parameters"); ap_.add_argument("--id")
    ag = asub.add_parser("get", help="read a TR-069 parameter"); ag.add_argument("param"); ag.add_argument("--id")
    aset = asub.add_parser("set", help="set a TR-069 parameter"); aset.add_argument("param"); aset.add_argument("value"); aset.add_argument("--id")
    arb = asub.add_parser("reboot", help="reboot the router via TR-069"); arb.add_argument("--id"); arb.add_argument("-y", "--yes", action="store_true")
    arf = asub.add_parser("refresh", help="refresh the device's parameters"); arf.add_argument("--id"); arf.add_argument("--object", default="")
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
