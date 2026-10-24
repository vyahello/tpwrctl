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


def _macnorm(m):
    return (m or "").upper().replace("-", ":")


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
        cpu = r.get("PROC_STATUS", ["CPUUsage"]).get("CPUUsage", "?")
    except Exception:
        cpu = "?"
    devs = devices(r)
    on = [d for d in devs if d["active"]]
    print("Model        : %s  (hw %s)" % (info.get("modelName"), info.get("hardwareVersion")))
    print("Firmware     : %s   [built %s]" % (info.get("softwareVersion"), _fw_date(info.get("softwareVersion"))))
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


def cmd_wifi(r, args):
    a = r.getlist("LAN_WLAN_ASSOC_DEV")
    print("%-17s %-7s %-9s %-6s %-12s %s" % ("MAC", "SIGNAL", "LINKRATE", "STD", "BW", "TX/RX rate"))
    for d in a:
        print("%-17s %-7s %-9s %-6s %-12s %s/%s" % (
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
    tt = p.get("X_TP_TotalTime");
    if tt and tt.isdigit():
        secs = int(tt) // 100
        print("Uptime    : ~%dh %dm (approx, from CPU time)" % (secs // 3600, (secs % 3600) // 60))


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
    rows = r.getlist(args.oid) if args.gl else [r.get(args.oid, args.attrs or None)]
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
    r.set(args.oid, attrs)
    print("OK: set %s %s" % (args.oid, attrs))


# ----------------------------------------------------------------------------- telnet
# The TL-WR850N also exposes a restricted proprietary CLI on telnet/23 (password-only).
# It is NOT a Unix shell; it's a small command tree. Only one telnet session is allowed
# at a time, and the channel is plaintext. The web /cgi API is preferred for everything
# else; this wrapper is for the few things the CLI exposes directly.
_IAC, _DONT, _DO, _WONT, _WILL, _SB, _SE = 255, 254, 253, 252, 251, 250, 240
_PROMPT = re.compile(rb"TP-Link(\([^)]*\))?[#>]\s*$")
TELNET_HELP = """TP-Link TL-WR850N telnet CLI command reference (discovered):

  dev version          firmware version
  dev serial           serial number
  dev show             device info
  dev reboot           reboot the router
  dev reset            FACTORY RESET  (destructive; needs -y)
  lan show info        LAN configuration
  lan show status      LAN status
  wlctl show           wireless configuration / clients
  wlctl set [...]      change wireless (ssid/bandWidth/switch/sec/...); see 'wlctl'
  igmp ...             IGMP config
  clear | history | help | logout

Examples:
  tpwrctl telnet "dev version"
  tpwrctl telnet "lan show info" "wlctl show"
Note: not a shell - commands like cat/ls/ifconfig do NOT exist here."""


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
        print(TELNET_HELP)
        if not args.list:
            print("\n(no command given)")
        return
    for c in args.commands:
        if "reset" in c.lower() and not args.yes:
            sys.exit("refusing '%s' (looks like a factory reset). Re-run with -y to force." % c)
    for cmd, out in telnet_exec(host, password, args.commands):
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
    sub.add_parser("wifi", help="associated Wi-Fi clients + signal/rates").set_defaults(fn=cmd_wifi)
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
    g.add_argument("--json", action="store_true", help="raw JSON output")
    st = sub.add_parser("set", help="general web write: set OID attrs (attr=val ...)")
    st.set_defaults(fn=cmd_set); st.add_argument("oid"); st.add_argument("attrs", nargs="+")
    sub.add_parser("oids", help="list useful web-API objects (web counterpart of 'telnet --list')")
    tn = sub.add_parser("telnet", help="run command(s) in the router's telnet CLI")
    tn.add_argument("commands", nargs="*", help='e.g. "dev version" "lan show info"')
    tn.add_argument("--list", action="store_true", help="show the telnet CLI command reference")
    tn.add_argument("--raw", action="store_true", help="show unformatted CLI output")
    tn.add_argument("-y", "--yes", action="store_true", help="allow destructive commands (reset)")
    cf = sub.add_parser("config", help="save host+password to ~/.config/tpwrctl"); cf.set_defaults(fn=cmd_config)
    cf.add_argument("--host", default="192.168.1.1"); cf.add_argument("--password")

    args = ap.parse_args()
    if args.cmd == "config":
        return args.fn(None, args)
    if args.cmd == "oids":                       # reference only, no login needed
        print(WEB_OIDS); return
    if args.cmd == "telnet" and args.list and not args.commands:
        print(TELNET_HELP); return
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
