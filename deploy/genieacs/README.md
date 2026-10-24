# GenieACS — TR-069 ACS for the router

Runs a [GenieACS](https://genieacs.com/) Auto Configuration Server so the router can be
managed remotely over **TR-069/CWMP**. The router (CPE) connects *out* to this ACS; you drive
it with `tpwrctl acs …` (which talks to the GenieACS REST API locally).

## Services / ports
| Service | Port | Exposure |
|---|---|---|
| `cwmp` | **7547** | **public** — the router connects here (lock to your WAN egress IP, see below) |
| `nbi`  | 7557 | localhost — REST API that `tpwrctl acs` uses |
| `ui`   | 3000 | localhost — web UI (reach via SSH tunnel) |
| `fs`   | 7567 | localhost — firmware file server |
| `mongo`| 27017 | internal (compose network) |

## Deploy
```bash
cd deploy/genieacs
cp .env.example .env
sed -i "s/replace-.*/$(openssl rand -hex 32)/" .env     # set a real JWT secret
docker compose up -d --build
docker compose ps
curl -s localhost:7557/devices/        # [] until the router informs
```

## Lock down the public CWMP port
Docker publishes `7547` via its own iptables chain that **bypasses ufw**, so restrict it in
`DOCKER-USER` to the IP the router appears as (its public egress; for a double-NATed router
that's your site's public IP, *not* its private WAN IP):
```bash
PUB=<your-public-egress-ip>
sudo iptables -I DOCKER-USER ! -s "$PUB" -p tcp --dport 7547 -j DROP
# persist across reboots however you prefer (netfilter-persistent, a systemd unit, etc.)
```

## Point the router at this ACS
From a machine on the LAN (where `tpwrctl` can reach the router):
```bash
tpwrctl set MANAGEMENT_SERVER URL=http://<VM_PUBLIC_IP>:7547/
```
The router sends a BOOTSTRAP inform within seconds; `tpwrctl acs devices` then lists it.

## Manage it (run on the VM)
```bash
tpwrctl acs devices                                   # what the ACS sees, and whether it still informs
tpwrctl acs inform --interval 60                      # run queued tasks within a minute (default 300 s)
tpwrctl acs status --refresh                          # fresh one-screen overview
tpwrctl acs get  DeviceInfo.UpTime                    # read fresh from the router (root optional)
tpwrctl acs set  ManagementServer.PeriodicInformInterval 120   # write + read back
tpwrctl acs wifi --password 'new-key'                 # remembered in ~/.config/tpwrctl/acs-secrets.json
tpwrctl acs reboot                                    # reboot, wait for the BOOT inform
tpwrctl acs tasks                                     # queued tasks / faults (--clear cancels)
```

## Double-NAT note
This router sits behind an upstream NAT, so the ACS **cannot** send it on-demand connection
requests (its `ConnectionRequestURL` is a private address). Every task therefore runs at the
router's **next periodic inform**; `tpwrctl acs` waits for it (with a countdown) and confirms the
result, or `--no-wait` just queues. Lower `PeriodicInformInterval` (`acs inform --interval 60`) for
snappier control. Instant control would need TR-111 (STUN + UDP connection requests): a STUN
server here on UDP 3478, that port opened (ufw/iptables + the cloud security list) to the router's
egress IP, and STUN enabled on the router — not set up.

## Web UI (optional)
```bash
ssh -p 2022 -i <key> -L 3000:localhost:3000 ubuntu@<VM>
# then open http://localhost:3000  (first run: create a user in the UI)
```
