# Evidence — SMB Brute Force Detection Lab

## Incident Overview

| Field | Value |
|---|---|
| Date | Lab simulation |
| Attacker IP | 192.168.56.103 |
| Attacker Host | KALI |
| Target IP | 192.168.56.105 |
| Target System | Windows 10 VM |
| Protocol | SMB (Logon Type 3) |
| Targeted Account | GoldRoguer |
| Outcome | **COMPROMISED** — successful logon confirmed after failures |

## Timeline

| Time (relative) | Event | EventCode | Details |
|---|---|---|---|
| T+0:00 | First failed logon | 4625 | src: 192.168.56.103, account: GoldRoguer, reason: bad password |
| T+0:12 | Failed logon | 4625 | src: 192.168.56.103, account: GoldRoguer |
| T+0:24 | Failed logon | 4625 | src: 192.168.56.103, account: GoldRoguer |
| T+0:31 | Failed logon | 4625 | src: 192.168.56.103, account: GoldRoguer |
| T+0:38 | **Successful logon** | 4624 | src: 192.168.56.103, account: GoldRoguer, Logon_Type: 3 |

## Key Evidence Fields (EventCode 4625)
