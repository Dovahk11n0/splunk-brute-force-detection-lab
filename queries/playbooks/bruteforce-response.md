# Incident Response Playbook — SMB Brute Force Authentication Attack

**Playbook ID:** IR-001  
**Version:** 1.0  
**Applies to:** Windows SMB brute force detected via Splunk (EventCode 4624/4625)  
**ATT&CK Techniques:** T1110 (Brute Force), T1078 (Valid Accounts), T1021.002 (SMB/Windows Admin Shares)

---

## Step 1 — Validate the Alert

**Goal:** Confirm this is a true positive, not a false positive.

Run `failed-logons.spl` and verify:
- [ ] Source IP is external or unexpected on the network
- [ ] Failure count exceeds normal user error threshold (>5 in short window)
- [ ] `Logon_Type` is `3` (network logon) — not type 2 (interactive/local)
- [ ] `Failure_Reason` is "Unknown user name or bad password" (not "Account locked out" or "Account expired")

**False positive indicators:**
- Source IP matches a known service account or backup system
- Failures are against multiple different accounts from one IP (may indicate misconfigured credentials, not attack)
- Failures only occurred at a single point in time with no pattern

If validated as true positive, proceed to Step 2.

---

## Step 2 — Determine Scope

Run `success-after-failures.spl`:
- [ ] Did the source IP achieve a successful logon (EventCode 4624) after the failures?
- [ ] What account was targeted?
- [ ] What is the timeframe from first failure to success?

Run `brute-force-summary.spl` to see full picture:
- [ ] How many accounts were targeted from this IP?
- [ ] Is the `outcome` field showing `COMPROMISED` or `ATTEMPTED_ONLY`?

**Escalate immediately if:** `outcome = COMPROMISED` — a successful logon occurred after brute force attempts.

---

## Step 3 — Containment

### If attack is ongoing:
Create an inbound Windows Defender Firewall rule to block the source IP:

```powershell
New-NetFirewallRule `
  -DisplayName "BLOCK - Brute Force Source" `
  -Direction Inbound `
  -RemoteAddress "192.168.56.103" `
  -Action Block `
  -Protocol Any
```

Verify the rule was applied:
```powershell
Get-NetFirewallRule -DisplayName "BLOCK - Brute Force Source"
```

### If account was compromised (EventCode 4624 confirmed):
- Disable the affected account immediately:
```powershell
Disable-LocalUser -Name "AccountName"
```
- Force password reset before re-enabling
- Review what the account accessed after the successful logon (check EventCode 4663, 5140 for file/share access)

---

## Step 4 — Escalation Criteria

Escalate to Tier 2 / Senior Analyst if any of the following are true:
- [ ] Successful authentication confirmed from the attacking IP
- [ ] Attack originated from inside the network (lateral movement indicator)
- [ ] Multiple accounts targeted in the same timeframe (credential stuffing vs single-account brute force)
- [ ] Targeted account has elevated privileges (admin, service account)
- [ ] Attacker IP appears in threat intelligence feeds

---

## Step 5 — Documentation

Record the following in your incident ticket:
