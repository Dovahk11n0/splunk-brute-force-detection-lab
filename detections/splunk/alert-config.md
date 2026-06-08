# Splunk Alert — Possible Brute Force: Repeated Failed Logons

## Alert Name
`Possible brute force - failed logons`

## Search Query
```spl
index=wineventlog EventCode=4625
| eval src_ip=coalesce(Source_Network_Address, src_ip)
| stats count AS failed_attempts BY src_ip, Account_Name
| where failed_attempts > 5
```

## Schedule
- Run every: **5 minutes**
- Time window: **Last 10 minutes**

## Trigger Condition
- Number of results **greater than 0**
  (the `where` clause inside the search handles the threshold — any result that reaches this alert already has >5 failures)

## Severity
**High**

## Throttle
Suppress for **60 minutes** per `src_ip` to avoid alert flooding during active attack

## Recommended Actions on Trigger
1. Open the alert and note the `src_ip` and `Account_Name`
2. Run `success-after-failures.spl` to check for successful logon after failures
3. Follow `playbooks/bruteforce-response.md`

## Why This Threshold
5 failures in 10 minutes from one IP exceeds normal human error rate (1–2 mistyped passwords).
A lower threshold (e.g., 3) increases false positives from legitimate users; a higher threshold (e.g., 10) risks missing slow brute force attacks.
