# lsass-access-detection-splunk
Detection of credential dumping via LSASS access using Sysmon Event ID 10 and Splunk SPL, mapped to MITRE ATT&amp;CK T1003 
# Credential Dumping Detection via LSASS Access (MITRE T1003)

This project focuses on detecting attempts to dump credentials by accessing the memory of the `lsass.exe` process. Tools like Mimikatz and Procdump commonly perform this behavior to extract password hashes and other sensitive authentication data from memory.

The detection logic is built using **Sysmon Event ID 10** (Process Access) and implemented in **Splunk SPL**, with enrichment for severity scoring, ATT&CK tagging, and a whitelist for legitimate access tools.

---

##  Objective

Detect malicious processes attempting to access `lsass.exe` memory in order to dump credentials.

This is mapped to:
- **MITRE ATT&CK Technique ID:** T1003
- **Technique:** OS Credential Dumping
- **Tactic:** Credential Access

## Data Source

- **Sysmon Event ID 10** — logs when one process attempts to access another.
- Synthetic logs were generated for simulation and testing, including both suspicious and benign access attempts.

---

##  Files Included

- `README.md` – this documentation
- `lsass_access_logs.csv` – synthetic sample data for testing
- `legit_access_tools.csv` – whitelist to reduce false positives

---

##  Detection Logic (Splunk SPL)

```spl
index="sysmon_lsass" 
| eval source_image=lower(Image), target_image=lower(TargetImage)
| search target_image="c:\\windows\\system32\\lsass.exe"
| lookup legit_access_tools.csv source_image AS source_image OUTPUT source_image AS legit_tool
| where isnull(legit_tool)
| eval severity=case(
    match(source_image, ".*mimikatz.*"), "critical",
    match(source_image, ".*procdump.*"), "high",
    match(source_image, ".*powershell.*"), "medium",
    1=1, "low"
)
| eval Tactic="Credential Access", Technique_ID="T1003", Technique="OS Credential Dumping"
| eval rule_name="LSASS Access Detection"
| table _time, User, Computer, source_image, target_image, GrantedAccess, severity, rule_name, Technique_ID, Technique, Tactic
```

## What This SPL Does:
Filters for any process accessing lsass.exe

Uses a lookup table to filter out known legitimate tools

Tags each event with a severity level based on the accessing process

Enriches each event with MITRE ATT&CK metadata

Outputs clean, readable fields for analyst triage or dashboarding

