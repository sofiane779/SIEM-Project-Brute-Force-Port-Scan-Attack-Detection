# Brute-Force / Port Scan Attack Detection

## Context
This project utilizes the Splunk Security Information and Event Management (SIEM) platform to analyze security logs containing threat categories (PortScan, BotAttack, Failure). The goal was to perform forensic analysis on historical data, identify a persistent threat, and operationalize the finding through a scheduled alert.

## Objective
1.  Identify the exact IP address responsible for the highest number of failed network connection attempts (Brute-Force/Port Scan).
2.  Determine the precise timeline and intensity (peak) of the attack.
3.  Implement a continuous, low-latency detection rule (Splunk Alert) to flag similar future behavior.

## Final Detection Rule (SPL)

The resulting rule effectively aggregates threats and applies a threshold to filter out normal network noise:

```spl
index=main PortScan OR BotAttack OR Failure
| rex "(?<Source_IP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[,\s]"
| stats count as Attack_Count by Source_IP
| where Attack_Count > 5
| sort -Attack_Count
```

## Analysis and Key Findings

Based on the execution of the detection rule and subsequent visualization (Triage), the following threat profile was established:

### Key Findings
* **Main Attacker IP:** `192.168.8.114`
* **Total Malicious Events:** 547 (Confirmed via visualization [SPLK_VISU2.png])
* **Attack Peak Date:** The most intense activity was concentrated on **August 20, 2018**.
* **Status:** Detection logic successfully implemented as a **Scheduled Splunk Alert**.

## Technical Deep Dive and Documentation

* **[Detailed Detection Breakdown](./DETECTION_BREAKDOWN.md)**: Explore the technical explanation of each Search Processing Language (SPL) command used in the rule (`| rex`, `| stats`, `| where`).
* **[Evidence Guide](./EVIDENCE/EVIDENCE_GUIDE.md)**: View the structured analysis of all screenshots, confirming the Triage steps and the alert implementation.

## 📁 Repository Structure

```
├── DETECTION_BREAKDOWN.md 
├── EVIDENCE/ 
|   ├── Splunk_alert.png  
|   ├── EVIDENCE_GUIDE.md  
|   ├── SPLK_VISU.png  
|   ├── SPLK_VISU2.png  
|   └── SPLK_RESULTS.png 
├── LICENSE 
└── README.md 
```



