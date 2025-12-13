# Detection Rule Breakdown and Triage Analysis

This document details the technical function of the Search Processing Language (SPL) query and the investigative steps (triage) taken to fully contextualize the detected attack.

## 1) Technical Breakdown of the SPL Rule

The following query transforms raw logs into actionable security intelligence:

```spl
index=main PortScan OR BotAttack OR Failure
| rex "(?<Source_IP>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[,\s]"
| stats count as Attack_Count by Source_IP
| where Attack_Count > 5
| sort -Attack_Count
```

## Breakdown of SPL Commands
### a) index=main PortScan OR BotAttack OR Failure

  Function: Initial log filter.

  Security Value: Limits the search scope to core security logs and event categories (PortScan, BotAttack, Failure).

### b) | rex "(?<Source_IP>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})[\\s,]"

Function: Runtime Field Extraction (REX).

Security Value: Creates the custom Source_IP field by matching the IP pattern at the beginning of the log line. This is crucial as the field was not indexed by default.

### c) | stats count as Attack_Count by Source_IP

Function: Aggregation.

Security Value: Groups all matching events by the newly extracted Source_IP and counts the total for each IP.

### d) | where Attack_Count > 5

Function: Thresholding.

Security Value: Filters out normal/acceptable noise by only returning IP addresses that exceeded 5 attack events. This is the core logic of the Brute-Force/Scan detection.

### e) | sort -Attack_Count

Function: Prioritization.

Security Value: Organizes the results to place the most prolific attackers at the top, enabling immediate security response focus.

## 2) Triage and Contextualization of the Attack
While the main rule identified 547 events from 192.168.8.114, further triage was necessary to determine the exact timeline of the attack (when it occurred).

### 1. Initial Visualization (Time Series)
Query Used: The detection rule was modified using | timechart span=1d count by Source_IP.

Result: The visualization revealed that the 547 events were not spread out, but highly concentrated in specific time periods (2018 and 2019). The overall largest visual spike for the IP 192.168.8.114 occurred on August 20, 2018.

### 2. Validation and Precision (Event Triage)
To validate the specific time of the attack, a highly targeted search was performed on the raw events for the identified attacker:

Query Used:
```spl
index=main PortScan OR Failure 
| regex _raw="192\\.168\\.8\\.114" 
| table _time, _raw 
| sort -_time
```

Result: The raw event log listing confirmed that the concentrated attack activity (408 attempts) occurred on August 20, 2018. The subsequent activity was seen as late as November 2019, confirming the attack lasted longer than a single day, but peaked significantly on that date.

### 3. Final Conclusion
The 192.168.8.114 attack was a severe Brute-Force or Port Scan event peaking on August 20, 2018. The automated alert ensures that any future attacker reaching this threshold is immediately flagged for response.
