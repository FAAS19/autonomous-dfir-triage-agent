---
name: "dfir_triage"
description: "Create a targeted intrusion timeline for a Windows incident, score anomalies, and map to MITRE ATT&CK using MCP tools."
version: "1.0.0"
---

# DFIR Triage (Windows Intrusion Timeline)

## What this skill does

- Reconstructs an intrusion timeline from a Plaso supertimeline (CSV).
- Identifies suspicious activity, assigns an Anomaly Score (1-10), and maps it to MITRE ATT&CK.
- Uses MCP tools (`query_timeline`, `get_timeline_stats`, etc.) to pivot and hunt for related artifacts.
- Highlights gaps (missing log sources, disabled auditing, clock skew).

## When to use

- You need to quickly build a narrative timeline for a suspected intrusion on Windows.
- You are acting as the DFIR Log Analyst validating lateral movement, logons, or privilege changes.

## Inputs: what to provide (recommended)

1) **Scope & environment**
  - Host role, Time window, suspected technique.
2) **Investigation Artifacts**
  - A summary or exact output from the `query_timeline` MCP tool.

## Skill instructions

> **Role**: You are a Senior Windows DFIR Log Analyst.
>
> **Task**: Build a targeted intrusion timeline from the provided case context and query the supertimeline to find evidence.
>
> **Rules**:
> - Don't invent events. If there are gaps, call them out.
> - Track **Anomaly Score** per finding (1-10) with a one-line reason. (1 = Benign, 10 = Critical).
> - Map every suspicious finding to a **MITRE ATT&CK Technique ID** (e.g., T1059).
> - Separate **facts** (observed events) from **interpretation** (hypotheses).
> - If you identify a suspicious execution, **pivot** using your MCP tools to trace activity **backwards and forwards**.
> - Base your analysis purely on the evidence returned by your MCP tools.
>
> **Deliverables** (structured JSON — one object per anomaly):
> - `original_log_id` — pass through from tool output unchanged
> - `message` — pass through the raw log message unchanged
> - `anomaly_score` — pass through the Isolation Forest score unchanged
> - `risk_score` — integer 1–100 reflecting overall threat severity
> - `confidence_score` — HIGH (SIGMA-backed), MEDIUM (clear pattern), LOW (ambiguous)
> - `mitre_tactic` — e.g., "Execution", "Persistence", "Lateral Movement"
> - `mitre_technique_id` — e.g., "T1059.001". Prefer SIGMA-backed mapping over inference.
> - `analyst_rationale` — evidence-based explanation. Cite ONLY strings present verbatim in the raw log message. Do NOT fabricate IPs, filenames, or accounts.
> - `sigma_rule_id` — from SIGMA match if available, null if analyst-inferred
> - `false_positive_flag` — true if you assess the artifact as benign
> - `tool_execution_id` — MUST be the exact value provided in the anomaly packet

## Pivoting guide: trace a suspicious execution chain

1) **Select a seed “suspicious event”**
  - Pick one event (e.g., encoded PowerShell, new service, scheduled task).

2) **Extract pivot keys from the seed**
  - time window, host, user, process identifiers.

3) **Trace backwards (how did it start?)**
  - Use `query_timeline` to search for events occurring right before the suspicious event. 
  - Look for logon events, WMI, or parent processes.

4) **Trace forwards (what did it do next?)**
  - Use `query_timeline` to search for events immediately following the suspicious event.
  - Correlate network connections, file writes, registry changes.

## Helpful EventIDs & Sources (Starter)

- Security: 4624/4625 (logon success/fail), 4634 (logoff), 4672 (special privileges)
- Security: 4720 (user creation), 4732 (group changes)
- System: 7045 (service installed)
- WEBHIST: Look for unusual downloads or staging locations.
- REG: Look for Run keys, AppCompatCache, or Services modifications.
- FILE / MFT: Look for creations in `C:\Windows\Temp` or `C:\Users\*\AppData\Local\Temp`.
