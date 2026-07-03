# BDD Scenarios (Gherkin) — V3 Hybrid NLP Architecture

> These scenarios define the expected behavior of the Autonomous DFIR Agent.
> They serve as the test contract for code generation and the evaluation baseline.

---

## Phase 1: Frequency Stacking

**Scenario:** Filtering high-frequency benign commands
**Given** an evidence CSV containing 10,000 rows where `svchost.exe -k netsvcs` appears 9,500 times
**And** the `frequency_threshold` is set to `100`
**When** the Orchestrator calls the `run_frequency_filter` tool
**Then** the tool tags the 9,500 `svchost.exe` rows as `is_filtered: true`
**And** returns the remaining 500 long-tail commands as `is_filtered: false`
**And** includes a summary: "Filtered 9,500/10,000 commands across 1 unique normalized form"
**And** every returned row includes a valid `tool_execution_id`

**Scenario:** All commands are unique (no filtering)
**Given** an evidence CSV containing 200 unique artifact messages (MFT, Registry, Event Logs), each appearing exactly once
**When** the Orchestrator calls `run_frequency_filter` with default threshold `100`
**Then** zero commands are filtered
**And** all 200 are passed to Phase 2 as long-tail

**Scenario:** Custom frequency threshold
**Given** an evidence CSV where `cmd.exe /c echo hello` appears 50 times
**When** the Orchestrator calls `run_frequency_filter` with `frequency_threshold: 25`
**Then** that message is filtered out (50 > 25)

---

## Phase 2: NLP Embeddings + Isolation Forest

**Scenario:** Detecting encoded PowerShell as anomalous
**Given** 50 long-tail commands from Phase 1, including 1 Base64 encoded PowerShell (`powershell.exe -enc SQBFAFgA...`)
**When** the Orchestrator calls `run_anomaly_detection`
**Then** the encoded PowerShell message receives an `anomaly_score < -0.5`
**And** it is included in the anomaly output
**And** the `embedding_model_used` field indicates which model generated the embedding

**Scenario:** Clean environment produces few anomalies
**Given** 100 long-tail messages that are all benign administrative actions
**When** the Orchestrator calls `run_anomaly_detection` with default threshold `-0.5`
**Then** the tool returns fewer than 5 anomalies (or zero)
**And** the Log Analyst receives an appropriately small analysis set

**Scenario:** Graceful fallback to local TF-IDF when Vertex AI is unreachable
**Given** the Google Cloud `text-embedding-004` API is unreachable (network error or invalid key)
**When** the Orchestrator calls `run_anomaly_detection`
**Then** the tool automatically falls back to the TfidfVectorizer offline model
**And** sets `embedding_model_used: "tfidf-fallback"` in each output row
**And** logs the fallback event to `provenance.jsonl`
**And** does NOT crash or return an unstructured error

---

## Phase 3: SIGMA Enrichment

**Scenario:** Matching a known attack pattern
**Given** an anomalous message `powershell.exe -encodedcommand SQBFAFgA...`
**When** the Orchestrator calls `search_sigma_rules` with that command
**Then** the tool returns a match: `sigma_rule_id: "proc_creation_win_powershell_encoded_cmd"`, `mitre_technique_id: "T1059.001"`, `mitre_tactic: "Execution"`
**And** the Log Analyst uses this SIGMA-backed mapping instead of inferring its own

**Scenario:** No SIGMA match for a novel artifact message
**Given** an anomalous message that does not match any bundled SIGMA rule
**When** the Orchestrator calls `search_sigma_rules`
**Then** the tool returns an empty match list for that command
**And** the Log Analyst infers its own MITRE mapping with `sigma_rule_id: null`
**And** sets `confidence_score: MEDIUM` or `LOW` (lower confidence without SIGMA backing)

---

## Agent Analysis

**Scenario:** Log Analyst produces a complete finding
**Given** the Log Analyst receives an anomaly with `anomaly_score: -0.82` and a SIGMA match for T1059.001
**When** the Log Analyst analyzes the artifact
**Then** it outputs a finding with all required `analysis_output` schema fields
**And** `risk_score` is between 1 and 100
**And** `confidence_score` is HIGH (SIGMA-backed)
**And** `analyst_rationale` references only data present in the provided log entry
**And** `tool_execution_id` matches the MCP tool's output

**Scenario:** Log Analyst correctly flags a false positive
**Given** a one-off benign action scores as anomalous
**When** the Log Analyst reviews the anomaly
**Then** the Log Analyst sets `false_positive_flag: true`
**And** assigns a low `risk_score` (< 20) with a clear rationale

---

## Validator Gate

**Scenario:** Validator passes a valid finding
**Given** the Log Analyst outputs a finding with a valid `tool_execution_id` matching an MCP log
**And** the rationale does not reference artifacts absent from the raw log
**When** the finding passes through the Validator
**Then** the finding is included in the final report

**Scenario:** Validator drops a hallucinated finding (missing provenance)
**Given** the Log Analyst outputs a finding about a malicious IP address
**And** that finding does not have a `tool_execution_id` matching any MCP tool log
**When** the report passes through the Validator
**Then** the finding is dropped from the final output
**And** the drop is logged to `provenance.jsonl` with `event_type: "finding_dropped"`

---

## Edge Cases

**Scenario:** Empty or missing evidence CSV
**Given** an empty CSV or missing file path is provided to the Orchestrator
**When** the Orchestrator calls `read_evidence_manifest`
**Then** the tool returns a structured error: "Insufficient evidence"
**And** the Orchestrator gracefully halts the pipeline
**And** no downstream tools or agents are invoked

**Scenario:** Evidence CSV fails hash validation
**Given** an evidence CSV whose SHA-256 hash does not match the expected value in the manifest
**When** the Orchestrator calls `read_evidence_manifest`
**Then** the tool returns: "Evidence integrity check failed — hash mismatch"
**And** the Orchestrator halts execution

**Scenario:** Provenance log is verifiable
**Given** a completed analysis with 15 provenance log entries
**When** an auditor reads provenance.jsonl
**Then** every event is sequentially recorded with a tool_execution_id

---

## Context Cache

**Scenario:** Loading evidence into the context cache
**Given** a valid CSV timeline file
**When** the Orchestrator calls the `upload_to_context_cache` tool
**Then** the tool successfully loads the file into memory
**And** returns a success message with the row count
**And** subsequent tools can query the cached data without reloading the file
