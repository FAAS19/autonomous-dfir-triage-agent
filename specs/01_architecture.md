# Spec-Driven Development: Autonomous DFIR Agent — V3 Hybrid NLP Architecture

This document is the **Architectural North Star** for the Autonomous DFIR Agent, strictly adhering to the Spec-Driven Development (SDD) methodology defined in `docs/kaggle_course_synthesis.md` (Day 5).

## Background Information

The goal is to build an Autonomous DFIR Triage Agent for the Kaggle "AI Agents: Intensive Vibe Coding" Capstone Project (**Agents for Business** track). The system ingests massive volumes of a unified Super Timeline (Plaso format) containing Windows Event Logs, MFT, Registry, and Prefetch artifacts, deterministically filters benign noise using DFIR Frequency Stacking on artifact messages, generates NLP embeddings for rare artifacts, scores them with an Isolation Forest, and feeds the top anomalies to an LLM agent for SIGMA-enriched analysis. This eliminates analyst alert fatigue and guarantees zero-hallucination outputs via provenance-gated validation.

### Why Not DBSCAN?

The original V2 architecture used DBSCAN clustering, which was abandoned due to:
- **O(N²) memory:** Distance matrix causes OOM on 500K+ logs.
- **Parameter fragility:** `epsilon` and `min_samples` must be re-tuned per environment.
- See: `docs/clustering_brainstorm.md` for the full analysis.

## Technical Design

### 1. Evidence Layer (Immutable State)

- **Input Ingestion (Integration Boundary):**
  - Our agent relies on upstream governed DFIR MCP servers (such as **Agentropix MCP** or **MCP DFIR**) to extract raw host evidence (like binary `.evtx` files or disk captures) and parse them into standard, normalized formats.
  - **Supported Formats:** 
    1.  **Process Event Logs:** CSV files containing parsed Windows Event ID 4688 logs (columns: `timestamp`, `process_id`, `process_name`, `command_line`).
    2.  **Super Timelines:** Plaso (`log2timeline`) CSV files containing MFT, Registry, Prefetch, and Event log events consolidated into a single timestamped timeline (columns: `timestamp`, `source`, `source_type`, `message`, `command_line`, `user`).
- **Integrity:** SHA-256 hash computed on startup via `chain_of_custody.py`. Hash stored in `provenance.jsonl`.
- **Immutability:** All MCP tools operate on in-memory copies or local SQLite views. No tool may modify the original evidence CSV.

### 2. Tool Layer (MCP Server: `triage_engine`)

The MCP server exposes **5 read-only tools** that form the core analytical pipeline. All tools return a `tool_execution_id` for provenance tracking.

#### Tool 1: `read_evidence_manifest`
- **Purpose:** Read and validate the evidence CSV (Plaso Super Timeline). Upload it to the Gemini File API and cache it via Context Caching for efficient downstream context querying. Return metadata (row count, column names, SHA-256 hash).
- **Security:** Read-only. Rejects files that fail hash validation.

#### Tool 2: `run_frequency_filter` (Phase 1 — Stacking)
- **Purpose:** Normalize timeline signatures (message fields), hash, and count frequency.
- **Input:** Evidence CSV path, `frequency_threshold` (integer, default: `100`).
- **Logic:** Events with `frequency_count > threshold` are tagged as `is_filtered: true` (dropped as benign repetitive noise). The "long tail" (rare events) passes to Phase 2.
- **Output:** `frequency_filter_output` schema (see `02_data_schemas.yaml`).
- **Complexity:** O(N) — single pass.

#### Tool 3: `run_anomaly_detection` (Phase 2 — NLP + Isolation Forest)
- **Purpose:** Generate NLP embeddings for the long-tail events and score them with an Isolation Forest.
- **Embedding Strategy:**
   - **Primary:** Google Cloud `text-embedding-004` via `google-genai` SDK.
   - **Fallback:** TfidfVectorizer via scikit-learn (offline, lightweight).
- **Anomaly Scoring:** `scikit-learn` Isolation Forest. Returns `anomaly_score` (float, range -1 to 0 where more negative = more anomalous).
- **Output Filter:** Sorts by severity and extracts only the top $K$ (default: `50`) most anomalous entries to prevent context window bloat.
- **Output:** `anomaly_detection_output` schema (see `02_data_schemas.yaml`).

#### Tool 4: `upload_to_context_cache` (Gemini File API)
- **Purpose:** Uploads the entire Super Timeline CSV to Google's Gemini File API and initiates Context Caching. This completely eliminates the need for a local SQLite database.
- **Logic:** Calls `client.files.upload` to stage the CSV, then creates a Cached Content reference. The 2-million token context window of Gemini 1.5 Pro allows the agent to ingest the entire timeline directly and retrieve context instantly.
- **Output:** Returns the `cache_name` URI which is passed to the downstream agents.

#### Tool 5: `search_sigma_rules` (Phase 3 — SIGMA Enrichment)
- **Purpose:** Match anomalous timeline messages against a curated set of ~50 SIGMA rules.
- **Rules Source:** Bundled as YAML files in `mcp_server/sigma_rules/`.
- **Output:** List of matching `sigma_rule_id`, `sigma_rule_name`, `mitre_tactic`, `mitre_technique_id` per event.
- **Security:** Read-only. Rules are static files.

### 3. Multi-Agent Engine (ADK)

Three agents orchestrated as a directed graph:

#### Orchestrator Agent
- **Role:** DFIR investigation coordinator.
- **Responsibilities:**
  1. Call `read_evidence_manifest` to validate evidence.
  2. Call `run_frequency_filter` to eliminate noise.
  3. Call `run_anomaly_detection` to score rare commands.
  4. Call `search_sigma_rules` to enrich anomalies with MITRE mappings.
  5. Pass enriched anomalies to the Log Analyst.
  6. Record every tool call to the `provenance.jsonl` log.
- **Halts gracefully** if evidence is empty, missing, or fails hash validation.

#### Log Analyst Agent
- **Role:** Expert SOC Analyst.
- **Receives:** Anomalies with `anomaly_score`, `sigma_matches[]`, and raw `command_line`.
- **Outputs:** `analysis_output` schema with:
  - `risk_score` (1–100)
  - `confidence_score` (HIGH / MEDIUM / LOW)
  - `mitre_tactic` and `mitre_technique_id` (prefer SIGMA-backed mappings over inference)
  - `analyst_rationale` (evidence-based, citing only provided logs)
  - `sigma_rule_id` (if matched)
  - `false_positive_flag`
- **Constraint:** Analysis must be based *only* on provided logs and tool outputs. No external knowledge fabrication.

#### Validator Agent
- **Role:** Zero-Trust Verification Gate.
- **Checks:**
  1. **Provenance Gate:** Every finding must have a valid `tool_execution_id` matching an MCP tool log entry.
  2. **Self-Correction Loop:** If a finding fails validation, return a structured correction prompt to the Log Analyst (max 3 retries before permanent drop).
- **Output:** Validated findings only. Dropped findings are logged to `provenance.jsonl` with reason.

### 4. Provenance Layer (Sequential Audit Trail)

Every tool call and agent action is recorded in `provenance.jsonl`:
- **Fields:** `event_type`, `timestamp`, `agent_id`, `tool_execution_id`.
- **Audit Log:** Maintained as a sequential JSONL file.
- **Purpose:** Proves to Kaggle judges (and SOC managers) that no evidence was tampered with and no hallucinated findings survived.

### 5. Evaluation Framework (Quality Flywheel)

The agent's performance and accuracy are continuously evaluated using the Google ADK `agents-cli eval` pipeline.

- **Evaluation Dataset:** Static JSON datasets located in `tests/eval/datasets/` containing known true-positive threats (e.g., encoded PowerShell, lateral movement) and false-positive benign activities.
- **Metrics (LLM-as-Judge):**
  - `multi_turn_tool_use_quality`: Verifies the Orchestrator executes the pipeline tools in correct sequence.
  - `dfir_grounding_metric`: A custom LLMMetric that strictly fails any finding whose rationale references IPs, files, or registry keys not present in the tool output (Catching Hallucinations).
  - `mitre_accuracy_metric`: A custom LLMMetric verifying correct mapping to the MITRE ATT&CK framework.

## Kaggle Wow Factors (Rubric Maximizers)

To maximize points across Problem Definition (30pts) and Implementation (70pts):

1. **Interactive Anomaly Visualizer:** HTML/JS dashboard showing an anomaly score heatmap/timeline. Color-codes commands by `anomaly_score` severity. Filterable by MITRE tactic.
2. **Self-Healing Agent Loop:** Validator → Log Analyst retry loop (up to 3x), demonstrating the Quality Flywheel from Day 4.
3. **Adversarial Simulation:** `generate_attack_logs.py` blends LLM-generated Red Team command lines with benign traffic for controlled testing.
4. **Deployable Web UI:** Streamlit or Gradio app for uploading CSVs, watching streaming agent thoughts, and viewing the anomaly visualizer.
5. **Dockerized Deployment:** A `Dockerfile` and `docker-compose.yml` that bundles the ADK agents, MCP server, and Streamlit UI into a single click-to-run container environment to guarantee perfect Deployability scores.
6. **Sequential Provenance Trail:** Every finding has a traceable `tool_execution_id` from raw CSV to final report — offline verifiable via `provenance.jsonl`.
6. **Dual Embedding Fallback:** Demonstrates robustness — Google Cloud `text-embedding-004` primary, TF-IDF (scikit-learn) offline fallback. Graceful degradation, not hard failure.

## Key Concepts Demonstrated (Kaggle Rubric)

| Course Concept | Where Demonstrated |
|---|---|
| Agent / Multi-agent system (ADK) | Orchestrator + Log Analyst + Validator (3-agent directed graph) |
| MCP Server | `triage_engine` with 5 read-only tools, `tool_execution_id` provenance |
| Antigravity / Vibe Coding | Spec-driven workflow; this spec file; BDD scenarios; AGENTS.md |
| Security Features | Read-only evidence; no shell access; sequential provenance log |
| Deployability | `docker-compose up` one-click deployment; `run_case.py` CLI + Streamlit UI |
| Agent Skills | DFIR triage skill; SIGMA correlation skill; report synthesis skill |
