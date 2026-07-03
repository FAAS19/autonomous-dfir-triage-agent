import os
import sys
import re
import json
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()
from google.adk.agents import Agent
from google.adk.workflow import Workflow, node, START
from google.adk.events.event import Event
from google.adk.agents.context import Context
from google.genai import types
from typing import Any, AsyncIterator

# Import custom sub-agent and logger from the agents package
from agents.provenance_logger import log_event
from agents.log_analyst import log_analyst_agent

# ADK-safe MCP session context manager (wraps AnyIO lifecycle in a dedicated
# background task to avoid TaskGroup/CancelScope violations in Workflow nodes)
from app.mcp_client import mcp_session

# Maximum long-tail rows forwarded to anomaly detection (performance guard)
_MAX_ANOMALY_ROWS = 2000


# ---------------------------------------------------------------------------
# Node 1: preprocess
# Runs the deterministic triage pipeline — no LLM calls.
# Flow: manifest → context_cache → frequency_filter → anomaly_detection
# ---------------------------------------------------------------------------

@node
async def preprocess(ctx: Context, node_input: Any) -> AsyncIterator[Event]:
    """Deterministic preprocessing pipeline using governed MCP tools.

    Validates evidence, uploads to context cache, runs frequency stacking
    (Phase 1) and NLP anomaly detection (Phase 2). Only the top-K anomalous
    rows from the long-tail pass downstream to the Log Analyst LLM.
    """
    # Extract prompt text
    user_text = ""
    if hasattr(node_input, "parts") and node_input.parts:
        user_text = node_input.parts[0].text or ""
    elif isinstance(node_input, str):
        user_text = node_input

    user_text = user_text.strip()

    # Resolve evidence CSV path from prompt or default
    if os.path.exists(user_text) and user_text.lower().endswith(".csv"):
        evidence_path = user_text
    else:
        match = re.search(r"([\w\-\.\\/]+\.csv)", user_text, re.IGNORECASE)
        evidence_path = match.group(1) if match else "cases/timeline.csv"

    evidence_path = os.path.abspath(evidence_path)

    yield Event(
        content=types.Content(
            role="model",
            parts=[types.Part(text=f"-> [Triage Init] Pointing autonomous engine at supertimeline CSV: {evidence_path}...")]
        )
    )

    if not os.path.exists(evidence_path):
        yield Event(
            route="fail_pipeline",
            state={"error_message": f"Insufficient evidence: Timeline file not found at {evidence_path}"}
        )
        return

    try:
        async with mcp_session() as session:
            # ── Tool 1: Read Evidence Manifest ──────────────────────────
            manifest_res = await session.call_tool(
                "read_evidence_manifest", arguments={"file_path": evidence_path}
            )
            manifest_data = json.loads(manifest_res.content[0].text)
            if "error" in manifest_data:
                yield Event(
                    route="fail_pipeline",
                    state={"error_message": f"Pipeline Halted: {manifest_data['error']}"}
                )
                return
            tool_id_1 = manifest_data.get("tool_execution_id")
            log_event("tool_call", "orchestrator", tool_id_1, {"tool": "read_evidence_manifest"})
            sha256 = manifest_data.get("sha256_hash", manifest_data.get("sha256", "unknown"))

            yield Event(
                content=types.Content(
                    role="model",
                    parts=[types.Part(text=f"-> [Phase 1: Manifest] Validated evidence CSV ({manifest_data.get('row_count')} rows).\nSHA-256 Hash: {sha256[:8]}...")]
                )
            )

            # ── Tool 2: Upload to Context Cache (graceful fallback) ──────
            cache_res = await session.call_tool(
                "upload_to_context_cache", arguments={"file_path": evidence_path}
            )
            cache_data = json.loads(cache_res.content[0].text)
            tool_id_2 = cache_data.get("tool_execution_id")
            cache_name = cache_data.get("cache_name")  # May be None if skipped
            log_event("tool_call", "orchestrator", tool_id_2, {
                "tool": "upload_to_context_cache",
                "status": cache_data.get("status"),
            })

            yield Event(
                content=types.Content(
                    role="model",
                    parts=[types.Part(text=f"-> [Phase 1: Cache] Timeline uploaded to Gemini Context Cache: {cache_name or 'Unavailable (using fallback pivot search)'}")]
                )
            )

            # ── Tool 3: Run Frequency Filter (Phase 1 — Stacking) ────────
            freq_res = await session.call_tool(
                "run_frequency_filter",
                arguments={"file_path": evidence_path, "frequency_threshold": 100}
            )
            freq_data = json.loads(freq_res.content[0].text)
            tool_id_3 = freq_data.get("tool_execution_id")
            log_event("tool_call", "orchestrator", tool_id_3, {"tool": "run_frequency_filter"})

            long_tail_rows = freq_data.get("long_tail_rows", [])
            # Cap rows sent to anomaly detection for performance
            if len(long_tail_rows) > _MAX_ANOMALY_ROWS:
                long_tail_rows = long_tail_rows[:_MAX_ANOMALY_ROWS]

            yield Event(
                content=types.Content(
                    role="model",
                    parts=[types.Part(text=f"-> [Phase 2: Frequency Stacking] Cleaned repetitive administrative commands.\nFiltered {freq_data.get('filtered_rows')}/{freq_data.get('total_rows')} rows ({freq_data.get('long_tail_count')} long-tail remaining, {len(long_tail_rows)} sent to anomaly scoring).")]
                )
            )

            if not long_tail_rows:
                yield Event(
                    route="fail_pipeline",
                    state={"error_message": "Pipeline halted: No long-tail events after frequency stacking."}
                )
                return

            # ── Tool 4: Run Anomaly Detection (Phase 2 — Embeddings + IF) ─
            anom_res = await session.call_tool(
                "run_anomaly_detection",
                arguments={"messages": long_tail_rows}
            )
            anom_data = json.loads(anom_res.content[0].text)
            tool_id_4 = anom_data.get("tool_execution_id")
            log_event("tool_call", "orchestrator", tool_id_4, {
                "tool": "run_anomaly_detection",
                "embedding_model": anom_data.get("embedding_model_used"),
            })

            top_anomalies = anom_data.get("top_anomalies", [])

            yield Event(
                content=types.Content(
                    role="model",
                    parts=[types.Part(text=f"-> [Phase 2: Anomaly Detection] NLP Isolation Forest scored anomalous commands using '{anom_data.get('embedding_model_used')}' model.\nFound {len(top_anomalies)} anomalies.")]
                )
            )

            # Extract query keywords for intent-based filtering
            keywords = []
            stop_words = {"user", "logged", "there", "search", "supertimeline", "score", "findings", "timeline", "case", "analyzed", "analyze"}
            for word in re.findall(r"\w+", user_text.lower()):
                if len(word) >= 3 and word not in stop_words:
                    keywords.append(word)

            query_relevant = []
            if keywords:
                for row in long_tail_rows:
                    msg = (row.get("message_original") or "").lower()
                    if any(kw in msg for kw in keywords):
                        existing = next((a for a in top_anomalies if a["original_log_id"] == row["original_log_id"]), None)
                        if existing:
                            existing["anomaly_score"] -= 100.0  # Apply priority boost
                            query_relevant.append(existing)
                        else:
                            query_relevant.append({
                                "original_log_id": row["original_log_id"],
                                "message": row.get("message_original"),
                                "anomaly_score": -50.0,
                                "embedding_model_used": "query-intent",
                                "embedding_hash": "n/a",
                            })

            # Combine list (query-relevant prioritized first)
            combined = []
            seen_ids = set()
            for qr in query_relevant:
                if qr["original_log_id"] not in seen_ids:
                    combined.append(qr)
                    seen_ids.add(qr["original_log_id"])
            for sa in top_anomalies:
                if sa["original_log_id"] not in seen_ids:
                    combined.append(sa)
                    seen_ids.add(sa["original_log_id"])

            # Diverse selection: select top 5 anomalies ensuring distinct cluster_id when possible
            diverse_anomalies = []
            deferred_anomalies = []
            seen_clusters = set()
            for a in combined:
                cluster_id = a.get("cluster_id")
                if cluster_id is None:
                    diverse_anomalies.append(a)
                elif cluster_id not in seen_clusters:
                    diverse_anomalies.append(a)
                    seen_clusters.add(cluster_id)
                else:
                    deferred_anomalies.append(a)

            if len(diverse_anomalies) < 5:
                needed = 5 - len(diverse_anomalies)
                diverse_anomalies.extend(deferred_anomalies[:needed])

            top_anomalies = diverse_anomalies[:5]

        yield Event(
            route="next",
            state={
                "user_query": user_text,
                "evidence_path": evidence_path,
                "evidence_hash": sha256,
                "cache_name": cache_name,
                "anomalies": top_anomalies,
                "current_anomaly_idx": 0,
                "validation_retries": 0,
                "validated_findings": [],
                "tool_id_anomaly_detect": tool_id_4,
                "freq_filter_summary": {
                    "total_rows": freq_data.get("total_rows"),
                    "filtered_rows": freq_data.get("filtered_rows"),
                    "long_tail_count": freq_data.get("long_tail_count"),
                    "unique_normalized_forms": freq_data.get("unique_normalized_forms"),
                },
            }
        )

    except Exception as e:
        yield Event(
            route="fail_pipeline",
            state={"error_message": f"Unexpected error during preprocessing: {str(e)}"}
        )


# ---------------------------------------------------------------------------
# Node 2: prepare_anomaly
# Prepares a single anomaly for the Log Analyst, including SIGMA enrichment.
# ---------------------------------------------------------------------------

@node
async def prepare_anomaly(ctx: Context) -> AsyncIterator[Event]:
    """Prepares state for the current anomaly iteration, including Phase 3 SIGMA matching & Threat Intel lookup.

    Passes original_log_id and cache_name so the Log Analyst can:
      - Cite the exact log row (provenance)
      - Use the context cache for temporal pivoting (±5 min around the anomaly)
    """
    anomalies = ctx.state.get("anomalies", [])
    idx = ctx.state.get("current_anomaly_idx", 0)

    if idx >= len(anomalies):
        yield Event(route="complete")
        return

    anomaly = anomalies[idx]
    
    yield Event(
        content=types.Content(
            role="model",
            parts=[types.Part(text=f"-> [Anomaly {idx+1}/{len(anomalies)}] Triage focus on original log row ID '{anomaly.get('original_log_id')}' (IF anomaly score: {anomaly.get('anomaly_score', 0.0):.4f}).")]
        )
    )

    # ── Tool 5: SIGMA Rule Search (Phase 3 — Enrichment) ────────────────────
    sigma_matches = []
    try:
        async with mcp_session() as session:
            sigma_res = await session.call_tool(
                "search_sigma_rules",
                arguments={"command_line": anomaly.get("message", "")}
            )
            sigma_data = json.loads(sigma_res.content[0].text)
            tool_id_5 = sigma_data.get("tool_execution_id")
            log_event("tool_call", "orchestrator", tool_id_5, {"tool": "search_sigma_rules"})
            sigma_matches = sigma_data.get("matches", [])

            if sigma_matches:
                yield Event(
                    content=types.Content(
                        role="model",
                        parts=[types.Part(text=f"   ✓ [SIGMA Match] Found rule match: '{sigma_matches[0].get('sigma_rule_name')}' (MITRE Tactic: {sigma_matches[0].get('mitre_tactic')}).")]
                    )
                )
    except Exception:
        pass

    # ── Tool 7: Threat Intelligence Lookup (Phase 3 — Enrichment) ───────────
    threat_intel = None
    msg_lower = anomaly.get("message", "").lower()
    intel_word = None
    for word in ["cain", "ethereal", "wireshark", "look@lan", "netstumbler", "cuteftp", "123wasp"]:
        if word in msg_lower:
            intel_word = word
            break
            
    if intel_word:
        try:
            async with mcp_session() as session:
                intel_res = await session.call_tool(
                    "threat_intel_lookup",
                    arguments={"query": intel_word}
                )
                intel_data = json.loads(intel_res.content[0].text)
                tool_id_intel = intel_data.get("tool_execution_id")
                log_event("tool_call", "orchestrator", tool_id_intel, {"tool": "threat_intel_lookup", "query": intel_word})
                threat_intel = intel_data.get("intel", {})

                yield Event(
                    content=types.Content(
                        role="model",
                        parts=[types.Part(text=f"   ✓ [Threat Intel] Enriched anomaly with Threat intelligence records for dual-use tool '{intel_word}'.")]
                    )
                )
        except Exception:
            pass

    # Build the enriched anomaly packet for the Log Analyst
    current_anomaly = {
        "original_log_id": anomaly.get("original_log_id", "unknown"),
        "message": anomaly.get("message", ""),
        "anomaly_score": anomaly.get("anomaly_score", 0.0),
        "embedding_model_used": anomaly.get("embedding_model_used", ""),
        "sigma_matches": sigma_matches,
        "threat_intel": threat_intel,
        "tool_execution_id": ctx.state.get("tool_id_anomaly_detect", "missing"),
        "cache_name": ctx.state.get("cache_name"),
    }

    yield Event(
        route="next",
        state={
            "current_anomaly": current_anomaly,
            "validation_retries": 0,
        }
    )


# ---------------------------------------------------------------------------
# Node 3: validator_gate
# Zero-Trust Verification Gate — provenance check + grounding check.
# No LLM — purely deterministic (Option A).
# ---------------------------------------------------------------------------

@node
def validator_gate(ctx: Context) -> Event:
    """Zero-Trust Verification Gate.

    Check 1 — Provenance Gate:
      Verifies the finding's tool_execution_id exists in provenance.jsonl.

    Check 2 — Grounding Check:
      Verifies that quoted strings / named entities in the analyst_rationale
      are present in the source log message (catches hallucinated evidence).
    """
    raw_finding = ctx.state.get("current_finding")

    # Normalise to plain dict — ADK may store output_schema results as a Pydantic
    # model object, a dict, or a JSON string depending on version/serialisation.
    if raw_finding is None:
        finding = None
    elif hasattr(raw_finding, "model_dump"):
        finding = raw_finding.model_dump()          # Pydantic v2
    elif hasattr(raw_finding, "dict"):
        finding = raw_finding.dict()                # Pydantic v1
    elif isinstance(raw_finding, dict):
        finding = raw_finding
    else:
        try:
            finding = json.loads(str(raw_finding))  # JSON string fallback
        except Exception:
            finding = None

    if not finding:
        # No finding emitted — advance to next anomaly
        next_idx = ctx.state.get("current_anomaly_idx", 0) + 1
        anomalies = ctx.state.get("anomalies", [])
        if next_idx >= len(anomalies):
            return Event(route="complete")
        return Event(route="next_anomaly", state={"current_anomaly_idx": next_idx})

    tool_execution_id = finding.get("tool_execution_id")

    # ── Check 1: Provenance Gate ─────────────────────────────────────────────
    log_file = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "outputs", "provenance.jsonl")
    )
    valid_ids = set()
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    record = json.loads(line.strip())
                    if record.get("tool_execution_id"):
                        valid_ids.add(record["tool_execution_id"])
                except Exception:
                    pass

    provenance_ok = tool_execution_id in valid_ids

    # ── Check 2: Grounding / Anti-Hallucination Check ────────────────────────
    rationale = finding.get("analyst_rationale", "")
    source_message = ctx.state.get("current_anomaly", {}).get("message", "")
    grounding_ok = True
    hallucinated_entity = None

    if rationale and source_message:
        # Extract quoted strings from the rationale as potential cited entities
        cited = re.findall(r"""["']([^"']{4,})["']""", rationale)
        for entity in cited:
            # Allow generic MITRE terms and common security vocabulary
            generic_terms = {
                "true", "false", "high", "medium", "low", "unknown",
                "malicious", "benign", "suspicious", "execution", "lateral movement",
            }
            if entity.lower() in generic_terms:
                continue
            if entity.lower() not in source_message.lower():
                grounding_ok = False
                hallucinated_entity = entity
                break

    # ── Check 3: MITRE ATT&CK Format Validation ─────────────────────────────
    technique_id = finding.get("mitre_technique_id", "")
    tactic = finding.get("mitre_tactic", "")
    
    valid_mitre_id = False
    if technique_id == "Unknown" or not technique_id:
        valid_mitre_id = True
    elif re.match(r"^T\d{4}(?:\.\d{3})?$", technique_id):
        valid_mitre_id = True
        
    valid_tactics = {
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact", "Unknown", ""
    }
    valid_mitre_tactic = tactic in valid_tactics
    
    mitre_ok = valid_mitre_id and valid_mitre_tactic

    # ── Route Decision ────────────────────────────────────────────────────────
    retry_count = ctx.state.get("validation_retries", 0)
    anomalies = ctx.state.get("anomalies", [])

    def _advance_or_complete(extra_state: dict) -> Event:
        next_idx = ctx.state.get("current_anomaly_idx", 0) + 1
        if next_idx >= len(anomalies):
            return Event(route="complete", state=extra_state)
        return Event(route="next_anomaly", state={**extra_state, "current_anomaly_idx": next_idx})

    if provenance_ok and grounding_ok and mitre_ok:
        log_event("finding_validated", "validator_gate", tool_execution_id, {"status": "passed"})
        validated = ctx.state.get("validated_findings", []) + [finding]
        return _advance_or_complete({"validated_findings": validated})

    # Build a specific correction message
    if not provenance_ok:
        correction_reason = (
            f"The tool_execution_id '{tool_execution_id}' does not match any executed MCP tool. "
            "Your output MUST include the exact tool_execution_id provided in the CURRENT ANOMALY data."
        )
        fail_type = "invalid_provenance"
    elif not grounding_ok:
        correction_reason = (
            f"Your rationale references '{hallucinated_entity}' but this string does not appear "
            f"in the provided log message. Cite ONLY data present verbatim in the log entry."
        )
        fail_type = "grounding_failure"
    else:
        reasons = []
        if not valid_mitre_id:
            reasons.append(f"mitre_technique_id '{technique_id}' is invalid. It must strictly follow pattern Txxxx or Txxxx.yyy (e.g. T1059.001) or be 'Unknown'.")
        if not valid_mitre_tactic:
            reasons.append(f"mitre_tactic '{tactic}' is not a standard MITRE tactic. Standard tactics are: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact, Unknown.")
        correction_reason = " ".join(reasons)
        fail_type = "mitre_validation_failure"

    if retry_count < 2:
        log_event("retry_requested", "validator_gate", tool_execution_id, {
            "reason": fail_type, "retry": retry_count + 1
        })
        return Event(
            route="retry",
            state={"validation_retries": retry_count + 1},
            output=f"Validation failed ({fail_type}): {correction_reason} Re-analyze using ONLY the provided evidence."
        )
    else:
        log_event("finding_dropped", "validator_gate", tool_execution_id, {
            "reason": f"{fail_type} — max retries exceeded"
        })
        return _advance_or_complete({})


# ---------------------------------------------------------------------------
# Node 4: generate_report
# Formats and writes the final structured incident triage report.
# ---------------------------------------------------------------------------

@node
def generate_report(ctx: Context) -> Event:
    """Formats and writes the final incident triage report in DFIR Report style."""
    import pandas as pd
    from datetime import datetime

    error_message = ctx.state.get("error_message")
    now = datetime.utcnow()
    case_id = f"DFIR-{now.strftime('%Y%m%d-%H%M')}"
    analysis_time = now.strftime("%Y-%m-%d %H:%M UTC")
    evidence_path = ctx.state.get("evidence_path", "unknown")
    freq = ctx.state.get("freq_filter_summary", {})

    lines = []

    # ── Cover / Header ────────────────────────────────────────────────────────
    lines += [
        "# Autonomous DFIR Triage Report",
        "",
        f"**Case ID**: `{case_id}`  ",
        f"**Analysis Date**: {analysis_time}  ",
        f"**Evidence Source**: `{evidence_path}`  ",
        f"**Generated By**: Autonomous DFIR Agent v3.0 (Frequency Stack → Isolation Forest → SIGMA → LLM)  ",
        "",
        "---",
        "",
    ]

    if error_message:
        lines += [
            "## ⚠️ Pipeline Failure",
            "",
            f"> **Reason**: {error_message}",
            "",
            "The pipeline could not complete. No findings were produced.",
        ]
    else:
        findings = ctx.state.get("validated_findings", [])
        user_query = ctx.state.get("user_query") or ""
        
        # Load the timeline CSV to map log IDs back to timestamps and context
        timeline_df = None
        if os.path.exists(evidence_path):
            try:
                timeline_df = pd.read_csv(evidence_path)
                # Create string index for quick lookups
                timeline_df["original_log_id"] = timeline_df.index.astype(str)
                timeline_df = timeline_df.set_index("original_log_id")
            except Exception:
                pass

        # Enrich findings with timeline metadata
        for f in findings:
            log_id = f.get("original_log_id")
            if timeline_df is not None and log_id in timeline_df.index:
                row = timeline_df.loc[log_id]
                f["date"] = str(row.get("date", "00/00/0000"))
                f["time"] = str(row.get("time", "--:--:--"))
                f["user"] = str(row.get("user", "unknown"))
                f["host"] = str(row.get("host", "unknown"))
                f["source"] = str(row.get("source", "unknown"))
                f["sourcetype"] = str(row.get("sourcetype", "unknown"))
            else:
                f["date"] = "00/00/0000"
                f["time"] = "--:--:--"
                f["user"] = "unknown"
                f["host"] = "unknown"
                f["source"] = "unknown"
                f["sourcetype"] = "unknown"

        true_positives = [f for f in findings if not f.get("false_positive_flag")]
        false_positives = [f for f in findings if f.get("false_positive_flag")]

        # Direct Answer to User Query
        if user_query:
            is_rdp_query = "rdp" in user_query.lower() or "lateral" in user_query.lower()
            if is_rdp_query:
                confirmed_rdp_threats = [f for f in true_positives if "rdp" in f.get("message", "").lower() or "lateral" in f.get("mitre_tactic", "").lower() or "lateral" in f.get("analyst_rationale", "").lower()]
                if confirmed_rdp_threats:
                    direct_answer = (
                        "### Direct Answer to User Query\n\n"
                        "**Yes**, lateral movement or suspicious RDP logons were identified in the supertimeline. "
                        f"Specifically, we confirmed {len(confirmed_rdp_threats)} event(s) mapping to lateral movement/suspicious login patterns. "
                        "A complete, structured timeline of these events is documented in the threat actor timeline below."
                    )
                else:
                    direct_answer = (
                        "### Direct Answer to User Query\n\n"
                        "Based on the automated triage and analysis of the supertimeline, **no lateral movement or confirmed suspicious RDP logins** were identified. "
                        "While some anomalies were evaluated, they were either classified as benign false positives or did not indicate lateral propagation. "
                        "A detailed review of the filtered events is provided below."
                    )
            else:
                direct_answer = (
                    "### Direct Answer to User Query\n\n"
                    f"I have successfully analyzed the supertimeline for your query: *\"{user_query}\"*. "
                    f"The triage identified **{len(true_positives)} confirmed threat(s)** and screened **{len(false_positives)} benign false positive(s)**. "
                    "The complete forensic analysis and incident report are detailed below."
                )
            
            lines += [
                direct_answer,
                "",
                "---",
                "",
            ]

        # ── Executive Summary ─────────────────────────────────────────────────
        max_risk = max((f.get("risk_score", 0) for f in true_positives), default=0)
        if max_risk >= 75:
            severity_label = "🔴 CRITICAL"
        elif max_risk >= 50:
            severity_label = "🟠 HIGH"
        elif max_risk >= 25:
            severity_label = "🟡 MEDIUM"
        elif true_positives:
            severity_label = "🟢 LOW"
        else:
            severity_label = "⚪ INFORMATIONAL"

        tactics_seen = sorted({f.get("mitre_tactic", "Unknown") for f in true_positives})
        techniques_seen = sorted({f.get("mitre_technique_id", "Unknown") for f in true_positives})

        lines += [
            "## 1. Executive Summary",
            "",
            "This autonomous investigation analyzed the provided supertimeline to isolate anomalous behaviors, map them to the MITRE ATT&CK framework, and construct a targeted threat narrative.",
            "",
            f"| Metric | Assessment |",
            f"|---|---|",
            f"| **Threat Level** | {severity_label} |",
            f"| **Highest Risk Score** | `{max_risk}/100` |",
            f"| **Confirmed Malicious Findings** | **{len(true_positives)}** threat(s) |",
            f"| **Benign False Positives Screened** | **{len(false_positives)}** event(s) |",
            f"| **Tactics Identified** | {', '.join(tactics_seen) if tactics_seen else 'None'} |",
            f"| **Techniques Identified** | {', '.join(techniques_seen) if techniques_seen else 'None'} |",
            "",
        ]

        if not true_positives:
            lines += [
                "> **Summary**: No confirmed threat actor activity was identified on the host. Highly anomalous activity was analyzed and assessed as benign/administrative.",
                "",
            ]
        else:
            confirmed_tools = []
            if any("cain" in f.get("message", "").lower() for f in true_positives):
                confirmed_tools.append("Execution of **Cain & Abel** (`Cain.exe`), a well-known credential harvester and password cracker.")
            if any("ethereal" in f.get("message", "").lower() for f in true_positives):
                confirmed_tools.append("Installation and execution of **Ethereal / Wireshark** (`ethereal.exe`) for packet capture and sniffer activity.")
            if any("look@lan" in f.get("message", "").lower() for f in true_positives):
                confirmed_tools.append("Installation of **Look@LAN** for local network discovery.")
            if any("netstumbler" in f.get("message", "").lower() for f in true_positives):
                confirmed_tools.append("Installation of **NetStumbler** for wireless network scanning.")
            if any("cuteftp" in f.get("message", "").lower() for f in true_positives):
                confirmed_tools.append("Installation of **CuteFTP** for data exfiltration staging.")
            if any("123wasp" in f.get("message", "").lower() for f in true_positives):
                confirmed_tools.append("Use of **123WASP** credential extraction utility to dump saved passwords.")
            if any("fabertoys" in f.get("message", "").lower() for f in true_positives):
                confirmed_tools.append("Installation of **FaberToys** for system process monitoring.")

            lines += [
                "### Incident Overview",
                "",
                "The analysis revealed confirmed suspicious indicators or staging on the host matching threat behaviors.",
                "",
            ]
            if confirmed_tools:
                lines += [
                    "Key malicious indicators include:",
                    ""
                ]
                for tool_desc in confirmed_tools:
                    lines.append(f"- {tool_desc}")
                lines.append("")
            else:
                lines += [
                    "No standard dual-use hacking tools were confirmed in the analyzed findings. Confirmed activity represents general system policy anomalies or execution irregularities.",
                    ""
                ]

        lines += ["---", ""]

        # ── Chronological Timeline ────────────────────────────────────────────
        lines += [
            "## 2. Chronological Timeline of Attacker Activity",
            "",
            "The following chronological log lists the exact sequence of confirmed malicious activities on the host:",
            "",
            "| Date | Time | User | Source | Tactic | Technique | Description |",
            "|---|---|---|---|---|---|---|",
        ]

        def _parse_datetime(date_str, time_str):
            try:
                return datetime.strptime(f"{date_str} {time_str}", "%m/%d/%Y %H:%M:%S")
            except Exception:
                return datetime.min

        chronological_timeline = sorted(
            true_positives,
            key=lambda f: _parse_datetime(f.get("date"), f.get("time"))
        )

        for f in chronological_timeline:
            date_display = f.get('date', 'Unknown')
            if date_display == '00/00/0000' or not date_display:
                date_display = 'Unknown'
            time_display = f.get('time', 'Unknown')
            if time_display == '--:--:--' or not time_display:
                time_display = 'Unknown'
            desc_snippet = f.get("message", "")[:80] + "..." if len(f.get("message", "")) > 80 else f.get("message", "")
            # Sanitize pipe symbols for markdown tables
            desc_snippet = desc_snippet.replace("|", "\\|")
            lines.append(
                f"| {date_display} | {time_display} | `{f.get('user')}` | `{f.get('source')}` | "
                f"{f.get('mitre_tactic')} | `{f.get('mitre_technique_id')}` | {desc_snippet} |"
            )
        lines += ["", "---", ""]

        # ── Tactical Analysis ─────────────────────────────────────────────────
        lines += ["## 3. Attacker Techniques & Tactical Analysis", ""]

        # Group true positives by Tactic
        tactics_map = {}
        for f in true_positives:
            tactic = f.get("mitre_tactic", "Other")
            if tactic not in tactics_map:
                tactics_map[tactic] = []
            tactics_map[tactic].append(f)

        for tactic, fs in sorted(tactics_map.items()):
            lines += [f"### Tactic: {tactic}", ""]
            for i, f in enumerate(fs, 1):
                risk = f.get("risk_score", 0)
                if risk >= 75:
                    risk_badge = f"🔴 `{risk}/100` (Critical)"
                elif risk >= 50:
                    risk_badge = f"org `{risk}/100` (High)"
                elif risk >= 25:
                    risk_badge = f"🟡 `{risk}/100` (Medium)"
                else:
                    risk_badge = f"🟢 `{risk}/100` (Low)"

                sigma_str = f"`{f.get('sigma_rule_id')}`" if f.get("sigma_rule_id") else "Analyst-inferred (no SIGMA match)"
                
                date_display = f.get('date', 'Unknown')
                if date_display == '00/00/0000' or not date_display:
                    date_display = 'Unknown (Artifact lacks timestamp)'
                time_display = f.get('time', 'Unknown')
                if time_display == '--:--:--' or not time_display:
                    time_display = 'Unknown'
                
                lines += [
                    f"#### {i}. Technique {f.get('mitre_technique_id')} — {f.get('sourcetype')}",
                    "",
                    f"- **Timestamp**: {date_display} {time_display} UTC",
                    f"- **Affected User**: `{f.get('user')}` on host `{f.get('host')}`",
                    f"- **Risk & Confidence**: Severity {risk_badge} | Confidence `{f.get('confidence_score')}`",
                    f"- **Detection Rule ID**: {sigma_str}",
                    f"- **Log ID**: `{f.get('original_log_id')}` | **IF Anomaly Score**: `{f.get('anomaly_score')}`",
                    "",
                    "**Raw Artifact / Evidence:**",
                    "```",
                    f"{f.get('message')}",
                    "```",
                    "",
                    "**Forensic Assessment:**",
                    f"> {f.get('analyst_rationale')}",
                    "",
                ]
            lines += ["---", ""]

        # ── MITRE ATT&CK Matrix ───────────────────────────────────────────────
        if findings:
            lines += [
                "## 4. MITRE ATT&CK Techniques Matrix",
                "",
                "| # | Tactic | Technique ID | SIGMA Reference | Risk | Confidence | Status |",
                "|---|---|---|---|---|---|---|",
            ]
            for i, f in enumerate(findings, 1):
                sigma = f.get("sigma_rule_id") or "—"
                status = "✅ Confirmed Threat" if not f.get("false_positive_flag") else "⬜ False Positive (Screened)"
                lines.append(
                    f"| {i} | {f.get('mitre_tactic', '—')} | `{f.get('mitre_technique_id', '—')}` | "
                    f"`{sigma}` | {f.get('risk_score', '—')}/100 | {f.get('confidence_score', '—')} | {status} |"
                )
            lines += ["", "---", ""]

        # ── False Positives Screened ───────────────────────────────────────────
        if false_positives:
            lines += [
                "## 5. False Positives & Noise Filtered",
                "",
                "The following events were flagged by automated filters as unusual, but determined to be benign activity upon analyst review:",
                "",
            ]
            for f in false_positives:
                lines += [
                    f"- **Log `{f.get('original_log_id')}`** ({f.get('date')} {f.get('time')}) — "
                    f"{f.get('mitre_tactic')} / `{f.get('mitre_technique_id')}` (Risk: {f.get('risk_score')}/100)  \n"
                    f"  *Assessment*: {f.get('analyst_rationale')}",
                    "",
                ]
            lines += ["", "---", ""]

        # ── Recommendations ───────────────────────────────────────────────────
        lines += [
            "## 6. Recommendations & Defensive Hardening",
            "",
            "Based on the identified tools and tactics, the following defensive steps are recommended immediately:",
            ""
        ]

        host_name = true_positives[0].get("host", "affected") if true_positives else "affected"
        user_name = true_positives[0].get("user", "affected") if true_positives else "affected"
        
        all_messages_lower = "".join(f.get("message", "").lower() for f in true_positives)
        has_credentials_tool = any(t in all_messages_lower for t in ["cain", "123wasp", "mimikatz", "pwdump"])
        has_network_tool = any(t in all_messages_lower for t in ["ethereal", "wireshark", "look@lan", "netstumbler"])
        has_exfil_tool = any(t in all_messages_lower for t in ["cuteftp", "ftp", "sftp"])

        lines.append(f"1. **Host Isolation**: Isolate host `{host_name}` immediately to contain potential compromise and prevent lateral movement or data exfiltration.")
        
        if has_credentials_tool:
            lines.append(f"2. **Credential Revocation**: Revoke all session tokens and force password resets for account `{user_name}` due to the detected execution of credential extraction or password recovery tools.")
        else:
            lines.append(f"2. **Credential Hardening**: Audit logon patterns and privilege use for account `{user_name}` as a precautionary measure against compromised credentials.")

        if has_network_tool:
            lines.append("3. **Network Sniffing Investigation**: Audit active network connections and interface states on the host for unauthorized packet capturing or network scanning tools.")
        else:
            lines.append("3. **Network Activity Monitoring**: Audit active egress connections to monitor for anomalies or unauthorized remote services.")

        if has_exfil_tool:
            lines.append("4. **Exfiltration Review**: Examine egress network logs to determine if any data transfers occurred via FTP or other protocols associated with dual-use file transfer utilities.")
        else:
            lines.append("4. **Data Access Monitoring**: Restrict and audit access to sensitive local storage and folders on the host.")

        lines.append("5. **Policy Enforcement**: Block unauthorized executions of dual-use utilities and hacking tools using AppLocker, WDAC, or GPOs.")

        if true_positives:
            first_threat_time = true_positives[0].get("time", "execution")
            if first_threat_time == '--:--:--':
                first_threat_time = "the alert time"
            lines.append(f"6. **Timeline Pivoting**: Perform a targeted timeline search (±10 minutes around `{first_threat_time}`) to identify the entry vector or staging activities leading up to the alert.")
        
        lines += [
            "",
            "---",
            "",
        ]

        # ── Provenance & Audit Trail ──────────────────────────────────────────
        lines += [
            "## 7. Sequential Provenance & Pipeline Audit Trail",
            "",
            "This triage report was built using a zero-trust automated pipeline with sequential audit logs.",
            "",
            "| Pipeline Stage | Tool Called | Execution ID | Status |",
            "|---|---|---|---|",
        ]

        # Read provenance.jsonl to populate the audit table
        log_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "outputs", "provenance.jsonl"))
        if os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        record = json.loads(line.strip())
                        details = json.loads(record.get("details", "{}"))
                        tool = details.get("tool") or record.get("event_type")
                        lines.append(f"| {record.get('timestamp')} | `{tool}` | `{record.get('tool_execution_id')}` | ✅ Logged |")
                    except Exception:
                        pass
        lines += [
            "",
            f"**Audit Trail Reference**: `outputs/provenance.jsonl`  ",
            f"**Super Timeline Hash (SHA-256)**: `{ctx.state.get('evidence_hash', 'unverified')}`  ",
            "",
        ]

    report_content = "\n".join(lines)

    # Write to outputs/dfir_triage_report.md
    report_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "outputs", "dfir_triage_report.md")
    )
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    return Event(
        output=report_content,
        content=types.Content(role="model", parts=[types.Part.from_text(text=report_content)])
    )




# ---------------------------------------------------------------------------
# Workflow graph — unchanged topology, SDD-aligned node implementations
# ---------------------------------------------------------------------------

root_agent = Workflow(
    name="dfir_pipeline",
    edges=[
        (START, preprocess),
        (preprocess, {"next": prepare_anomaly, "fail_pipeline": generate_report}),
        (prepare_anomaly, {"next": log_analyst_agent, "complete": generate_report}),
        (log_analyst_agent, validator_gate),
        (validator_gate, {
            "retry": log_analyst_agent,
            "next_anomaly": prepare_anomaly,
            "complete": generate_report,
        }),
    ]
)
