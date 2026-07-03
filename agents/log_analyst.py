import os
from dotenv import load_dotenv
load_dotenv()

from google.adk.agents import Agent
from google.adk.agents.callback_context import CallbackContext
from google.genai import types as genai_types
from pydantic import BaseModel, Field
from typing import Literal, Optional


# ---------------------------------------------------------------------------
# Output Schema — analysis_output (02_data_schemas.yaml)
# Includes passthrough fields so the validator can verify source provenance.
# ---------------------------------------------------------------------------

class AnalysisOutput(BaseModel):
    # Passthrough fields (Gap G15) — carry the source context forward
    original_log_id: str = Field(description="Pass through from tool output — the row ID of the analysed log entry")
    message: str = Field(description="The raw log message that was analysed")
    anomaly_score: float = Field(description="The Isolation Forest score from the anomaly detection tool")

    # Analyst-generated fields
    risk_score: int = Field(ge=1, le=100, description="Risk score from 1 to 100")
    confidence_score: Literal["HIGH", "MEDIUM", "LOW"] = Field(
        description="Confidence: HIGH=SIGMA-backed, MEDIUM=clear pattern, LOW=ambiguous"
    )
    mitre_tactic: str = Field(description="MITRE ATT&CK Tactic (e.g., Execution, Persistence)")
    mitre_technique_id: str = Field(description="MITRE ATT&CK Technique ID (e.g., T1059.001)")
    analyst_rationale: str = Field(
        description="Evidence-based rationale. Cite ONLY strings present verbatim in the provided log entry."
    )
    sigma_rule_id: Optional[str] = Field(
        default=None,
        description="SIGMA Rule ID if matched, null if analyst-inferred"
    )
    false_positive_flag: bool = Field(
        description="True if this is likely a benign false positive"
    )
    tool_execution_id: str = Field(
        description="MUST exactly match the tool_execution_id from the anomaly detection tool output"
    )


# ---------------------------------------------------------------------------
# Callback: inject current anomaly into agent state before each LLM call
# ---------------------------------------------------------------------------

async def prepare_anomaly_for_analyst(callback_context: CallbackContext):
    """Loads the current anomaly packet into state variables for prompt interpolation."""
    ctx = callback_context
    anomaly = ctx.state.get("current_anomaly", {})

    ctx.state["anomaly_original_log_id"] = anomaly.get("original_log_id", "unknown")
    ctx.state["anomaly_message"] = anomaly.get("message", "").replace("\\", "\\\\")
    ctx.state["anomaly_score"] = anomaly.get("anomaly_score", 0.0)
    ctx.state["sigma_matches"] = anomaly.get("sigma_matches", [])
    ctx.state["threat_intel"] = anomaly.get("threat_intel") or "None"
    ctx.state["tool_execution_id"] = anomaly.get("tool_execution_id", "missing")
    # Cache name for temporal context queries (may be None if File API was unavailable)
    ctx.state["cache_name"] = anomaly.get("cache_name") or "unavailable"


# ---------------------------------------------------------------------------
# Load the DFIR Triage skill instructions from .agents/skills/dfir_triage/
# ---------------------------------------------------------------------------

skill_path = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", ".agents", "skills", "dfir_triage", "SKILL.md")
)
# Load the full DFIR Triage skill — it defines the analyst's role, rules,
# pivoting guide, and structured output format (aligned with AnalysisOutput schema).
skill_instructions = ""
if os.path.exists(skill_path):
    with open(skill_path, "r", encoding="utf-8") as f:
        skill_instructions = f.read()


# ---------------------------------------------------------------------------
# Model configuration — supports OpenRouter via environment variable (Gap G14)
#
# To use OpenRouter, set in .env:
#   LOG_ANALYST_MODEL=openai/anthropic/claude-sonnet-4-5
#   OPENAI_API_KEY=<your OpenRouter key>
#   OPENAI_BASE_URL=https://openrouter.ai/api/v1
#
# Falls back to gemini-2.5-flash if LOG_ANALYST_MODEL is not set.
# ---------------------------------------------------------------------------

from google.adk.models.lite_llm import LiteLlm

LOG_ANALYST_MODEL = os.getenv("LOG_ANALYST_MODEL", "gemini-2.5-flash")

if LOG_ANALYST_MODEL.startswith("gemini"):
    model_param = LOG_ANALYST_MODEL
else:
    model_param = LiteLlm(model=LOG_ANALYST_MODEL)


# ---------------------------------------------------------------------------
# Log Analyst Agent
# ---------------------------------------------------------------------------

log_analyst_agent = Agent(
    name="log_analyst",
    model=model_param,
    instruction=f"""
{skill_instructions}

---

## CURRENT ANOMALY TO ANALYSE

You have been given a single pre-processed anomaly from the DFIR triage pipeline.
This anomaly survived Phase 1 (frequency stacking) and Phase 2 (Isolation Forest scoring),
meaning it is a statistically rare event that warrants expert review.

**Original Log ID**: {{anomaly_original_log_id}}
**Raw Log Message**: {{anomaly_message}}
**Anomaly Score**: {{anomaly_score}}  (more negative = more anomalous; range -1 to 0)
**SIGMA Rule Matches**: {{sigma_matches}}
**Threat Intelligence Lookup Enrichment**: {{threat_intel}}
**Tool Execution ID**: {{tool_execution_id}}

---

## CONTEXT CACHE

{"A reference to the full Super Timeline is available for temporal context queries." if True else ""}
**Cache Reference**: {{cache_name}}

If the cache_name is not 'unavailable', you may query the Gemini context cache to retrieve
events occurring immediately before or after this anomaly to establish the full attack chain.
If it is 'unavailable', work solely from the provided log entry.

---

## YOUR TASK

1. Determine if this artifact is **malicious** or a **benign false positive**.
2. Assign `risk_score` (1–100) and `confidence_score` (HIGH/MEDIUM/LOW).
3. Map to MITRE ATT&CK (`mitre_tactic`, `mitre_technique_id`). Use the exact standard MITRE ATT&CK tactic names (e.g. 'Defense Evasion' (with a space, NOT 'Defense-Evasion'), 'Initial Access', 'Command and Control', 'Lateral Movement', 'Credential Access', 'Execution', 'Discovery'). Choose the tactic and technique matching the log source category:
   - Registry changes / registry execution entries: Defense Evasion or Credential Access.
   - Browser history logs / cached HTTP requests: Initial Access, Command and Control, or Defense Evasion. Do NOT map to Execution (T1204 / T1059) unless the log describes process starting or binary execution. For standard browser-cached images (.jpg, .gif) with atypical user fields (like mr. evil), map them to Defense Evasion (T1027 for steganography / obfuscated information) or Initial Access (T1189 for drive-by compromise), rather than Command & Control (T1071.001) or Ingress Tool Transfer (T1105), unless there is explicit evidence of tool binary transfer. For internal browser pages (like 'about:Home' or 'about:blank') containing atypical user fields (like 'Mr. Evil'), map them to Defense Evasion (T1027 for masquerading / obfuscated information) rather than Initial Access (T1189), since they represent internal browser operations.
   - Process creation logs / executables execution: Execution. For executions of legitimate installer or uninstaller binaries (such as wise32.exe or unwise.exe) from normal system locations, map them to Execution (T1204.002 for User Execution) if they are flagged as anomalous. Do NOT map generic installer/uninstaller executions to WMI (T1047) unless the wmic utility is explicitly invoked.
   - Shortcuts / LNK files: Execution or Defense Evasion. Opening or executing standard local shortcut or help files (such as .lnk, .hlp, .chm) must never be mapped to Exfiltration (T1048) or Command and Control (T1071) unless there is direct evidence in the log message of external network data transfer. Instead, map them to Execution (T1204.002 for User Execution: Malicious File) or Defense Evasion (T1027.003 for Steganography/Obfuscation) if they are suspicious or disguised.
4. Write `analyst_rationale` describing only the facts in the raw log message. Do NOT copy, mention, or include matched SIGMA rule titles, file names, or technique ID names in the text of your rationale, as this violates strict grounding audits.
5. Set `false_positive_flag: true` if benign.
6. Pass through `original_log_id`, `message`, and `anomaly_score` unchanged in your output.

## CRITICAL RULES

- **tool_execution_id**: Your output MUST include the EXACT value shown above: `{{tool_execution_id}}`
- **No fabrication**: Do NOT reference IPs, filenames, registry keys, or usernames unless they
  appear verbatim in the **Raw Log Message** above. If uncertain, lower confidence and say so.
- **Confidence scoring**: HIGH only if SIGMA rule matched AND you agree with it.
- **Rationale grounding**: The text of your analyst_rationale must strictly refer only to entities present verbatim in the Raw Log Message. Do not quote rule titles or description metadata.
- **MITRE technique format**: `mitre_technique_id` MUST strictly match the pattern `Txxxx` or `Txxxx.yyy` (e.g. `T1059.001`, `T1048`) or be exactly `"Unknown"`. Do NOT add any textual name, comments, or extra characters inside this field.
- **MITRE tactic names**: `mitre_tactic` MUST be one of the standard tactics exactly: "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact", or "Unknown".
""",
    output_schema=AnalysisOutput,
    output_key="current_finding",
    include_contents="none",
    before_agent_callback=prepare_anomaly_for_analyst,
    generate_content_config=genai_types.GenerateContentConfig(
        temperature=0.1  # Low temperature — forensic analysis demands precision
    ),
)
