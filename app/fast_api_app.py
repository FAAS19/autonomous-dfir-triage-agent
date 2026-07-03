# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import contextlib
import os
import json
import logging
import re
from collections.abc import AsyncIterator

from a2a.server.tasks import InMemoryTaskStore
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from google.adk.cli.fast_api import get_fast_api_app
from google.adk.runners import Runner

from app.app_utils import services
from app.app_utils.a2a import attach_a2a_routes
from app.app_utils.typing import Feedback

load_dotenv()

# Setup standard logging (Ponytail: native Python standard library)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fastapi_app")

allow_origins = (
    os.getenv("ALLOW_ORIGINS", "").split(",") if os.getenv("ALLOW_ORIGINS") else None
)

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    from app import app as adk_app
    from app.agent import root_agent

    runner = Runner(
        app=adk_app,
        session_service=services.get_session_service(),
        artifact_service=services.get_artifact_service(),
        auto_create_session=True,
    )
    app.state.runner = runner
    app.state.agent_app_name = adk_app.name
    await attach_a2a_routes(
        app,
        agent=root_agent,
        runner=runner,
        task_store=InMemoryTaskStore(),
        rpc_path=f"/a2a/{adk_app.name}",
    )
    yield


app: FastAPI = get_fast_api_app(
    agents_dir=AGENT_DIR,
    web=True,
    artifact_service_uri=services.ARTIFACT_SERVICE_URI,
    allow_origins=allow_origins,
    session_service_uri=services.SESSION_SERVICE_URI,
    otel_to_cloud=False,
    lifespan=lifespan,
)
app.title = "capstone"
app.description = "API for interacting with the Agent capstone"


@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard():
    """Serves the Interactive Anomaly Visualizer Dashboard."""
    template_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "templates", "dashboard.html"))
    if os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Dashboard template not found at app/templates/dashboard.html</h1>"


@app.get("/api/findings")
def get_findings_json():
    """Parses and returns structured incident findings and provenance logs."""
    report_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "outputs", "dfir_triage_report.md"))
    prov_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "outputs", "provenance.jsonl"))

    report_content = ""
    findings = []
    if os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8") as rf:
            report_content = rf.read()

        # Parse findings from markdown
        sections = report_content.split("#### ")
        for sec in sections[1:]:
            lines = sec.split("\n")
            tech_match = re.match(r"\d+\. Technique ([^\s]+) — ([^\n]+)", lines[0])
            if not tech_match:
                continue
            tech, sourcetype = tech_match.groups()
            
            ts, user, host, severity, confidence, rule, log_id, score, raw, rationale = "", "", "", "", "", "", "", "", "", ""
            mode = ""
            raw_lines = []
            for l in lines[1:]:
                l_strip = l.strip()
                if l_strip.startswith("- **Timestamp**"):
                    ts = l_strip.split("Timestamp**:")[-1].strip().replace(" UTC", "")
                elif l_strip.startswith("- **Affected User**"):
                    user_match = re.search(r"`([^`]+)` on host `([^`]+)`", l_strip)
                    if user_match:
                        user, host = user_match.groups()
                elif l_strip.startswith("- **Risk & Confidence**"):
                    sev_match = re.search(r"Severity ([^\s|]+)[^|]*\| Confidence `([^`]+)`", l_strip)
                    if sev_match:
                        severity, confidence = sev_match.groups()
                elif l_strip.startswith("- **Detection Rule ID**"):
                    rule = l_strip.split("Detection Rule ID**:")[-1].strip().replace("`", "")
                elif l_strip.startswith("- **Log ID**"):
                    id_match = re.search(r"`([^`]+)` \| \*\*IF Anomaly Score\*\*:\s*`([^`]+)`", l_strip)
                    if id_match:
                        log_id, score = id_match.groups()
                elif l_strip.startswith("**Raw Artifact / Evidence:**"):
                    mode = "raw"
                elif l_strip.startswith("**Forensic Assessment:**"):
                    mode = "rationale"
                elif l_strip.startswith(">") and mode == "rationale":
                    rationale = l_strip.lstrip("> ").strip()
                    mode = ""
                elif mode == "raw":
                    if l_strip == "```":
                        if raw_lines:
                            raw = "\n".join(raw_lines)
                            mode = ""
                    else:
                        raw_lines.append(l)
            
            findings.append({
                "tech": tech,
                "sourcetype": sourcetype,
                "ts": ts,
                "user": user,
                "host": host,
                "severity": severity,
                "confidence": confidence,
                "rule": rule,
                "log_id": log_id,
                "score": score,
                "raw": raw,
                "rationale": rationale
            })

    provenance_logs = []
    if os.path.exists(prov_path):
        with open(prov_path, "r", encoding="utf-8") as pf:
            for line in pf:
                try:
                    record = json.loads(line.strip())
                    if isinstance(record.get("details"), str):
                        try:
                            record["details"] = json.loads(record["details"])
                        except Exception:
                            pass
                    provenance_logs.append(record)
                except Exception:
                    pass

    return {
        "report_markdown": report_content,
        "findings": findings,
        "provenance": provenance_logs
    }


@app.post("/feedback")
def collect_feedback(feedback: Feedback) -> dict[str, str]:
    """Collect and log feedback."""
    logger.info(f"Feedback Received: {json.dumps(feedback.model_dump())}")
    return {"status": "success"}


# Main execution
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
