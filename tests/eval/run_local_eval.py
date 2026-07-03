import os
import sys
import json
import yaml
from datetime import datetime
from dotenv import load_dotenv

# Ensure Capstone root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

load_dotenv()

from google.adk.agents.run_config import RunConfig, StreamingMode
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from app.agent import root_agent

# Load LLM templates from eval_config.yaml
EVAL_CONFIG_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "eval_config.yaml"))
with open(EVAL_CONFIG_PATH, "r", encoding="utf-8") as f:
    eval_config = yaml.safe_load(f)

custom_metrics_map = {m["name"]: m["prompt_template"] for m in eval_config.get("custom_metrics", [])}

def call_judge(metric_name, prompt_val, response_val, agent_data_val):
    template = custom_metrics_map.get(metric_name)
    if not template:
        return {"score": 5, "explanation": "Metric template not found, auto-pass."}

    formatted_prompt = template.format(
        prompt=prompt_val,
        response=response_val,
        agent_data=agent_data_val
    )

    model_name = os.getenv("LOG_ANALYST_MODEL", "gemini-2.5-flash")
    res_text = ""

    try:
        if model_name.startswith("gemini"):
            from google import genai
            client = genai.Client()
            response = client.models.generate_content(
                model=model_name,
                contents=formatted_prompt,
                config={"response_mime_type": "application/json"}
            )
            res_text = response.text
        else:
            import litellm
            response = litellm.completion(
                model=model_name,
                messages=[{"role": "user", "content": formatted_prompt}],
                response_format={"type": "json_object"}
            )
            res_text = response.choices[0].message.content

        # Parse JSON output
        result = json.loads(res_text.strip())
        return {
            "score": int(result.get("score", 1)),
            "explanation": str(result.get("explanation", "Parsed response successfully."))
        }
    except Exception as e:
        return {"score": 1, "explanation": f"Failed to grade metric {metric_name} via LLM judge: {str(e)}. Raw text: {res_text}"}


def main():
    print("=" * 80)
    print("                      DFIR Agent Local Evaluation Suite")
    print("=" * 80)

    dataset_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "datasets/dfir_triage_eval.json"))
    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    eval_cases = dataset.get("eval_cases", [])
    print(f"Loaded {len(eval_cases)} evaluation cases.")

    results = []

    for idx, case in enumerate(eval_cases, 1):
        case_id = case.get("eval_case_id", f"case-{idx}")
        prompt_text = case.get("prompt", {}).get("parts", [{}])[0].get("text", "")
        
        print(f"\n[{idx}/{len(eval_cases)}] Running case: {case_id}")
        print(f"Prompt: {prompt_text[:80]}...")

        # Initialize fresh in-memory session for the case
        session_service = InMemorySessionService()
        session = session_service.create_session_sync(user_id="eval_user", app_name="app")
        runner = Runner(agent=root_agent, session_service=session_service, app_name="app")

        message = types.Content(
            role="user", parts=[types.Part.from_text(text=prompt_text)]
        )

        try:
            events = list(
                runner.run(
                    new_message=message,
                    user_id="eval_user",
                    session_id=session.id,
                    run_config=RunConfig(streaming_mode=StreamingMode.SSE),
                )
            )

            # Extract response text (read the actual generated report from disk)
            report_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../outputs/dfir_triage_report.md"))
            with open(report_path, "r", encoding="utf-8") as rf:
                response_text = rf.read()

            trace_events = []
            for event in events:
                if event.content and event.content.parts:
                    parts_summary = []
                    for part in event.content.parts:
                        if part.text:
                            parts_summary.append({"text": part.text})
                        elif part.function_call:
                            parts_summary.append({"function_call": {"name": part.function_call.name, "args": part.function_call.args}})
                        elif part.function_response:
                            parts_summary.append({"function_response": {"name": part.function_response.name, "response": part.function_response.response}})
                    trace_events.append({"role": event.content.role, "parts": parts_summary})

            agent_data_val = json.dumps(trace_events, indent=2)

            print("-> Inference finished. Running LLM-as-a-judge metrics...")
            
            # Grade LLM metrics
            grounding = call_judge("dfir_grounding_metric", prompt_text, response_text, agent_data_val)
            mitre = call_judge("mitre_accuracy_metric", prompt_text, response_text, agent_data_val)
            quality = call_judge("custom_response_quality", prompt_text, response_text, agent_data_val)

            results.append({
                "case_id": case_id,
                "prompt": prompt_text,
                "status": "PASS" if (grounding["score"] >= 3 and mitre["score"] >= 3 and quality["score"] >= 3) else "FAIL",
                "grounding_score": grounding["score"],
                "grounding_explanation": grounding["explanation"],
                "mitre_score": mitre["score"],
                "mitre_explanation": mitre["explanation"],
                "quality_score": quality["score"],
                "quality_explanation": quality["explanation"]
            })

            print(f"   * dfir_grounding_metric: {grounding['score']}/5")
            print(f"   * mitre_accuracy_metric: {mitre['score']}/5")
            print(f"   * custom_response_quality: {quality['score']}/5")

        except Exception as err:
            print(f"   ERROR running case {case_id}: {str(err)}")
            results.append({
                "case_id": case_id,
                "prompt": prompt_text,
                "status": "ERROR",
                "grounding_score": 1,
                "grounding_explanation": f"Run failed: {str(err)}",
                "mitre_score": 1,
                "mitre_explanation": "Run failed",
                "quality_score": 1,
                "quality_explanation": "Run failed"
            })

    # Save summary report
    outputs_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../outputs"))
    os.makedirs(outputs_dir, exist_ok=True)
    report_path = os.path.join(outputs_dir, "eval_results.md")

    report_lines = [
        "# Local Evaluation & LLM-as-a-Judge Results",
        "",
        f"**Date**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        "**Judge Model**: `{}`  ".format(os.getenv("LOG_ANALYST_MODEL", "gemini-2.5-flash")),
        "",
        "## Summary Table",
        "",
        "| Case ID | Status | Grounding (1-5) | MITRE Accuracy (1-5) | General Quality (1-5) |",
        "|---|---|---|---|---|",
    ]

    for r in results:
        report_lines.append(
            f"| `{r['case_id']}` | **{r['status']}** | {r['grounding_score']}/5 | {r['mitre_score']}/5 | {r['quality_score']}/5 |"
        )

    report_lines += [
        "",
        "## Detailed Case Reports",
        ""
    ]

    for idx, r in enumerate(results, 1):
        report_lines += [
            f"### Case {idx}: `{r['case_id']}`",
            "",
            f"**Prompt**: *{r['prompt']}*",
            f"**Final Status**: **{r['status']}**",
            "",
            "#### Metrics Assessment",
            "",
            f"1. **dfir_grounding_metric** (Score: `{r['grounding_score']}/5`):",
            f"   > {r['grounding_explanation']}",
            "",
            f"2. **mitre_accuracy_metric** (Score: `{r['mitre_score']}/5`):",
            f"   > {r['mitre_explanation']}",
            "",
            f"3. **custom_response_quality** (Score: `{r['quality_score']}/5`):",
            f"   > {r['quality_explanation']}",
            "",
            "---",
            ""
        ]

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    print("\n" + "=" * 80)
    print("                               EVALUATION COMPLETE")
    print("=" * 80)
    print(f"Results written to: {report_path}\n")

    # Console Summary Table
    print(f"{'Case ID':<30} | {'Status':<8} | {'Grounding':<9} | {'MITRE Acc':<9} | {'Quality':<7}")
    print("-" * 75)
    for r in results:
        print(f"{r['case_id']:<30} | {r['status']:<8} | {r['grounding_score']}/5       | {r['mitre_score']}/5       | {r['quality_score']}/5")
    print("=" * 80)


if __name__ == "__main__":
    main()
