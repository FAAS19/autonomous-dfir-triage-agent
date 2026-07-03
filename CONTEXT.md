# Autonomous DFIR Agent - Project Context Map

> **AI Agent Instructions:** Start here. This is the "lazy loading" index for the Kaggle Capstone Autonomous DFIR project. Instead of reading every file in the repository, read this index to understand the project state and locate the specific documents you need.

## 1. Project Goal
To build an Autonomous Digital Forensics and Incident Response (DFIR) Triage Agent for a Kaggle competition. The agent ingests a unified Plaso Super Timeline CSV (containing MFT, Registry, Prefetch, and Windows Event artifacts), deterministically filters benign noise via Frequency Stacking, and uses NLP Embeddings + Isolation Forest anomaly detection to surface threats for LLM-powered SIGMA-enriched analysis.

## 2. The Architecture (V3 - Hybrid NLP)
We have abandoned basic clustering (DBSCAN) in favor of a rock-solid DFIR approach:
1. **Frequency Stacking:** Instantly drop normal commands executing >100 times.
2. **NLP Embeddings:** Map remaining commands to a semantic vector space using Transformer models.
3. **Isolation Forest:** Assign an anomaly score to the vectors.
4. **Log Analyst Agent:** Cross-reference the top 50 anomalies against SIGMA rules to generate a MITRE ATT&CK report.

## 3. Directory Map (Where to find things)

### 📄 `/specs/` (Core Software Design Documents)
*Load these files when you need to understand the exact rules, schemas, or behaviors of the system.*
- `01_architecture.md`: The detailed architectural pipeline and Kaggle Wow Factors.
- `02_data_schemas.yaml`: The exact input (CSV) and output JSON/YAML schemas for the tools and LLMs.
- `03_bdd_scenarios.md`: Edge cases and testing scenarios (Gherkin format).
- `05_agent_prompts.md`: The global system prompts for the Orchestrator, Log Analyst, and Validator agents.

### 📚 `/docs/` (Research & Brainstorming)
*Load these files to understand the "why" behind the architectural decisions.*
- `advanced_ml_research.md`: NLP (CmdCaliper/PASTRAL) vs Graph Neural Networks.
- `clustering_brainstorm.md`: Why we dropped DBSCAN for Isolation Forests.
- `sans_tools_research.md`: How we leverage EvtxECmd and SIGMA.

### 💻 `/mcp_server/` (Tool Layer - Pending)
*This is where the Python code for the `triage_engine` MCP server will live (5 read-only tools).*

### 🤖 `/agents/` (Multi-Agent Engine - Pending)
*This is where the Orchestrator and Log Analyst agent graphs/scripts will live.*

## 4. Current Status
**Status:** FINAL REVIEW COMPLETE. READY FOR SCAFFOLDING.
**Next Action:** Scaffold project structure and begin implementation.
