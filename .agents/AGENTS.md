# Workspace Customizations

## Rules
- **Anti-Sycophancy**: NEVER agree with the user when they are wrong. Always push back with evidence. Only agree with evidence. Do not be sycophantic.
- **Saving Project Documentation**: When generating research, brainstorming, or documentation files intended for a project, always save these files directly to the appropriate project directory (e.g., `docs/`, `specs/`, or the repository root) rather than storing them exclusively as internal IDE artifacts.

## Project Conventions

### Stack & Dependencies
- **Python 3.11+** — type hints required on all function signatures
- **Google ADK** — multi-agent orchestration framework
- **google-genai** SDK — for Vertex AI `text-embedding-004` embeddings
- **scikit-learn TfidfVectorizer** — offline embedding fallback (replaces FastText)
- **scikit-learn** — Isolation Forest anomaly detection
- **PyYAML** — SIGMA rule parsing
- **structlog** — structured JSON logging throughout

### Coding Standards
- All MCP tools MUST return a `tool_execution_id` (UUID4) in every response.
- No raw shell access — tool wrappers only; never use `subprocess.run()` with user-supplied strings.
- All file operations on evidence are **read-only** — operate on in-memory copies. No evidence modification.
- **Evidence Formatting:** Plaso Super Timeline CSV (`log2timeline` output).
- **Context Constraints:** Upload the full Super Timeline to Gemini Context Caching via the `upload_to_context_cache` MCP tool. Agents query context through the cached content — no local SQLite.
- Every tool function must have a Google-style docstring with Args, Returns, and Raises sections.
- Use `pathlib.Path` for all file path operations (no raw string concatenation).
- Use `hashlib.sha256` for all integrity checks — no MD5.

### Architecture Reference
- **Source of truth:** `/specs/` folder (Spec-Driven Development — code is disposable, specs are permanent)
- **Data contracts:** `specs/02_data_schemas.yaml` defines all input/output schemas
- **Security enforcement:** Graph-level RBAC (tools assigned only to agents that need them) + read-only MCP tool design
- **Agent prompts:** `specs/05_agent_prompts.md` defines system prompts — do not hardcode prompts in Python

### Testing
- BDD scenarios in `specs/03_bdd_scenarios.md` are the test contract
- Write a failing test before fixing a bug
- Use `pytest` with fixtures for evidence CSV generation
