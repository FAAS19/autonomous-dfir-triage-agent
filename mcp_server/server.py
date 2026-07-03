import os
import re
import hashlib
import json
import pandas as pd
import yaml
from mcp.server.fastmcp import FastMCP
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
import uuid
from datetime import datetime, timezone

# Initialize FastMCP Server
mcp = FastMCP("triage_engine")

# ---------------------------------------------------------------------------
# Provenance helper (inline — server runs as a subprocess, no shared logger)
# ---------------------------------------------------------------------------

def _server_log_event(event_type: str, tool_execution_id: str, details: dict):
    """Write a provenance event to provenance.jsonl from the MCP server process."""
    log_file = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "outputs", "provenance.jsonl")
    )
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
        "event_type": event_type,
        "agent_id": "triage_engine",
        "tool_execution_id": tool_execution_id,
        "details": json.dumps(details),
    }
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


# ---------------------------------------------------------------------------
# Message normalisation (Phase 1 helper)
# ---------------------------------------------------------------------------

_GUID_RE = re.compile(
    r"\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?"
)
_TEMP_PATH_RE = re.compile(
    r"(C:\\Users\\[^\\]+\\AppData\\Local\\Temp|C:\\Windows\\Temp)[^\s]*",
    re.IGNORECASE,
)
_PID_RE = re.compile(r"\bpid\s*[:=]\s*\d+\b", re.IGNORECASE)


def _normalise(message: str) -> str:
    """Lowercase + strip GUIDs, temp paths, and PIDs for frequency stacking."""
    msg = message.lower()
    msg = _GUID_RE.sub("<guid>", msg)
    msg = _TEMP_PATH_RE.sub("<temppath>", msg)
    msg = _PID_RE.sub("pid:<pid>", msg)
    return msg.strip()


# ---------------------------------------------------------------------------
# Tool 1: read_evidence_manifest
# ---------------------------------------------------------------------------

@mcp.tool()
def read_evidence_manifest(file_path: str, expected_hash: str = None) -> dict:
    """Read and validate the evidence CSV. Returns metadata and SHA-256 hash."""
    if not os.path.exists(file_path):
        return {"error": "Insufficient evidence: File not found"}

    # Calculate SHA-256
    with open(file_path, "rb") as f:
        actual_hash = hashlib.file_digest(f, "sha256").hexdigest()
    if expected_hash and actual_hash != expected_hash:
        return {"error": "Evidence integrity check failed — hash mismatch"}

    try:
        df = pd.read_csv(file_path, nrows=5)  # Sample to get columns cheaply
    except Exception as e:
        return {"error": f"Failed to read CSV: {str(e)}"}

    tool_exec_id = str(uuid.uuid4())
    _server_log_event("tool_call", tool_exec_id, {"tool": "read_evidence_manifest", "file_path": file_path})
    return {
        "status": "success",
        "file_path": file_path,
        "row_count": sum(1 for _ in open(file_path, encoding="utf-8", errors="replace")) - 1,
        "columns": list(df.columns),
        "sha256_hash": actual_hash,
        "tool_execution_id": tool_exec_id,
    }


# ---------------------------------------------------------------------------
# Tool 2: upload_to_context_cache  (graceful fallback — Gap G11)
# ---------------------------------------------------------------------------

@mcp.tool()
def upload_to_context_cache(file_path: str) -> dict:
    """Uploads the Super Timeline CSV to Gemini File API for context caching.
    Gracefully skips and logs if the File API is unavailable (e.g., free tier)."""
    tool_exec_id = str(uuid.uuid4())
    if not os.path.exists(file_path):
        return {"error": "File not found", "tool_execution_id": tool_exec_id}

    try:
        from google import genai
        client = genai.Client()
        uploaded_file = client.files.upload(file=file_path)
        _server_log_event("tool_call", tool_exec_id, {"tool": "upload_to_context_cache", "status": "success"})
        return {
            "status": "success",
            "message": "Successfully uploaded to context cache",
            "cache_name": uploaded_file.name,
            "file_uri": uploaded_file.uri,
            "tool_execution_id": tool_exec_id,
        }
    except Exception as e:
        # Graceful fallback — log and continue without context cache
        _server_log_event(
            "cache_upload_skipped",
            tool_exec_id,
            {"tool": "upload_to_context_cache", "reason": str(e)},
        )
        return {
            "status": "skipped",
            "message": f"Context cache unavailable: {str(e)}. Pipeline continues without cache.",
            "cache_name": None,
            "file_uri": None,
            "tool_execution_id": tool_exec_id,
        }


# ---------------------------------------------------------------------------
# Tool 3: run_frequency_filter  (Phase 1 — Stacking)  — Gaps G5, G6, G7
# ---------------------------------------------------------------------------

@mcp.tool()
def run_frequency_filter(file_path: str, frequency_threshold: int = 100) -> dict:
    """Phase 1 — Frequency Stacking.

    Normalises the 'message' column (lowercase, strip GUIDs/temp paths/PIDs),
    counts frequency of each normalised form, and tags high-frequency events
    as is_filtered=true (benign noise). Returns row-level objects for the
    long-tail rare events that pass to Phase 2.
    """
    try:
        df = pd.read_csv(file_path)
    except Exception as e:
        return {"error": f"Failed to read CSV: {str(e)}"}

    # Identify the message column (Plaso CSV variations)
    target_col = next(
        (c for c in ["message", "desc", "command_line"] if c in df.columns), None
    )
    if target_col is None:
        return {"error": f"Missing target column. Available: {list(df.columns)}"}

    # Build a stable original_log_id from the row index
    df = df.reset_index(drop=True)
    df["original_log_id"] = df.index.astype(str)

    # Normalise messages
    df["message_normalized"] = df[target_col].fillna("").astype(str).map(_normalise)
    df["message_original"] = df[target_col].fillna("").astype(str)

    # Count normalised-form frequency
    freq_counts = df["message_normalized"].value_counts()
    df["frequency_count"] = df["message_normalized"].map(freq_counts)

    # Tag high-frequency rows as filtered (benign noise)
    df["is_filtered"] = df["frequency_count"] > frequency_threshold

    filtered_count = int(df["is_filtered"].sum())
    long_tail_df = df[~df["is_filtered"]]

    # Return row-level objects for long-tail events (unique by normalised form)
    seen_normalised = set()
    long_tail_rows = []
    for _, row in long_tail_df.iterrows():
        norm = row["message_normalized"]
        if norm in seen_normalised:
            continue
        seen_normalised.add(norm)
        long_tail_rows.append({
            "original_log_id": row["original_log_id"],
            "message_original": row["message_original"],
            "message_normalized": norm,
            "frequency_count": int(row["frequency_count"]),
            "is_filtered": False,
        })

    tool_exec_id = str(uuid.uuid4())
    _server_log_event("tool_call", tool_exec_id, {"tool": "run_frequency_filter", "filtered": filtered_count})
    return {
        "status": "success",
        "total_rows": len(df),
        "filtered_rows": filtered_count,
        "remaining_rows": len(df) - filtered_count,
        "long_tail_count": len(long_tail_rows),
        "unique_normalized_forms": len(seen_normalised),
        "frequency_threshold_used": frequency_threshold,
        "long_tail_rows": long_tail_rows,  # Row-level objects — feeds Phase 2
        "tool_execution_id": tool_exec_id,
    }


# ---------------------------------------------------------------------------
# SIGMA Cache for Anomaly Detection Prioritization
# ---------------------------------------------------------------------------

_cached_sigma_rules = None

def _load_sigma_rules():
    global _cached_sigma_rules
    if _cached_sigma_rules is not None:
        return _cached_sigma_rules
    
    import pickle
    rules_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "sigma_rules"))
    cache_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "sigma_rules_cache.pkl"))
    
    use_cache = False
    if os.path.exists(cache_path) and os.path.exists(rules_dir):
        try:
            cache_mtime = os.path.getmtime(cache_path)
            max_mtime = 0
            for root_dir, _, files in os.walk(rules_dir):
                for file in files:
                    if file.endswith((".yml", ".yaml")):
                        mtime = os.path.getmtime(os.path.join(root_dir, file))
                        if mtime > max_mtime:
                            max_mtime = mtime
            if cache_mtime >= max_mtime:
                use_cache = True
        except Exception:
            use_cache = False
            
    if use_cache:
        try:
            with open(cache_path, "rb") as f:
                _cached_sigma_rules = pickle.load(f)
            return _cached_sigma_rules
        except Exception:
            pass

    _cached_sigma_rules = []
    if os.path.exists(rules_dir):
        for root_dir, _, files in os.walk(rules_dir):
            for file in files:
                if file.endswith((".yml", ".yaml")):
                    try:
                        with open(os.path.join(root_dir, file), "r", encoding="utf-8") as f:
                            rule = yaml.safe_load(f)
                        if rule and "detection" in rule:
                            _cached_sigma_rules.append(rule)
                    except Exception:
                        pass
                        
    try:
        with open(cache_path, "wb") as f:
            pickle.dump(_cached_sigma_rules, f, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception:
        pass
        
    return _cached_sigma_rules


def _has_sigma_match(message: str) -> bool:
    """Checks if the message matches any of the cached SIGMA rules."""
    rules = _load_sigma_rules()
    for rule in rules:
        detection = rule.get("detection", {})
        
        def search_dict(d, target):
            for k, v in d.items():
                if isinstance(v, str) and v.lower() in target.lower():
                    return True
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, str) and item.lower() in target.lower():
                            return True
                elif isinstance(v, dict):
                    if search_dict(v, target):
                        return True
            return False
            
        try:
            if search_dict(detection, message):
                return True
        except Exception:
            pass
    return False


def _cluster_anomalies(anomalies: list, threshold: float = 0.4) -> list:
    """Groups anomalies into clusters based on Jaccard similarity of token sets.
    Assigns a 'cluster_id' (integer) to each anomaly.
    """
    def tokenize(s: str) -> set:
        # Split by non-alphanumeric characters, lowercase, filter out digits and empty
        tokens = {t.lower() for t in re.split(r'[^a-zA-Z0-9]', s) if t and not t.isdigit() and len(t) > 1}
        return tokens

    token_sets = [tokenize(a.get("message", "")) for a in anomalies]
    clusters = []
    
    for i, a in enumerate(anomalies):
        tokens_a = token_sets[i]
        assigned_cluster = None
        
        # Compare with existing clusters to find a match
        for cluster_id, cluster_members in enumerate(clusters):
            # Check if it matches any member of this cluster
            for member_idx in cluster_members:
                tokens_b = token_sets[member_idx]
                if not tokens_a and not tokens_b:
                    sim = 1.0
                elif not tokens_a or not tokens_b:
                    sim = 0.0
                else:
                    intersection = len(tokens_a.intersection(tokens_b))
                    union = len(tokens_a.union(tokens_b))
                    sim = intersection / union
                
                if sim >= threshold:
                    assigned_cluster = cluster_id
                    break
            if assigned_cluster is not None:
                break
                
        if assigned_cluster is None:
            assigned_cluster = len(clusters)
            clusters.append([i])
        else:
            clusters[assigned_cluster].append(i)
            
        a["cluster_id"] = assigned_cluster
        
    return anomalies


# ---------------------------------------------------------------------------
# Tool 4: run_anomaly_detection  (Phase 2 — NLP Embeddings + Isolation Forest)
# Gaps G8, G9, G10
# ---------------------------------------------------------------------------

@mcp.tool()
def run_anomaly_detection(messages: list) -> dict:
    """Phase 2 — NLP Embeddings + Isolation Forest.

    Accepts a list of row objects: [{original_log_id, message_original, ...}]
    OR a list of plain strings (legacy). Generates embeddings and scores each
    row with Isolation Forest. Returns per-row anomaly scores with original_log_id
    and a per-row embedding_hash for reproducibility.

    Primary: Google text-embedding-004 via google-genai SDK.
    Fallback: TfidfVectorizer (offline) — fallback is logged to provenance.jsonl.
    """
    if not messages:
        return {"error": "No messages provided"}

    # Normalise input — accept both row-objects and plain strings
    if isinstance(messages[0], dict):
        rows = messages
        texts = [r.get("message_normalized") or r.get("message_original", "") for r in rows]
    else:
        rows = [{"original_log_id": str(i), "message_original": m} for i, m in enumerate(messages)]
        texts = messages

    embedding_model = "tfidf-fallback"
    fallback_triggered = False

    try:
        from google import genai
        client = genai.Client()
        response = client.models.embed_content(
            model="text-embedding-004",
            contents=texts,
        )
        X = [e.values for e in response.embeddings]
        embedding_model = "text-embedding-004"
    except Exception as api_err:
        fallback_triggered = True
        vectorizer = TfidfVectorizer(max_features=512)
        try:
            X = vectorizer.fit_transform(texts).toarray().tolist()
        except Exception as e:
            return {"error": f"Vectorization failed: {str(e)}"}

    # Isolation Forest scoring
    clf = IsolationForest(contamination=0.1, random_state=42)
    clf.fit(X)
    scores = clf.decision_function(X)

    # Build per-row output with per-row embedding_hash (Gap G10)
    anomalies = []
    for i, (row, score, vec) in enumerate(zip(rows, scores, X)):
        # Per-row embedding hash for reproducibility
        vec_str = str(vec[:10])  # Use first 10 dims for a stable fingerprint
        row_embedding_hash = hashlib.sha256(vec_str.encode()).hexdigest()
        
        msg = row.get("message_original", texts[i])
        
        # Priority bonus if it matches a SIGMA rule
        final_score = float(score)
        if _has_sigma_match(msg):
            final_score -= 10.0
            
        anomalies.append({
            "original_log_id": row.get("original_log_id", str(i)),
            "message": msg,
            "anomaly_score": final_score,
            "embedding_model_used": embedding_model,
            "embedding_hash": row_embedding_hash,
        })

    # Sort by anomaly_score ascending (most negative = most anomalous first)
    anomalies.sort(key=lambda x: x["anomaly_score"])

    # Cluster the top 50 anomalies to assign cluster_id
    top_50 = anomalies[:50]
    _cluster_anomalies(top_50)

    tool_exec_id = str(uuid.uuid4())

    # Log fallback event to provenance.jsonl if triggered (Gap G8)
    if fallback_triggered:
        _server_log_event(
            "fallback_triggered",
            tool_exec_id,
            {
                "tool": "run_anomaly_detection",
                "embedding_model_used": "tfidf-fallback",
                "reason": "text-embedding-004 API unreachable",
            },
        )

    _server_log_event("tool_call", tool_exec_id, {"tool": "run_anomaly_detection", "rows_scored": len(anomalies)})
    return {
        "status": "success",
        "embedding_model_used": embedding_model,
        "top_anomalies": top_50,  # Top-K most anomalous (now with cluster_id)
        "tool_execution_id": tool_exec_id,
    }


# ---------------------------------------------------------------------------
# Tool 5: search_sigma_rules  (Phase 3 — SIGMA Enrichment)
# ---------------------------------------------------------------------------

@mcp.tool()
def search_sigma_rules(command_line: str) -> dict:
    """Phase 3 — Matches the command line against bundled SIGMA rules.
    Returns MITRE ATT&CK tactic + technique for each match."""
    rules_dir = os.path.join(os.path.dirname(__file__), "sigma_rules")
    matches = []

    if os.path.exists(rules_dir):
        for root, _, files in os.walk(rules_dir):
            for file in files:
                if file.endswith((".yml", ".yaml")):
                    try:
                        with open(os.path.join(root, file), "r", encoding="utf-8") as f:
                            rule = yaml.safe_load(f)

                        detection = rule.get("detection", {})

                        def search_dict(d, target):
                            for k, v in d.items():
                                if isinstance(v, str) and v.lower() in target.lower():
                                    return True
                                elif isinstance(v, list):
                                    for item in v:
                                        if isinstance(item, str) and item.lower() in target.lower():
                                            return True
                                elif isinstance(v, dict):
                                    if search_dict(v, target):
                                        return True
                            return False

                        if search_dict(detection, command_line):
                            tags = rule.get("tags", [])
                            mitre_tactic = "Unknown"
                            mitre_technique = "Unknown"
                            for tag in tags:
                                if tag.startswith("attack.t"):
                                    mitre_technique = tag.replace("attack.", "").upper()
                                elif tag.startswith("attack.") and not tag.startswith("attack.t"):
                                    mitre_tactic = tag.replace("attack.", "").title()

                            matches.append({
                                "sigma_rule_name": rule.get("title", file),
                                "sigma_rule_id": rule.get("id", file.replace(".yml", "")),
                                "mitre_tactic": mitre_tactic,
                                "mitre_technique_id": mitre_technique,
                                "sigma_severity": rule.get("level", "medium"),
                            })
                    except Exception:
                        pass

    tool_exec_id = str(uuid.uuid4())
    _server_log_event("tool_call", tool_exec_id, {"tool": "search_sigma_rules", "matches": len(matches)})
    return {
        "status": "success",
        "matches": matches,
        "tool_execution_id": tool_exec_id,
    }


# ---------------------------------------------------------------------------
# Tool 6: query_timeline  (Ad-hoc pivot / temporal context)
# ---------------------------------------------------------------------------

@mcp.tool()
def query_timeline(query: str, file_path: str = "cases/timeline.csv", limit: int = 50) -> dict:
    """Searches the timeline CSV for rows containing the query string (case-insensitive).
    Used by the Log Analyst for temporal pivoting (before/after an anomaly)."""
    if not os.path.exists(file_path):
        return {"error": f"File not found: {file_path}"}

    try:
        df = pd.read_csv(file_path)
    except Exception as e:
        return {"error": f"Failed to read CSV: {str(e)}"}

    mask = pd.Series(False, index=df.index)
    for col in df.select_dtypes(include=["object"]):
        mask |= df[col].astype(str).str.contains(query, case=False, na=False)

    results = df[mask].head(limit)

    tool_exec_id = str(uuid.uuid4())
    _server_log_event("tool_call", tool_exec_id, {"tool": "query_timeline", "query": query, "matches": int(mask.sum())})
    return {
        "status": "success",
        "matches_found": int(mask.sum()),
        "returned_rows": len(results),
        "results": results.to_dict(orient="records"),
        "tool_execution_id": tool_exec_id,
    }


# ---------------------------------------------------------------------------
# Tool 7: threat_intel_lookup  (Threat intelligence lookup)
# ---------------------------------------------------------------------------

@mcp.tool()
def threat_intel_lookup(query: str) -> dict:
    """Perform a threat intelligence lookup on a query (e.g. process name, registry key, or tool name)
    to enrich forensic anomalies with MITRE tactics and remediation guidance."""
    query_lower = query.lower()
    intel = {}
    if "cain" in query_lower:
        intel = {
            "tool": "Cain & Abel",
            "category": "Credential Access / Password Cracker",
            "description": "Cain & Abel is a password recovery tool for Microsoft Operating Systems. It allows easy recovery of various kind of passwords by sniffing the network, cracking encrypted passwords using Dictionary, Brute-Force and Cryptanalysis attacks.",
            "mitre_tactic": "Credential Access",
            "mitre_technique_id": "T1110"
        }
    elif "ethereal" in query_lower or "wireshark" in query_lower:
        intel = {
            "tool": "Ethereal / Wireshark",
            "category": "Discovery / Network Sniffing",
            "description": "Ethereal (now Wireshark) is a popular packet analyzer used for network troubleshooting, analysis, software and communications protocol development, and education. It can capture packets in real-time.",
            "mitre_tactic": "Credential Access / Discovery",
            "mitre_technique_id": "T1040"
        }
    elif "look@lan" in query_lower or "netstumbler" in query_lower:
        intel = {
            "tool": "Look@LAN / NetStumbler",
            "category": "Discovery / Network Scanning",
            "description": "Active network scanning and mapping tools used to discover live hosts, open ports, and wireless access points in range.",
            "mitre_tactic": "Discovery",
            "mitre_technique_id": "T1046"
        }
    elif "cuteftp" in query_lower:
        intel = {
            "tool": "CuteFTP",
            "category": "Exfiltration",
            "description": "Standard FTP client commonly abused by threat actors to exfiltrate compressed files and folders to remote staging servers.",
            "mitre_tactic": "Exfiltration",
            "mitre_technique_id": "T1048"
        }
    elif "123wasp" in query_lower:
        intel = {
            "tool": "123WASP",
            "category": "Credential Access",
            "description": "A legacy password recovery tool designed to extract cached credentials from Windows applications and systems.",
            "mitre_tactic": "Credential Access",
            "mitre_technique_id": "T1003"
        }
    else:
        intel = {
            "status": "No threat intel records found in database",
            "query": query
        }
    
    tool_exec_id = str(uuid.uuid4())
    _server_log_event("tool_call", tool_exec_id, {"tool": "threat_intel_lookup", "query": query})
    return {
        "status": "success",
        "intel": intel,
        "tool_execution_id": tool_exec_id
    }


if __name__ == "__main__":
    mcp.run()
