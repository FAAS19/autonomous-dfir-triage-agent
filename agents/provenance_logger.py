import logging
import json
import os
from datetime import datetime

# Setup standard python logging
log_file = os.path.join(os.path.dirname(__file__), '..', 'outputs', 'provenance.jsonl')
os.makedirs(os.path.dirname(log_file), exist_ok=True)

logger = logging.getLogger("ProvenanceLogger")
logger.setLevel(logging.INFO)

# JSON Formatter
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": getattr(record, "event_type", "log"),
            "agent_id": getattr(record, "agent_id", "system"),
            "tool_execution_id": getattr(record, "tool_execution_id", None),
            "details": record.msg
        }
        return json.dumps(log_record)

file_handler = logging.FileHandler(log_file, mode='a')
file_handler.setFormatter(JsonFormatter())
logger.addHandler(file_handler)

def log_event(event_type: str, agent_id: str, tool_execution_id: str, details: dict):
    """Log a structured provenance event."""
    logger.info(details, extra={
        "event_type": event_type,
        "agent_id": agent_id,
        "tool_execution_id": tool_execution_id
    })
