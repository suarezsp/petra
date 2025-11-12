from pydantic import BaseModel, Field
from typing import List
from enum import Enum
from .log_entry import LogEntry

class AnomalyLevel(str, Enum):
    """Enum for anomaly level"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Anomaly(BaseModel):
    """Represents an anomaly detected by log"""
    level: AnomalyLevel = Field(..., description="Severity level")
    score: float = Field(..., ge=0.0, le=1.0, description="Trust score 0-1")
    type: str = Field(..., min_length=1, description="Type, e.g., 'brute_force', 'unusual_time'")
    evidence: List[LogEntry] = Field(..., description="Logs entries")
    description: str = Field(..., min_length=1, description="Explained in human language")