from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime
from typing import Optional

class LogEntry(BaseModel):

    model_config = ConfigDict(
        frozen=True,  # Inmutable
        strict=True   # Strict types
    )

    """Represents a parsed input from the system"""
    timestamp: datetime = Field(..., description="Date and hour of event")
    user: Optional[str] = Field(None,description="User involved")
    ip: Optional[str] = Field(None, description="IP origin, if applies")
    event_type: str = Field(..., min_length=1, description="Type of event")
    success: bool = Field(False, description="If event was succ or fail")
    details: Optional[str] = Field(None, description="Details")