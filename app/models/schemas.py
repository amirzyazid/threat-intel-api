from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

class ObservableType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"

class ThreatActor(BaseModel):
    name: str
    country: Optional[str] = None
    description: Optional[str] = None

class MitreTTP(BaseModel):
    id: str
    name: str
    url: Optional[str] = None

class SourceReport(BaseModel):
    source_name: str
    malicious_votes: int = 0
    total_votes: int = 0
    tags: List[str] = []
    
class RiskReport(BaseModel):
    observable: str
    observable_type: ObservableType
    overall_risk_score: int = Field(ge=0, le=100, description="Risk score from 0 (Safe) to 100 (Critical)")
    severity: str = Field(description="Low, Medium, High, or Critical")
    sources: List[SourceReport] = []
    mitre_ttps: List[MitreTTP] = []
    associated_actors: List[ThreatActor] = []
    summary: str
