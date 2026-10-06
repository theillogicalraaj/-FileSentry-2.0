from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field

class RegisterRequest(BaseModel):
    email: str
    password: str = Field(min_length=10, max_length=128)

class LoginRequest(RegisterRequest):
    pass

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class AnalysisSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    original_name: str
    size_bytes: int
    status: str
    detected_type: str
    detected_mime: str
    confidence: int
    claimed_extension: str | None
    risk_score: int
    risk_level: str
    sha256: str
    entropy: float
    created_at: datetime

class AnalysisDetail(AnalysisSummary):
    claimed_mime: str | None
    md5: str
    sha512: str
    findings: list[dict]
    indicators: dict
