from pydantic import BaseModel, Field, field_validator
from urllib.parse import urlsplit
import re

class PredictRequest(BaseModel):
    url: str = Field(min_length=3, max_length=4096)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ord(ch) < 32 for ch in value):
            raise ValueError("URL is empty or contains control characters")
        candidate = value if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value) else "http://" + value
        try:
            parsed = urlsplit(candidate)
            if not parsed.hostname or "." not in parsed.hostname and parsed.hostname not in ("localhost",):
                raise ValueError("Provide a URL with a hostname")
            if parsed.scheme.lower() not in ("http", "https"):
                raise ValueError("Only http and https URLs are supported")
        except Exception as exc:
            raise ValueError("Malformed URL") from exc
        return value

class PredictResponse(BaseModel):
    url: str
    predicted_class: str
    phishing_probability: float
    risk_assessment: str
    warning_indicators: list[str]
    model_version: str
    threshold: float
