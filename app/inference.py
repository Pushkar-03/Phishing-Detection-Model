"""Local model loading and safe prediction; no network access is performed."""
from __future__ import annotations
import os
from pathlib import Path
import joblib
import pandas as pd
from app.feature_extractor import extract_url_features, FEATURE_NAMES

DEFAULT_ARTIFACT = os.getenv("MODEL_PATH", "artifacts/phishing_url_v1.joblib")

class PhishingPredictor:
    def __init__(self, artifact_path=DEFAULT_ARTIFACT):
        path = Path(artifact_path)
        if not path.exists():
            raise FileNotFoundError(f"Model artifact not found: {path}. Run training first.")
        self.artifact = joblib.load(path)
        if self.artifact.get("feature_names") != FEATURE_NAMES:
            raise ValueError("Artifact feature schema does not match current extractor.")
        self.model = self.artifact["model"]

    def predict(self, url: str) -> dict:
        features = extract_url_features(url)
        X = pd.DataFrame([[features[k] for k in FEATURE_NAMES]], columns=FEATURE_NAMES)
        probability = float(self.model.predict_proba(X)[0, 1])
        threshold = float(self.artifact["threshold"])
        phishing = probability >= threshold
        indicators = []
        if features["has_ip_host"]: indicators.append("hostname_is_ip_address")
        if features["has_at_in_authority"] or features["count_at"]: indicators.append("at_symbol_present")
        if features["is_shortener"]: indicators.append("known_url_shortener")
        if features["has_punycode"]: indicators.append("punycode_hostname")
        if features["has_suspicious_term"]: indicators.append("suspicious_term_in_url")
        if features["count_encoded_marker"]: indicators.append("percent_encoded_characters")
        if features["https_scheme"] == 0: indicators.append("not_https_scheme")
        if features["uses_credentials"]: indicators.append("embedded_url_credentials")
        return {
            "url": url,
            "predicted_class": "phishing" if phishing else "legitimate",
            "phishing_probability": probability,
            "risk_assessment": "high" if probability >= max(threshold, 0.80) else ("medium" if phishing or probability >= 0.40 else "low"),
            "warning_indicators": indicators,
            "model_version": self.artifact["model_version"],
            "threshold": threshold,
        }
