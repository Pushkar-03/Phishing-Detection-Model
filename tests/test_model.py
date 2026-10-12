import os
import pytest
from app.inference import PhishingPredictor

@pytest.mark.skipif(not os.path.exists("artifacts/phishing_url_v1.joblib"), reason="Train model first")
def test_model_loads_and_predicts_without_network():
    predictor = PhishingPredictor()
    result = predictor.predict("https://example.com/")
    assert result["predicted_class"] in {"phishing", "legitimate"}
    assert 0 <= result["phishing_probability"] <= 1
    assert result["model_version"]
