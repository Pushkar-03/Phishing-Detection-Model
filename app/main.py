"""Optional local FastAPI inference API. Does not fetch submitted URLs."""
from fastapi import FastAPI, HTTPException
from app.schemas import PredictRequest, PredictResponse
from app.inference import PhishingPredictor

app = FastAPI(title="Standalone Phishing URL Detector", version="1.0.0")
_predictor = None

def get_predictor():
    global _predictor
    if _predictor is None:
        try:
            _predictor = PhishingPredictor()
        except Exception as exc:
            raise HTTPException(status_code=503, detail=f"Model unavailable: {exc}") from exc
    return _predictor

@app.get("/health")
def health():
    try:
        predictor = get_predictor()
        return {"status": "ok", "model_version": predictor.artifact["model_version"]}
    except HTTPException:
        return {"status": "model_unavailable"}

@app.get("/model-info")
def model_info():
    predictor = get_predictor()
    return {"model_version": predictor.artifact["model_version"],
            "selected_model": predictor.artifact["selected_model"],
            "threshold": predictor.artifact["threshold"],
            "features": len(predictor.artifact["feature_names"]),
            "positive_class": "phishing"}

@app.post("/predict", response_model=PredictResponse)
def predict(request: PredictRequest):
    predictor = get_predictor()
    try:
        return predictor.predict(request.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
