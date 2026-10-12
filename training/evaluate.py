"""Evaluate the frozen artifact on the held-out grouped test split."""
from __future__ import annotations
import argparse, json, time
from pathlib import Path
import joblib, numpy as np, pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, average_precision_score, roc_auc_score,
    RocCurveDisplay, PrecisionRecallDisplay)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--artifact", default="artifacts/phishing_url_v1.joblib")
    p.add_argument("--test", default="data/processed/test_split.csv")
    args = p.parse_args()
    artifact = joblib.load(args.artifact)
    test = pd.read_csv(args.test)
    from training.train import features
    X = features(test.url)
    y = test.y.astype(int).to_numpy()
    model = artifact["model"]
    started = time.perf_counter()
    prob = model.predict_proba(X)[:, 1]
    latency_ms = (time.perf_counter() - started) * 1000 / max(1, len(test))
    threshold = float(artifact["threshold"])
    pred = (prob >= threshold).astype(int)
    cm = confusion_matrix(y, pred, labels=[0, 1])
    tn, fp, fn, tp = [int(x) for x in cm.ravel()]
    metrics = {
        "model_version": artifact["model_version"],
        "selected_model": artifact["selected_model"],
        "threshold": threshold,
        "n_test": len(test),
        "accuracy": float(accuracy_score(y, pred)),
        "precision_phishing": float(precision_score(y, pred, zero_division=0)),
        "recall_phishing": float(recall_score(y, pred, zero_division=0)),
        "f1_phishing": float(f1_score(y, pred, zero_division=0)),
        "macro_f1": float(f1_score(y, pred, average="macro", zero_division=0)),
        "pr_auc": float(average_precision_score(y, prob)),
        "roc_auc": float(roc_auc_score(y, prob)) if len(np.unique(y)) == 2 else None,
        "false_positive_rate": float(fp / max(1, fp + tn)),
        "confusion_matrix_labels_0_legitimate_1_phishing": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "mean_inference_ms_per_url_in_batch": latency_ms,
        "classification_report": classification_report(y, pred, target_names=["legitimate", "phishing"], output_dict=True, zero_division=0),
        "test_hostname_overlap_with_train_validation": None,
        "note": "Grouped hostname split; publication data lacks reliable row timestamps, so temporal generalization is not measured.",
    }
    out = Path("reports"); out.mkdir(exist_ok=True)
    (out / "evaluation.json").write_text(json.dumps(metrics, indent=2))
    pd.DataFrame({"url": test.url, "hostname": test.hostname, "y_true": y,
                  "y_pred": pred, "phishing_probability": prob,
                  "error_type": np.where((y == 0) & (pred == 1), "false_positive",
                               np.where((y == 1) & (pred == 0), "false_negative", "correct"))}
                 ).to_csv(out / "prediction_errors.csv", index=False)
    fig, ax = plt.subplots()
    RocCurveDisplay.from_predictions(y, prob, ax=ax)
    fig.tight_layout(); fig.savefig(out / "roc_curve.png", dpi=140); plt.close(fig)
    fig, ax = plt.subplots()
    PrecisionRecallDisplay.from_predictions(y, prob, ax=ax)
    fig.tight_layout(); fig.savefig(out / "precision_recall_curve.png", dpi=140); plt.close(fig)
    fig, ax = plt.subplots()
    ax.imshow(cm)
    ax.set_xticks([0,1], ["legitimate", "phishing"]); ax.set_yticks([0,1], ["legitimate", "phishing"])
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title("Confusion matrix")
    for (i,j), v in np.ndenumerate(cm): ax.text(j, i, str(v), ha="center", va="center")
    fig.tight_layout(); fig.savefig(out / "confusion_matrix.png", dpi=140); plt.close(fig)
    print(json.dumps(metrics, indent=2))
if __name__ == "__main__":
    main()
