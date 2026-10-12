"""Train URL-only classifiers. Run dataset audit first."""
from __future__ import annotations
import argparse, json, time
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import average_precision_score, precision_score, recall_score, f1_score
from app.feature_extractor import FEATURE_NAMES, extract_url_features
from training.preprocessing import prepare_url_labels, grouped_train_val_test

SEED = 42
VERSION = "phishing-url-v1"

def features(urls):
    return pd.DataFrame([extract_url_features(u) for u in urls], columns=FEATURE_NAMES)

def choose_threshold(y_true, probabilities, min_recall=0.90):
    best = None
    for threshold in np.linspace(0.05, 0.95, 91):
        pred = (probabilities >= threshold).astype(int)
        rec = recall_score(y_true, pred, zero_division=0)
        prec = precision_score(y_true, pred, zero_division=0)
        f1 = f1_score(y_true, pred, zero_division=0)
        candidate = (rec >= min_recall, f1, prec, rec, threshold)
        if best is None or candidate[:4] > best[:4]:
            best = candidate
    if best and best[0]:
        return float(best[4])
    # If target recall is not reached, maximize F1 on validation only.
    scores = [(f1_score(y_true, (probabilities >= t).astype(int), zero_division=0), t)
              for t in np.linspace(0.05, 0.95, 91)]
    return float(max(scores)[1])

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", default="data/processed/url_labels.csv")
    p.add_argument("--artifact", default="artifacts/phishing_url_v1.joblib")
    p.add_argument("--min-recall", type=float, default=0.90)
    args = p.parse_args()
    df, cleaning = prepare_url_labels(args.input)
    train, val, test = grouped_train_val_test(df, SEED)
    X_train, X_val = features(train.url), features(val.url)
    y_train, y_val = train.y.astype(int), val.y.astype(int)
    models = {
        "logistic_regression": Pipeline([("scale", StandardScaler()), ("model", LogisticRegression(
            max_iter=2000, class_weight="balanced", random_state=SEED, C=1.0))]),
        "random_forest": RandomForestClassifier(
            n_estimators=300, min_samples_leaf=2, class_weight="balanced_subsample",
            n_jobs=-1, random_state=SEED, max_features="sqrt"),
        "hist_gradient_boosting": HistGradientBoostingClassifier(
            max_iter=250, learning_rate=0.08, max_leaf_nodes=31, l2_regularization=1.0,
            random_state=SEED),
    }
    results = []
    fitted = {}
    for name, model in models.items():
        started = time.perf_counter()
        model.fit(X_train, y_train)
        probs = model.predict_proba(X_val)[:, 1]
        elapsed = time.perf_counter() - started
        results.append({
            "model": name,
            "validation_precision_at_0_5": float(precision_score(y_val, probs >= .5, zero_division=0)),
            "validation_recall_at_0_5": float(recall_score(y_val, probs >= .5, zero_division=0)),
            "validation_f1_at_0_5": float(f1_score(y_val, probs >= .5, zero_division=0)),
            "validation_pr_auc": float(average_precision_score(y_val, probs)),
            "fit_seconds": elapsed,
        })
        fitted[name] = model
    # Select by validation PR-AUC, then recall and F1. Final test is untouched here.
    chosen_result = max(results, key=lambda r: (r["validation_pr_auc"], r["validation_recall_at_0_5"], r["validation_f1_at_0_5"]))
    chosen_name = chosen_result["model"]
    chosen = fitted[chosen_name]
    val_probs = chosen.predict_proba(X_val)[:, 1]
    threshold = choose_threshold(y_val, val_probs, args.min_recall)
    # Refit chosen model on train+validation only after model/threshold selection.
    train_val = pd.concat([train, val], ignore_index=True)
    final_model = models[chosen_name]
    final_model.fit(features(train_val.url), train_val.y.astype(int))
    artifact = {
        "model": final_model,
        "feature_names": FEATURE_NAMES,
        "threshold": threshold,
        "model_version": VERSION,
        "selected_model": chosen_name,
        "positive_class": "phishing",
        "label_mapping": {"source_0": "phishing", "source_1": "legitimate"},
        "random_state": SEED,
        "cleaning_summary": cleaning,
        "split_rows": {"train": len(train), "validation": len(val), "test": len(test)},
        "trained_at_utc": pd.Timestamp.utcnow().isoformat(),
    }
    out = Path(args.artifact); out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, out)
    Path("reports").mkdir(exist_ok=True)
    Path("reports/model_comparison.json").write_text(json.dumps({
        "selection_rule": "Highest validation PR-AUC, then recall and F1 at 0.5; threshold selected on validation to target recall.",
        "selected_model": chosen_name, "threshold": threshold,
        "validation_results": results, "cleaning": cleaning,
        "split_rows": artifact["split_rows"],
    }, indent=2))
    # Save test split for evaluate.py; labels are not used during selection.
    test[["url", "y", "hostname"]].to_csv("data/processed/test_split.csv", index=False)
    print(json.dumps({"artifact": str(out), "selected_model": chosen_name, "threshold": threshold,
                      "validation_results": results, "split_rows": artifact["split_rows"],
                      "cleaning": cleaning}, indent=2))
if __name__ == "__main__":
    main()
