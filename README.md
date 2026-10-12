# Standalone Phishing URL Detection

A URL-only phishing classifier experiment for the SAKSHAM Smart Civic Governance & Security System. This repository is intentionally standalone: it does not modify or integrate with any existing web application.

## Important scope and safety

- Prediction uses only lexical properties of the submitted URL string.
- It does **not** open, resolve, crawl, or fetch submitted URLs.
- URL-only models cannot see page content, redirects, live reputation, DNS/WHOIS, certificate state, or current blocklists.
- A model prediction is a risk signal, not proof that a site is safe or malicious.
- Never deserialize model artifacts from untrusted sources.

## 1. Environment

Python 3.10–3.12 recommended.

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 2. Acquire data

The primary source is the official UCI PhiUSIIL dataset (ID 967), CC BY 4.0. Cite Prasad & Chandra (2024), DOI `10.1016/j.cose.2023.103545`.

```bash
python -c "from ucimlrepo import fetch_ucirepo; import pandas as pd; from pathlib import Path; p=Path('data/raw'); p.mkdir(parents=True, exist_ok=True); d=fetch_ucirepo(id=967); pd.concat([d.data.features, d.data.targets], axis=1).to_csv(p/'PhiUSIIL_Phishing_URL_Dataset.csv', index=False)"
```

Dataset label convention from UCI: `1 = legitimate`, `0 = phishing`. Raw files are excluded from version control.

## 3. Mandatory audit before training

```bash
python -m training.dataset_audit --csv data/raw/PhiUSIIL_Phishing_URL_Dataset.csv
```

Review `reports/dataset_audit.md` and `.json` before proceeding. The audit reports schema, missing values, label counts, duplicate URLs, hostname counts and hostnames with conflicting labels. It writes only the URL and source label to `data/processed/url_labels.csv`; all other dataset columns are excluded from URL-only inference.

The source dataset includes features extracted from webpage content and derived from external or corpus-wide statistics. These are not available to the URL-only runtime and are excluded. Dataset timestamps are not adequate for a trustworthy temporal test split; do not label a random/grouped split as a time-separated test.

## 4. Train and compare

```bash
python -m training.train
```

Three models are compared: Logistic Regression, Random Forest, and scikit-learn HistGradientBoosting (gradient-boosted trees). Splits are grouped by hostname to reduce same-host leakage. Exact duplicate URLs and hostnames with conflicting labels are removed instead of arbitrarily relabelled. The split is deterministic with seed 42.

Model selection uses validation PR-AUC and secondary validation metrics. The threshold is selected on validation data to target a configurable phishing recall (`--min-recall`, default 0.90). The test set is not used for selection. The selected estimator is refit on train+validation and serialized to `artifacts/phishing_url_v1.joblib`.

## 5. Evaluate once on held-out test

```bash
python -m training.evaluate
```

Outputs in `reports/` include accuracy, phishing precision/recall/F1, macro-F1, PR-AUC, ROC-AUC, false-positive rate, confusion matrix, ROC/PR curves and row-level error analysis. Inference timing is a local batch measurement, not a production latency guarantee.

## 6. Local CLI prediction

```bash
python -m app.cli "http://example.com/login"
```

The response includes predicted class, estimated phishing probability, a risk assessment, warning indicators actually derived from URL features, model version and threshold.

## 7. Optional local API

Only after training:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

- `GET http://127.0.0.1:8000/health`
- `GET http://127.0.0.1:8000/model-info`
- `POST http://127.0.0.1:8000/predict`

Example body: `{"url":"https://example.com/login"}`

The service binds to localhost by default and never fetches the submitted URL.

## 8. Tests

```bash
pytest -q
```

Model-dependent tests skip until an artifact exists. API validation tests do not require a trained model.

## Dataset and methodology limitations

- PhiUSIIL contains 235,795 rows, 54 features plus label (UCI page metadata); source label `1` is legitimate and `0` is phishing. Verify this against the downloaded schema.
- Grouping by hostname is a conservative approximation, not a public-suffix-aware registrable-domain grouping. Subdomains may still be split across groups if their hostname differs.
- The source does not provide reliable timestamps for each sample; a temporal holdout is not claimed.
- A grouped holdout from one dataset is not independent evidence of real-world reliability. Benchmark against fresh, verified feeds and benign URLs from the same period before deployment.
- PhishTank data should be used only with the provider's current terms and feed verification. Do not treat a feed URL as verified unless its status and timestamp are checked.
- UCI Phishing Websites (ID 327) is a secondary benchmark of engineered website-level features and does not provide raw URLs in a form compatible with this URL-only feature extractor; it should not be merged into the primary training set.
