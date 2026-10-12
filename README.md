# 🛡️ Phishing URL Detection using Machine Learning

<p align="center">
  <strong>SAKSHAM — Smart Civic Governance & Security System</strong><br>
  A standalone machine-learning project by <strong>Pushkar Hemant Bihani</strong>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white">
  <img alt="scikit-learn" src="https://img.shields.io/badge/ML-scikit--learn-F7931E?logo=scikitlearn&logoColor=white">
  <img alt="Project status" src="https://img.shields.io/badge/Status-Research%20%26%20Evaluation-blue">
  <img alt="Scope" src="https://img.shields.io/badge/Scope-Standalone-success">
</p>

## 👋 About this project

Hi, I'm **Pushkar Hemant Bihani**, a Computer Science Engineering student interested in Artificial Intelligence, Machine Learning, and building technology that can help solve practical security problems.

This repository contains the **Phishing URL Detection** component I'm developing as part of **SAKSHAM — Smart Civic Governance & Security System**. The goal is to investigate whether a machine-learning model can identify suspicious and potentially phishing URLs using characteristics of the URL itself.

This is deliberately a **standalone model-development project**. The current focus is on auditing the data, training and comparing models, evaluating their limitations, and testing predictions locally. **It is not integrated into the SAKSHAM web application.** Integration will be considered only after the model has been tested more thoroughly.

> **Project principle:** measure first, validate carefully, and integrate only when the evidence supports it.

## 🎯 Objectives

- Audit the dataset before training and document its quality and label distribution.
- Use URL-only lexical features that can be extracted without visiting the destination website.
- Compare multiple machine-learning algorithms using a held-out evaluation set.
- Report phishing precision, recall, F1-score, PR-AUC, ROC-AUC, and false-positive behaviour.
- Provide a local command-line interface and an optional local API for experimentation.
- Inspect false positives and false negatives instead of relying on accuracy alone.
- Keep the project independent of the existing web application during this evaluation stage.

## 🧰 Current approach

The pipeline is designed to move through these stages:

1. **Dataset inspection and audit** — inspect schema, labels, missing values, duplicates, and hostname-level conflicts.
2. **URL preprocessing** — retain the URL and source label while excluding webpage-content and other non-URL features.
3. **Feature extraction** — calculate lexical characteristics from the URL string.
4. **Model comparison** — compare Logistic Regression, Random Forest, and HistGradientBoosting.
5. **Validation and threshold selection** — use validation data for model selection and threshold tuning.
6. **Held-out evaluation** — report metrics and produce prediction-error analysis.
7. **Local inference** — run predictions through the CLI or optional local API.

### Technology

- **Language:** Python
- **Machine learning:** scikit-learn
- **Data processing:** pandas, NumPy
- **Model persistence:** joblib
- **API (optional):** FastAPI and Uvicorn
- **Testing:** pytest
- **Dataset source:** UCI Machine Learning Repository — PhiUSIIL Phishing URL Dataset

## 📊 Current experimental results

The following are the results reported by my current local run on the project's held-out test split. They are **experimental benchmark results**, not a claim of production readiness or guaranteed real-world detection performance.

| Metric | Current result |
|---|---:|
| Test samples | 34,940 |
| Accuracy | 99.59% |
| Phishing precision | 99.90% |
| Phishing recall | 99.12% |
| Phishing F1-score | 99.51% |
| Macro F1-score | 99.58% |
| PR-AUC | 0.9985 |
| ROC-AUC | 0.9982 |
| False-positive rate | 0.0693% |
| Selected model | HistGradientBoosting |

**Reported confusion matrix** — legitimate is class `0`; phishing is class `1`:

| | Predicted legitimate | Predicted phishing |
|---|---:|---:|
| **Actually legitimate** | 20,188 | 14 |
| **Actually phishing** | 130 | 14,608 |

These results are useful as a baseline, but they do not establish how well the model will perform on new URLs collected from the live internet. Dataset-specific patterns, repeated domains, label quality, and distribution shifts can all make benchmark results look better than real-world performance.

**Important validation note:** a high model score should not automatically be interpreted as a reliable probability of real-world danger. During testing, even a reserved example URL with a `/login` path received a high phishing score. This is a reason to inspect feature behaviour and false predictions, validate against known benign URLs, and improve generalization before considering deployment. The project should not add one-off exceptions just to make individual examples pass.

## ⚠️ Scope, safety, and limitations

- The model analyses **the URL string only**.
- It does **not** open, resolve, crawl, or fetch submitted URLs.
- It does not inspect webpage content, redirects, DNS/WHOIS records, certificate details, live reputation, or current blocklists.
- A prediction is a risk signal, not proof that a URL is safe or malicious.
- URL-only features may miss sophisticated phishing links and may flag legitimate URLs with unusual patterns.
- The current evaluation uses a grouped split from one dataset; it is not a time-separated or independently collected real-world test.
- Grouping by hostname is not the same as grouping by registrable domain, so subdomain leakage may remain possible.
- Probability outputs may be uncalibrated and should not be presented as verified real-world risk probabilities.
- Do not load model artifacts from untrusted sources.

## 🚀 Getting started

### 1. Clone the repository

```bash
git clone <YOUR-REPOSITORY-URL>
cd phishing-detection
```

Replace `<YOUR-REPOSITORY-URL>` with the URL of your repository.

### 2. Create and activate a virtual environment

**Windows PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

**macOS / Linux**

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Python 3.10–3.12 is recommended.

## 📥 Dataset setup

The primary dataset is the [UCI PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset), dataset ID 967. The UCI label convention is `1 = legitimate` and `0 = phishing`; the preprocessing pipeline maps this to `0 = legitimate` and `1 = phishing` for model evaluation.

Download and save the CSV locally under `data/raw/`. One way to retrieve it is:

```bash
python -c "from ucimlrepo import fetch_ucirepo; import pandas as pd; from pathlib import Path; p=Path('data/raw'); p.mkdir(parents=True, exist_ok=True); d=fetch_ucirepo(id=967); pd.concat([d.data.features, d.data.targets], axis=1).to_csv(p/'PhiUSIIL_Phishing_URL_Dataset.csv', index=False)"
```

Before training, run the dataset audit:

```bash
python -m training.dataset_audit --csv data/raw/PhiUSIIL_Phishing_URL_Dataset.csv
```

Review the generated audit report in `reports/`. Raw datasets are excluded from version control.

## 🧪 Train, evaluate, and predict

### Train and compare models

```bash
python -m training.train
```

The training workflow compares Logistic Regression, Random Forest, and HistGradientBoosting. Model selection and threshold tuning use validation data; the held-out test split is reserved for final evaluation.

### Evaluate the selected model

```bash
python -m training.evaluate
```

The evaluation workflow writes metrics, curves, a confusion matrix, and row-level prediction-error analysis under `reports/`.

### Run a local prediction

```bash
python -m app.cli "https://example.com/"
```

Try a range of known benign URLs and carefully verified phishing URLs. A single prediction should not be used to determine that a site is safe.

### Run the optional local API

After training has created the model artifact:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Available local endpoints:

- `GET /health`
- `GET /model-info`
- `POST /predict`

Example request body:

```json
{
  "url": "https://example.com/login"
}
```

The API is intended for local experimentation and binds to localhost by default. It does not fetch the submitted URL. This API is **not a web-app integration**.

## ✅ Run tests

```bash
pytest -q
```

Tests help check expected feature extraction, model inference, and API behaviour. Passing tests demonstrate that tested code paths work as expected; they do not prove that the model is accurate on real-world phishing campaigns.

## 🔬 Next validation priorities

Before treating this as a dependable security component, I plan to focus on:

- Reviewing `reports/prediction_errors.csv` and categorising false positives and false negatives.
- Testing a curated set of legitimate URLs, including URLs with login-like paths, query parameters, and non-HTTPS schemes where appropriate.
- Evaluating against fresh, independently collected legitimate and verified phishing URLs.
- Checking hostname and domain overlap across splits.
- Investigating dataset bias and feature importance/behaviour.
- Measuring end-to-end latency, including feature extraction, rather than estimator-only timing.
- Checking probability calibration and selecting an operating threshold based on the intended use case.

## 📚 Dataset citation

Prasad, A., & Chandra, S. (2024). *PhiUSIIL: A diverse security profile empowered phishing URL detection framework based on similarity index and incremental learning.* Computers & Security. DOI: [10.1016/j.cose.2023.103545](https://doi.org/10.1016/j.cose.2023.103545).

Please check the dataset's current licence and usage terms before redistributing it or publishing derived artifacts.

## 👨‍💻 Author

**Pushkar Hemant Bihani**  
B.Tech — Computer Science Engineering  
Project: **SAKSHAM — Smart Civic Governance & Security System**

- GitHub: [@Pushkar-03](https://github.com/Pushkar-03)

I'm building this project to strengthen my practical experience in machine learning, security-focused model evaluation, and responsible AI development. Suggestions, constructive feedback, and reproducible issue reports are welcome.

## 📄 Disclaimer

This project is developed for educational, research, and defensive cybersecurity purposes. It is an experimental URL-classification model, not a complete phishing protection system. Do not rely on it as the sole basis for security decisions, and do not use its output as a guarantee that a website is safe or malicious.
