"""Audit UCI PhiUSIIL CSV before any model fitting."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from urllib.parse import urlsplit
import pandas as pd

LABEL_CANDIDATES = ("label", "Label", "result", "Result", "target", "Target")
URL_CANDIDATES = ("URL", "url", "URLString", "url_string")

def find_column(columns, candidates):
    for candidate in candidates:
        if candidate in columns:
            return candidate
    return None

def domain_from_url(value):
    try:
        u = str(value).strip()
        if "://" not in u:
            u = "http://" + u
        return (urlsplit(u).hostname or "").lower().rstrip(".")
    except Exception:
        return ""

def audit_dataset(csv_path: str, out_dir: str = "reports") -> dict:
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}. Download UCI dataset first; see README.")
    df = pd.read_csv(path, low_memory=False)
    url_col = find_column(df.columns, URL_CANDIDATES)
    label_col = find_column(df.columns, LABEL_CANDIDATES)
    if not url_col or not label_col:
        raise ValueError(f"Could not identify URL/label columns. Columns: {list(df.columns)}")
    urls = df[url_col].astype("string").str.strip()
    labels = pd.to_numeric(df[label_col], errors="coerce")
    valid = urls.notna() & urls.ne("") & labels.notna()
    clean = df.loc[valid].copy()
    clean_urls = urls.loc[valid]
    clean_labels = labels.loc[valid].astype(int)
    domains = clean_urls.map(domain_from_url)
    label_map = {str(k): int(v) for k, v in clean_labels.value_counts().sort_index().items()}
    duplicate_url_rows = int(clean_urls.duplicated(keep=False).sum())
    duplicate_url_unique = int(clean_urls[clean_urls.duplicated(keep=False)].nunique())
    domain_label_counts = pd.DataFrame({"domain": domains, "label": clean_labels}).groupby("domain")["label"].nunique()
    conflicting_domains = int((domain_label_counts > 1).sum())
    # PhiUSIIL documented labels: 1=legitimate, 0=phishing. This report keeps raw label counts.
    # Only URL-derived columns are retained for URL-only model training.
    report = {
        "source_file": str(path),
        "rows_raw": int(len(df)),
        "columns_raw": int(len(df.columns)),
        "columns": [str(c) for c in df.columns],
        "url_column": url_col,
        "label_column": label_col,
        "missing_by_column": {str(k): int(v) for k, v in df.isna().sum().items()},
        "rows_missing_or_invalid_url_or_label": int((~valid).sum()),
        "rows_valid_url_and_label": int(valid.sum()),
        "label_counts_raw": {str(k): int(v) for k, v in labels.value_counts(dropna=False).sort_index().items()},
        "label_counts_valid": label_map,
        "duplicate_url_rows_including_repeats": duplicate_url_rows,
        "unique_urls_appearing_in_duplicate_groups": duplicate_url_unique,
        "unique_domains": int(domains.nunique()),
        "domains_with_conflicting_labels": conflicting_domains,
        "columns_excluded_from_url_only_pipeline": [
            str(c) for c in df.columns if c not in (url_col, label_col)
        ],
        "label_semantics": "UCI PhiUSIIL: 1=legitimate, 0=phishing; verify against current official metadata.",
        "limitations": [
            "PhiUSIIL contains webpage/content-derived features; they are excluded from URL-only inference.",
            "Dataset publication does not provide a reliable per-row collection timestamp for a time split.",
            "Grouped split by registrable-domain approximation is required; the code groups by extracted hostname, not full public-suffix parsing.",
        ],
    }
    out = Path(out_dir); out.mkdir(parents=True, exist_ok=True)
    (out / "dataset_audit.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    lines = [
        "# Dataset Audit", "",
        f"- Source: `{path}`",
        f"- Raw shape: {len(df):,} rows × {len(df.columns)} columns",
        f"- URL column: `{url_col}`; label column: `{label_col}`",
        f"- Valid URL/label rows: {int(valid.sum()):,}",
        f"- Duplicate URL rows including repeats: {duplicate_url_rows:,}",
        f"- Unique domains: {domains.nunique():,}",
        f"- Domains with conflicting labels: {conflicting_domains:,}",
        f"- Missing values: {'present' if df.isna().any().any() else 'none detected'}",
        "", "## Label counts", "",
    ]
    lines += [f"- `{k}`: {v:,}" for k, v in report["label_counts_valid"].items()]
    lines += ["", "## URL-only policy", "",
              "Only the raw URL string and label are used downstream. All other columns are excluded because they may require page contents, external services, or source-specific derived statistics.",
              "", "## Limitations", ""] + [f"- {x}" for x in report["limitations"]]
    (out / "dataset_audit.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    # Write a minimal raw URL/label dataset; preserve source labels for explicit mapping in preprocessing.
    minimal = pd.DataFrame({"url": clean_urls.astype(str).values, "source_label": clean_labels.values})
    Path("data/processed").mkdir(parents=True, exist_ok=True)
    minimal.to_csv("data/processed/url_labels.csv", index=False)
    return report

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--csv", default="data/raw/PhiUSIIL_Phishing_URL_Dataset.csv")
    p.add_argument("--out", default="reports")
    args = p.parse_args()
    report = audit_dataset(args.csv, args.out)
    print(json.dumps(report, indent=2))
if __name__ == "__main__":
    main()
