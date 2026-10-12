"""Label mapping, URL/domain deduplication, and leakage-resistant group split."""
from __future__ import annotations
from urllib.parse import urlsplit
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

def hostname(url: str) -> str:
    value = str(url).strip()
    if "://" not in value:
        value = "http://" + value
    return (urlsplit(value).hostname or "").lower().rstrip(".")

def prepare_url_labels(path="data/processed/url_labels.csv"):
    df = pd.read_csv(path)
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"].ne("")].copy()
    # UCI PhiUSIIL: label 0 phishing, 1 legitimate. Convert to 1=phishing.
    df["y"] = df["source_label"].astype(int).map({0: 1, 1: 0})
    if df["y"].isna().any():
        raise ValueError("Unexpected source labels; expected PhiUSIIL labels 0 and 1.")
    df["hostname"] = df["url"].map(hostname)
    # Exact duplicate URLs are collapsed; if labels conflict, remove the URL rather than guess.
    conflict_urls = df.groupby("url")["y"].nunique()
    bad_urls = set(conflict_urls[conflict_urls > 1].index)
    df = df[~df["url"].isin(bad_urls)].drop_duplicates("url", keep="first")
    # Domains that have mixed labels are removed entirely to prevent ambiguous labels and group leakage.
    domain_counts = df.groupby("hostname")["y"].nunique()
    bad_domains = set(domain_counts[domain_counts > 1].index)
    df = df[~df["hostname"].isin(bad_domains)].copy()
    df = df[df["hostname"].ne("")].reset_index(drop=True)
    return df[["url", "hostname", "y"]], {
        "conflicting_urls_removed": len(bad_urls),
        "conflicting_domains_removed": len(bad_domains),
        "rows_after_dedup_and_conflict_filter": len(df),
    }

def grouped_train_val_test(df, random_state=42):
    """Approximate 70/15/15 split by hostname. No group can cross partitions."""
    groups = df["hostname"].values
    splitter1 = GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=random_state)
    train_idx, temp_idx = next(splitter1.split(df, df["y"], groups))
    train = df.iloc[train_idx].copy()
    temp = df.iloc[temp_idx].copy()
    splitter2 = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=random_state)
    val_rel, test_rel = next(splitter2.split(temp, temp["y"], temp["hostname"].values))
    val, test = temp.iloc[val_rel].copy(), temp.iloc[test_rel].copy()
    if min(train["y"].nunique(), val["y"].nunique(), test["y"].nunique()) < 2:
        raise ValueError("A split contains only one class. Dataset/group distribution needs review.")
    return train, val, test
