# Dataset Audit

- Source: `data\raw\PhiUSIIL_Phishing_URL_Dataset.csv`
- Raw shape: 235,795 rows × 55 columns
- URL column: `URL`; label column: `label`
- Valid URL/label rows: 235,795
- Duplicate URL rows including repeats: 850
- Unique domains: 220,077
- Domains with conflicting labels: 54
- Missing values: none detected

## Label counts

- `0`: 100,945
- `1`: 134,850

## URL-only policy

Only the raw URL string and label are used downstream. All other columns are excluded because they may require page contents, external services, or source-specific derived statistics.

## Limitations

- PhiUSIIL contains webpage/content-derived features; they are excluded from URL-only inference.
- Dataset publication does not provide a reliable per-row collection timestamp for a time split.
- Grouped split by registrable-domain approximation is required; the code groups by extracted hostname, not full public-suffix parsing.
