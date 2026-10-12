# Model artifacts

Training writes `phishing_url_v1.joblib` here. It contains the fitted estimator, feature schema, threshold, model version, and training metadata. Artifacts are not included in source control. Only load trusted artifacts: joblib/pickle files can execute code during deserialization.
