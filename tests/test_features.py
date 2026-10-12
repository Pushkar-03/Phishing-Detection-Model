import pytest
from app.feature_extractor import FEATURE_NAMES, extract_url_features

def test_feature_schema_is_fixed_and_numeric():
    f = extract_url_features("https://example.com/login?id=4")
    assert list(f) == FEATURE_NAMES
    assert all(isinstance(v, float) for v in f.values())

def test_detects_ip_and_at_sign():
    f = extract_url_features("http://192.0.2.1@evil.example/path")
    assert f["has_at_in_authority"] == 1.0
    assert f["count_at"] == 1.0

def test_rejects_empty_input():
    with pytest.raises(ValueError):
        extract_url_features("  ")
