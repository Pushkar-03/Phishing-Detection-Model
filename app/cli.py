"""Command-line prediction interface."""
import argparse, json
from app.inference import PhishingPredictor

def main():
    parser = argparse.ArgumentParser(description="Classify a URL without fetching it.")
    parser.add_argument("url", help="URL to classify")
    parser.add_argument("--artifact", default=None, help="Optional model artifact path")
    args = parser.parse_args()
    predictor = PhishingPredictor(args.artifact) if args.artifact else PhishingPredictor()
    print(json.dumps(predictor.predict(args.url), indent=2))

if __name__ == "__main__":
    main()
