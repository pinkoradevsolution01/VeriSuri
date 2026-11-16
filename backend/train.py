"""Train V1 using permissioned UTF-8 CSV data with text,label (0/1) columns."""
import argparse, csv
from pathlib import Path
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("dataset", type=Path); parser.add_argument("--output", type=Path, default=Path("backend/models/verisuri_v1.joblib")); args = parser.parse_args()
    with args.dataset.open(encoding="utf-8", newline="") as source: rows = list(csv.DictReader(source))
    rows = [row for row in rows if row.get("text") and row.get("label") in {"0", "1"}]
    if len(rows) < 100 or len({row["label"] for row in rows}) < 2: raise ValueError("Use 100+ permissioned labelled examples with both classes.")
    model = Pipeline([("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)), ("classifier", LogisticRegression(max_iter=2000, class_weight="balanced"))])
    model.fit([row["text"].strip() for row in rows], [int(row["label"]) for row in rows]); args.output.parent.mkdir(parents=True, exist_ok=True); joblib.dump(model, args.output)
if __name__ == "__main__": main()
