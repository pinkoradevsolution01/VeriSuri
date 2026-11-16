"""Train/evaluate VeriSuri V1 from permissioned UTF-8 CSV data only."""
import argparse, csv, json
from pathlib import Path
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path, help="Permissioned CSV containing text,label,language,source columns")
    parser.add_argument("--output", type=Path, default=Path("backend/models/verisuri_v1.joblib"))
    parser.add_argument("--metrics", type=Path, default=Path("backend/models/verisuri_v1.metrics.json"))
    parser.add_argument("--version", default="verisuri-hybrid-v1")
    args = parser.parse_args()
    with args.dataset.open(encoding="utf-8", newline="") as source: rows = list(csv.DictReader(source))
    rows = [row for row in rows if row.get("text") and row.get("label") in {"0", "1"}]
    if len(rows) < 100 or len({row["label"] for row in rows}) < 2: raise ValueError("Use 100+ permissioned labelled examples with both classes.")
    texts, labels = [row["text"].strip() for row in rows], [int(row["label"]) for row in rows]
    train_x, test_x, train_y, test_y = train_test_split(texts, labels, test_size=.2, random_state=42, stratify=labels)
    model = Pipeline([("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)), ("classifier", LogisticRegression(max_iter=2000, class_weight="balanced"))])
    model.fit(train_x, train_y)
    predicted, probabilities = model.predict(test_x), model.predict_proba(test_x)[:, 1]
    precision, recall, f1, _ = precision_recall_fscore_support(test_y, predicted, average="binary", zero_division=0)
    metrics = {"version": args.version, "dataset_rows": len(rows), "train_rows": len(train_x), "test_rows": len(test_x), "accuracy": round(accuracy_score(test_y, predicted), 4), "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4), "roc_auc": round(roc_auc_score(test_y, probabilities), 4), "warning": "Evaluate disaggregated Filipino, English, and Taglish performance before production release."}
    args.output.parent.mkdir(parents=True, exist_ok=True); joblib.dump(model, args.output); args.metrics.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))
if __name__ == "__main__": main()
