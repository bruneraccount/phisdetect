import json
import os
import sys

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline

from email_text_features import clean_email

HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(HERE)
DATASET = os.path.join(_ROOT, "data", "email_text_dataset.jsonl")
OUT = os.path.join(_ROOT, "trained", "email_text_model.joblib")


def load_data(path):
    X, y = [], []
    with open(path) as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            X.append(clean_email(rec["text"]))
            y.append(rec["label"])
    return X, y


def main():
    if not os.path.exists(DATASET):
        print("no dataset found; run update_email_data.py first")
        return 1
    X, y = load_data(DATASET)
    print(f"loaded {len(X)} emails ({sum(y)} phish / {len(y) - sum(y)} benign)")

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    pipe = make_pipeline(
        TfidfVectorizer(
            analyzer="word",
            ngram_range=(1, 2),
            min_df=2,
            max_features=200000,
            sublinear_tf=True,
        ),
        LogisticRegression(C=1.0, max_iter=1000, class_weight="balanced"),
    )
    pipe.fit(X_tr, y_tr)

    acc = pipe.score(X_te, y_te)
    print(f"holdout accuracy: {acc:.4f}")
    print(classification_report(y_te, pipe.predict(X_te), target_names=["benign", "phish"]))

    joblib.dump(pipe, OUT)
    print(f"saved {OUT}")

    vec, clf = pipe[0], pipe[1]
    print(f"vocab size: {len(vec.vocabulary_)}")

    for sample in [
        "Dear user, your account has been suspended. Click here immediately to verify your identity.",
        "Hi Alex, lunch on friday at the usual place? Let me know what you think. Best, Sarah",
        "we detected unusual activity on your account please confirm your payment details now",
        "the quarterly report is attached for your review, let me know if you have questions",
    ]:
        p = pipe.predict_proba([clean_email(sample)])[0][1]
        print(f"  phish_prob={p:.3f} | {sample[:60]!r}")


if __name__ == "__main__":
    sys.exit(main())
