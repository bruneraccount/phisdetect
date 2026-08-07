import os
import random
import urllib.request

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.model_selection import train_test_split

from url_text_features import analyzer, url_text

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(MODEL_DIR)


def download(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 PhisDetect/1.0"})
    return urllib.request.urlopen(req, timeout=180).read()


def fetch_phish():
    out = []
    sources = (
        "https://openphish.com/feed.txt",
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
    )
    for source in sources:
        body = download(source).decode("utf-8", "replace")
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            u = url_text(line)
            if u:
                out.append(u)
    return list(dict.fromkeys(out))


def fetch_benign(n):
    random.seed(42)
    path = os.path.join(_ROOT, "lists", "tranco_top1m.txt")
    with open(path) as f:
        domains = [d.strip() for d in f if d.strip()]
    guaranteed = set(domains[:5000])
    extra = random.sample(domains[5000:], max(0, n - len(guaranteed)))
    sample = list(guaranteed) + list(extra)
    random.shuffle(sample)
    out = []
    for d in sample:
        variants = [
            d,
            "www." + d,
            d + "/",
            d + "/login",
            d + "/index.html",
            d + "/about",
            d + "/account/settings",
            d + "/products?id=5",
        ]
        for v in variants:
            t = url_text("https://" + v)
            if t:
                out.append(t)
    return out[:n]


def main():
    phish = fetch_phish()
    random.seed(42)
    if len(phish) > 150000:
        phish = random.sample(phish, 150000)
    benign = fetch_benign(len(phish))
    X = phish + benign
    y = [1] * len(phish) + [0] * len(benign)
    print(f"phish: {len(phish)}, benign: {len(benign)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42)

    vec = TfidfVectorizer(analyzer=analyzer, min_df=2, max_features=150000,
                          sublinear_tf=True)
    clf = LogisticRegression(C=1.0, solver="liblinear", max_iter=2000,
                             class_weight="balanced")
    vec.fit(X_train)
    Xtr = vec.transform(X_train)
    clf.fit(Xtr, y_train)
    y_pred = clf.predict(vec.transform(X_test))
    acc = accuracy_score(y_test, y_pred)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    print(f"Accuracy: {acc:.4f}")
    print(f"Benign correct: {tn}, Benign flagged: {fp}")
    print(f"Phish missed: {fn}, Phish caught: {tp}")

    joblib.dump((vec, clf), os.path.join(_ROOT, "trained", "url_text_model.joblib"))
    print("Saved url_text_model.joblib")

    checks = [
        "https://niggersforsale.com",
        "https://nigga.org.xyz",
        "http://amazoon.com.org.xyz",
        "http://paypal.com.secure-login-verify.xyz/account/confirm.php?id=98213",
        "https://www.google.com",
        "https://www.amazon.com",
        "https://signin.aws.amazon.com",
        "http://www.appleseed.com",
        "http://info.com",
        "http://www.roblox.ly",
        "https://www.facebook.com",
        "https://shop.amazon.co.uk",
        "http://free-bitcoin-casino-winner.xyz",
        "http://192.168.1.1",
    ]
    for u in checks:
        prob = float(clf.predict_proba(vec.transform([url_text(u)]))[0][1])
        print(f"  {u:60s} phish-prob={prob:.2f}")


if __name__ == "__main__":
    main()
