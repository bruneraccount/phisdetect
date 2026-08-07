import os
import random
import sys

import pandas as pd

from extract_features import FEATURES, extract

HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(HERE)
BASE = os.path.join(_ROOT, "trained", "dataset_small.csv")
OUT = os.path.join(_ROOT, "trained", "dataset_augmented.csv")
TRANCO = os.path.join(_ROOT, "lists", "tranco_top1m.txt")

PATHS = [
    "/watch?v={t}",
    "/watch?v={t}&list=PL{num}&index={num}",
    "/search?q={words}",
    "/s?k={words}&ref=nb_sb_noss",
    "/products?id={num}",
    "/products/{slug}",
    "/product/{slug}?variant={num}",
    "/account/login?redirect={path}",
    "/signin?next={path}",
    "/blog/{slug}",
    "/articles/{slug}-{year}",
    "/downloads/file-{name}.pdf",
    "/api/v2/items?limit={num}&offset={num}&sort=desc",
    "/index.php?page=home&lang=en",
    "/docs/{section}/index.html",
    "/user/{name}/profile",
    "/tracking/click?id={t}&ref=email",
    "/checkout/{num}/confirm?token={t}",
    "/",
    "/about",
]

SUB_DOMAINS = ["", "www.", "m.", "shop.", "blog.", "accounts.", "docs.", "support.", "help."]

CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"
WORDS = ["python", "project", "release", "update", "report", "budget", "api", "data",
         "client", "invoice", "holiday", "meeting", "sprint", "roadmap", "docs", "guide"]

DNS_DEFAULTS = {"qty_ip_resolved": 1, "ttl_hostname": 300, "qty_nameservers": 2,
                "qty_mx_servers": 1, "domain_spf": 1}


def rand_token(n=10):
    return "".join(random.choice(CHARS) for _ in range(n))


def rand_slug():
    return "-".join(random.sample(WORDS, random.randint(1, 3)))


def gen_url(domain):
    sub = random.choice(SUB_DOMAINS)
    path = random.choice(PATHS)
    t = rand_token(random.choice([8, 10, 11, 12])) + random.choice(["", "_R1_s", "_x", "="])
    words = random.sample(WORDS, random.randint(1, 3))
    if random.random() < 0.5:
        words = ["".join(random.choice(CHARS) for _ in range(random.randint(4, 6)))] + words
    path = path.replace("{path}", f"/{rand_slug()}/{rand_token(6)}")
    path = path.format(
        t=t,
        num=random.randint(1, 5000),
        words="+".join(words),
        slug=rand_slug(),
        year=random.randint(2019, 2026),
        name=rand_slug(),
        section=random.choice(["getting-started", "reference", "api"]),
        user=random.choice(WORDS) + str(random.randint(1, 99)),
    )
    return f"https://{sub}{domain}{path}"


def main():
    if not os.path.exists(BASE):
        print("dataset_small.csv not found")
        return 1
    if not os.path.exists(TRANCO):
        print("lists/tranco_top1m.txt not found")
        return 1

    base = pd.read_csv(BASE)
    print(f"base dataset: {len(base)} rows ({base['phishing'].value_counts().to_dict()})")

    with open(TRANCO) as f:
        domains = [line.strip().lower() for line in f if line.strip()][:1500]
    random.seed(7)
    domains = random.sample(domains, 600)
    guaranteed = ["youtube.com", "google.com", "amazon.com", "wikipedia.org", "github.com",
                  "stackoverflow.com", "reddit.com", "twitter.com", "facebook.com",
                  "netflix.com", "spotify.com", "linkedin.com", "apple.com",
                  "microsoft.com", "yahoo.com", "paypal.com", "ebay.com", "walmart.com"]
    for g in guaranteed:
        if g not in domains:
            domains.append(g)

    rows = []
    for d in domains:
        for _ in range(5):
            url = gen_url(d)
            try:
                feats = extract(url, with_dns=False)
            except Exception:
                continue
            feats.update(DNS_DEFAULTS)
            feats["phishing"] = 0
            rows.append(feats)

    aug = pd.DataFrame(rows, columns=FEATURES + ["phishing"])
    print(f"augmented benign rows: {len(aug)}")
    for c in aug.columns:
        if c not in base.columns:
            print(f"  new col: {c}")
            base[c] = -1

    combined = pd.concat([base, aug], ignore_index=True)
    missing = [c for c in FEATURES if c not in combined.columns]
    if missing:
        print("missing features:", missing)
        return 1
    combined = combined[FEATURES + ["phishing"]]
    combined.to_csv(OUT, index=False)
    print(f"saved {OUT}: {len(combined)} rows "
          f"({combined['phishing'].value_counts().to_dict()})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
