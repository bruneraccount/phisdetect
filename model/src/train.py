import joblib
import numpy as np
import os
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, brier_score_loss
from sklearn.model_selection import StratifiedKFold, train_test_split

from extract_features import FEATURES

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAINED = os.path.join(_ROOT, "trained")

df = pd.read_csv(os.path.join(TRAINED, "dataset_augmented.csv"))

missing = [c for c in FEATURES if c not in df.columns]
if missing:
    raise SystemExit(f"Missing columns in CSV: {missing}")

X = df[FEATURES]
y = df["phishing"]

print(f"Features: {len(FEATURES)}")
print(f"Rows: {len(X)}  (phish {int(y.sum())} / benign {int((1 - y).sum())})")

skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
tps = fps = fns = tns = 0
oof_prob = np.zeros(len(y))
for fold, (tr_idx, te_idx) in enumerate(skf.split(X, y), 1):
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X.iloc[tr_idx], y.iloc[tr_idx])
    prob = model.predict_proba(X.iloc[te_idx])[:, 1]
    oof_prob[te_idx] = prob
    pred = (prob >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y.iloc[te_idx], pred).ravel()
    tns, fps, fns, tps = tns + tn, fps + fp, fns + fn, tps + tp
    acc = accuracy_score(y.iloc[te_idx], pred)
    print(f"fold {fold}: acc={acc:.4f} fp={fp} fn={fn}")

print(f"\nCV totals: tp={tps} fp={fps} fn={fns} tn={tns}")
print(f"accuracy: {(tps + tns) / (tps + tns + fps + fns):.4f}")
print(f"false-positive rate (benign flagged): {fps / (fps + tns):.4f}")
print(f"false-negative rate (phish missed):   {fns / (fns + tps):.4f}")

print(f"\nraw RF out-of-fold Brier score: {brier_score_loss(y, oof_prob):.4f}")

bins = np.array([0.0, 0.2, 0.4, 0.6, 0.8, 1.01])
for lo, hi in zip(bins[:-1], bins[1:]):
    m = (oof_prob >= lo) & (oof_prob < hi)
    if m.sum() == 0:
        continue
    print(f"  prob {lo:.1f}-{hi:.1f}: n={m.sum():5d}  mean_pred={oof_prob[m].mean():.3f}  actual_phish={y[m].mean():.3f}")

print("\nCalibration check on a 20% held-out split (isotonic, cv=5):")
X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
rf_raw = RandomForestClassifier(n_estimators=100, random_state=42)
rf_raw.fit(X_tr, y_tr)
raw_prob = rf_raw.predict_proba(X_te)[:, 1]
cal = CalibratedClassifierCV(
    estimator=RandomForestClassifier(n_estimators=100, random_state=42),
    method="isotonic", cv=5)
cal.fit(X_tr, y_tr)
cal_prob = cal.predict_proba(X_te)[:, 1]
print(f"  raw  Brier={brier_score_loss(y_te, raw_prob):.4f} acc={accuracy_score(y_te, (raw_prob >= 0.5).astype(int)):.4f}")
print(f"  cal  Brier={brier_score_loss(y_te, cal_prob):.4f} acc={accuracy_score(y_te, (cal_prob >= 0.5).astype(int)):.4f}")
for lo, hi in zip(bins[:-1], bins[1:]):
    m = (cal_prob >= lo) & (cal_prob < hi)
    if m.sum() == 0:
        continue
    print(f"  cal prob {lo:.1f}-{hi:.1f}: n={m.sum():5d}  mean_pred={cal_prob[m].mean():.3f}  actual_phish={y_te[m].mean():.3f}")

print("\nFitting final calibrated model on ALL data...")
model = CalibratedClassifierCV(
    estimator=RandomForestClassifier(n_estimators=100, random_state=42),
    method="isotonic", cv=5)
model.fit(X, y)

imp = pd.Series(model.calibrated_classifiers_[0].estimator.feature_importances_,
                index=FEATURES).sort_values(ascending=False)
print("\nTop 15 features:")
for name, val in imp.head(15).items():
    print(f"  {val:8.4f}  {name}")

joblib.dump(model, os.path.join(TRAINED, "phishing_model.joblib"))
with open(os.path.join(TRAINED, "features.txt"), "w") as f:
    f.write("\n".join(FEATURES))
print("\nSaved calibrated phishing_model.joblib + features.txt")
