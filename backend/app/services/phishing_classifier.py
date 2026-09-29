from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Sequence

import joblib
import numpy as np

logger = logging.getLogger(__name__)


# ==========================================
# CONFIG
# ==========================================

MODEL_DIR = Path(
    os.getenv("PHISHING_MODEL_DIR", Path(__file__).resolve().parents[2] / "models")
)
MODEL_PATH = MODEL_DIR / "phishing_model.pkl"
VECTORIZER_PATH = MODEL_DIR / "phishing_tfidf.pkl"

PHISHING_LABEL = 1
REVIEW_THRESHOLD = 0.40    # >= this: suspicious, send to human review
PHISHING_THRESHOLD = 0.70  # >= this: phishing
MAX_TEXT_CHARS = 50_000
BATCH_SIZE = 512
TOP_TERMS = 5


# ==========================================
# RESULT TYPES
# ==========================================

class Verdict(str, Enum):
    LEGITIMATE = "legitimate"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"


@dataclass(frozen=True)
class Classification:
    verdict: Verdict
    phishing_probability: float          # raw ML probability
    final_score: float                   # ML probability + rule adjustment
    signals: tuple[str, ...] = ()        # rule-based red flags
    top_terms: tuple[str, ...] = ()      # words pushing toward phishing

    def to_dict(self) -> dict:
        return {
            "prediction": self.verdict.value,
            "phishing_probability": self.phishing_probability,
            "final_score": self.final_score,
            "signals": list(self.signals),
            "top_terms": list(self.top_terms),
        }


# ==========================================
# MODEL LOADING
# ==========================================

@dataclass(frozen=True)
class Detector:
    vectorizer: object
    model: object
    phishing_index: int
    feature_names: Optional[np.ndarray]   # only for linear models
    coefs: Optional[np.ndarray]


_detector: Optional[Detector] = None
_lock = threading.Lock()


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_artifact(path: Path) -> None:
    """If '<file>.sha256' exists next to the artifact, the hash must match.

    joblib/pickle can execute arbitrary code on load, so only load files you
    produced yourself, and pin their hashes.
    """
    if not path.is_file():
        raise FileNotFoundError(f"Model artifact not found: {path}")
    sidecar = path.with_suffix(path.suffix + ".sha256")
    if sidecar.is_file():
        expected = sidecar.read_text().split()[0].strip().lower()
        if _sha256(path) != expected:
            raise ValueError(f"Checksum mismatch for {path.name}")
    else:
        logger.warning("No checksum file for %s; skipping integrity check", path.name)


def _build_detector() -> Detector:
    start = time.perf_counter()
    for p in (VECTORIZER_PATH, MODEL_PATH):
        _verify_artifact(p)

    vectorizer = joblib.load(VECTORIZER_PATH)
    model = joblib.load(MODEL_PATH)

    if not hasattr(model, "predict_proba"):
        raise TypeError("Model must implement predict_proba().")

    classes = list(model.classes_)
    if PHISHING_LABEL not in classes:
        raise ValueError(f"Label {PHISHING_LABEL} not in model classes {classes}")
    idx = classes.index(PHISHING_LABEL)

    # Explainability is available for linear models (LogReg, LinearSVC, ...)
    names = coefs = None
    if hasattr(model, "coef_") and hasattr(vectorizer, "get_feature_names_out"):
        raw = np.asarray(model.coef_)
        row = raw[0] if raw.shape[0] == 1 else raw[idx]
        # For binary models coef_ describes classes_[1]; flip if phishing is classes_[0]
        coefs = row if (raw.shape[0] > 1 or idx == 1) else -row
        names = vectorizer.get_feature_names_out()

    logger.info("Phishing detector ready in %.2fs", time.perf_counter() - start)
    return Detector(vectorizer, model, idx, names, coefs)


def load_detector() -> Detector:
    """Thread-safe, load-once accessor."""
    global _detector
    if _detector is None:
        with _lock:
            if _detector is None:
                _detector = _build_detector()
    return _detector


def warm_up() -> None:
    load_detector()


# ==========================================
# TEXT + RULE SIGNALS
# ==========================================

def build_email_text(subject: Optional[str], body: Optional[str]) -> str:
    """Must match the training format exactly."""
    return f"Subject: {subject or ''}\n{body or ''}"[:MAX_TEXT_CHARS]


_URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.I)
_IP_URL_RE = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}", re.I)
_SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly")
_URGENCY_RE = re.compile(
    r"\b(urgent|immediately|act now|within 24 hours|account (?:suspended|locked)|"
    r"verify your account|final notice)\b", re.I)
_CREDENTIAL_RE = re.compile(
    r"\b(password|passcode|otp|pin|ssn|social security|card number|cvv)\b", re.I)

# (signal name, score boost). Kept small so rules nudge the model, not override it.
RULE_BOOSTS = {
    "ip_address_url": 0.15,
    "url_shortener": 0.08,
    "urgency_language": 0.05,
    "credential_request": 0.08,
}
MAX_RULE_BOOST = 0.25


def rule_signals(text: str) -> tuple[str, ...]:
    found = []
    if _IP_URL_RE.search(text):
        found.append("ip_address_url")
    urls = _URL_RE.findall(text)
    if any(s in u.lower() for u in urls for s in _SHORTENERS):
        found.append("url_shortener")
    if _URGENCY_RE.search(text):
        found.append("urgency_language")
    if _CREDENTIAL_RE.search(text):
        found.append("credential_request")
    return tuple(found)


# ==========================================
# EXPLANATION
# ==========================================

def _top_terms(detector: Detector, feature_row) -> tuple[str, ...]:
    if detector.coefs is None:
        return ()
    contrib = feature_row.multiply(detector.coefs).tocoo()
    if contrib.nnz == 0:
        return ()
    order = np.argsort(contrib.data)[::-1][:TOP_TERMS]
    return tuple(
        str(detector.feature_names[contrib.col[i]])
        for i in order if contrib.data[i] > 0
    )


# ==========================================
# CLASSIFICATION
# ==========================================

def _verdict(score: float, review: float, block: float) -> Verdict:
    if score >= block:
        return Verdict.PHISHING
    if score >= review:
        return Verdict.SUSPICIOUS
    return Verdict.LEGITIMATE


def classify_emails(
    emails: Sequence[tuple[Optional[str], Optional[str]]],
    review_threshold: float = REVIEW_THRESHOLD,
    phishing_threshold: float = PHISHING_THRESHOLD,
    explain: bool = False,
) -> list[Classification]:
    if not 0.0 <= review_threshold <= phishing_threshold <= 1.0:
        raise ValueError("Need 0 <= review_threshold <= phishing_threshold <= 1")
    if not emails:
        return []

    detector = load_detector()
    results: list[Classification] = []

    for i in range(0, len(emails), BATCH_SIZE):
        chunk = emails[i : i + BATCH_SIZE]
        texts = [build_email_text(s, b) for s, b in chunk]

        features = detector.vectorizer.transform(texts)
        probs = detector.model.predict_proba(features)[:, detector.phishing_index]

        for j, (text, p) in enumerate(zip(texts, probs)):
            p = float(p)
            signals = rule_signals(text)
            boost = min(sum(RULE_BOOSTS[s] for s in signals), MAX_RULE_BOOST)
            final = min(p + boost, 1.0)

            results.append(
                Classification(
                    verdict=_verdict(final, review_threshold, phishing_threshold),
                    phishing_probability=round(p, 4),
                    final_score=round(final, 4),
                    signals=signals,
                    top_terms=_top_terms(detector, features[j]) if explain else (),
                )
            )
    return results


def classify_email(
    subject: Optional[str],
    body: Optional[str],
    explain: bool = False,
    **kwargs,
) -> dict:
    """Backward-compatible single-email API returning a dict."""
    return classify_emails([(subject, body)], explain=explain, **kwargs)[0].to_dict()