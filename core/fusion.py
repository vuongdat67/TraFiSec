"""
TraFiSec — Stage 1 Screener: logistic fusion + ECE calibration
=====================================================================
proposal draft §3.1: score(x) = σ(w₀ + Σ_v w_v · s_v(x)); w fit bng logistic
regression trn train (attacks vs benign background); calibrate  bo xc sut.

Uses standard numpy and scipy.optimize for logistic regression and Platt scaling.
Optimization goals:
    - Robust classification between attack and benign transactions.
    - Calibrated probabilities for risk ranking under fixed FPR budgets.

Design principles:
  * Regularized logistic fusion: fits robust weights distinguishing attacks from benign traffic.
  * Missing view handling: if a view lacks debug data, logit evaluates over available views with bias offset w_0.
  * Deterministic: fixed seeds and initializations ensure reproducible scores.
"""
from __future__ import annotations

import json
import math

import numpy as np

SEED = 20260811


def _sigmoid(z: np.ndarray) -> np.ndarray:
    # Execution trace analysis and verification
    return 1.0 / (1.0 + np.exp(-np.clip(z, -40, 40)))


def _sigmoid_scalar(z: float) -> float:
    return 1.0 / (1.0 + math.exp(-max(-40.0, min(40.0, z))))


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------
class LogisticFusion:
    """score(x) = σ(w₀ + Σ_v w_v · s_v(x)); s_v ∈ [0,1], w₀ + Σw_v chnh l offset.

    - `view_names`: fixed order of behavioral views (default: 4 standard views).
    - Khi to: w₀ = 0, w = [1, 1, 1, 1] (ng nht, logit = Σ s − 1.5 offset
       score benign thp — recall-bias). Fit trn train thay th w.
    """

    DEFAULT_VIEWS = ("call_structure", "token_flow", "state_delta", "economic")

    def __init__(self, weights: dict | None = None,
                 view_names: tuple[str, ...] = DEFAULT_VIEWS,
                 offset: float = -1.5):
        self.view_names = list(view_names)
        self.offset = offset
        if weights is None:
            self.weights: dict[str, float] = {v: 1.0 for v in self.view_names}
        else:
            self.weights = {k: float(v) for k, v in weights.items()}
        self.train_recall_99_tau: float | None = None
        self.ece: float | None = None

    # ---- raw logit + score ----
    def _logit(self, scores: dict) -> float:
        """Computes weighted sum of available view scores: sum(w_v * s_v) + offset.
        hoc score None (missing data — screener truyn {v: None})."""
        acc = self.offset
        for v in self.view_names:
            s = scores.get(v)
            if s is None:
                continue
            acc += self.weights.get(v, 0.0) * float(s)
        return acc

    def score(self, scores: dict) -> float:
        """score trong [0,1] t dict {view: score|None}."""
        return _sigmoid_scalar(self._logit(scores))

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Vectorized: X shape (n, len(view_names)) — logit = offset + X @ w."""
        w = np.array([self.weights.get(v, 0.0) for v in self.view_names], dtype=float)
        z = self.offset + X @ w
        return _sigmoid(z)

    def to_dict(self) -> dict:
        return {"offset": self.offset, "view_names": self.view_names,
                "weights": self.weights, "train_recall_99_tau": self.train_recall_99_tau,
                "ece": self.ece}

    @classmethod
    def from_dict(cls, d: dict) -> "LogisticFusion":
        m = cls(weights=d.get("weights"), view_names=tuple(d.get("view_names", cls.DEFAULT_VIEWS)),
                offset=d.get("offset", -1.5))
        m.train_recall_99_tau = d.get("train_recall_99_tau")
        m.ece = d.get("ece")
        return m

    # ---- persistence ----
    def save(self, path: str) -> None:
        def stable(value):
            if isinstance(value, float):
                return round(value, 9) if math.isfinite(value) else value
            if isinstance(value, dict):
                return {key: stable(item) for key, item in value.items()}
            if isinstance(value, list):
                return [stable(item) for item in value]
            return value

        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(stable(self.to_dict()), f, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, path: str) -> "LogisticFusion":
        with open(path, encoding="utf-8") as f:
            return cls.from_dict(json.load(f))


# ---------------------------------------------------------------------------
# Execution trace analysis and verification
# ---------------------------------------------------------------------------
def fit_logistic_fusion(
    X: np.ndarray,
    y: np.ndarray,
    view_names: tuple[str, ...] = LogisticFusion.DEFAULT_VIEWS,
    offset_fixed: float | None = None,
    l2: float = 1.0,
    seed: int = SEED,
) -> LogisticFusion:
    """Fit view weights w (and offset if unconstrained) by maximizing logistic log-likelihood.

    - X: (n, len(view_names)) matrix of view feature scores in [0,1].
    - y: 1 = attack, 0 = benign.
    - offset_fixed: fixed intercept value (fits weights only).
      80 mu). None → fit c offset.
    - l2: ridge strength (trnh overfit train nh).
    - Deterministic: fixed random seed for reproducible weight optimization.
    """
    rng = np.random.default_rng(seed)
    n, p = X.shape
    if p != len(view_names):
        raise ValueError(f"X has {p} columns but view_names has length {len(view_names)}")

    # Execution trace analysis and verification
    w0 = rng.uniform(0.2, 1.2, size=p)
    fit_offset = offset_fixed is None
    x0 = np.concatenate([w0, [0.0]]) if fit_offset else w0

    def _fwd(theta: np.ndarray) -> np.ndarray:
        w = theta if not fit_offset else theta[:p]
        off = offset_fixed if offset_fixed is not None else theta[p]
        return _sigmoid(off + X @ w)

    def _nll(theta: np.ndarray) -> float:
        probs = np.clip(_fwd(theta), 1e-9, 1 - 1e-9)
        nll = -np.mean(y * np.log(probs) + (1 - y) * np.log(1 - probs))
        # Execution trace analysis and verification
        # Execution trace analysis and verification
        # Execution trace analysis and verification
        # Execution trace analysis and verification
        w = theta if not fit_offset else theta[:p]
        return float(nll + 0.5 * l2 * np.sum(w ** 2) / n)

    def _grad(theta: np.ndarray) -> np.ndarray:
        probs = _fwd(theta)
        err = (probs - y) / n
        g_w = X.T @ err
        g_w += (l2 / n) * (theta if not fit_offset else theta[:p])
        if fit_offset:
            return np.concatenate([g_w, [np.sum(err)]])
        return g_w

    try:
        from scipy.optimize import minimize
        res = minimize(_nll, x0, jac=_grad, method="L-BFGS-B",
                       options={"maxiter": 500, "ftol": 1e-8})
        theta = res.x
    except ImportError:  # Verified execution property
        theta = x0.copy()
        for _ in range(200):
            g = _grad(theta)
            theta -= 0.1 * g

    if fit_offset:
        off = float(theta[p])
        w = theta[:p]
    else:
        off = float(offset_fixed)
        w = theta
    m = LogisticFusion(weights={v: float(w[i]) for i, v in enumerate(view_names)},
                       view_names=view_names, offset=off)
    return m


# ---------------------------------------------------------------------------
# Calibration — Expected Calibration Error (ECE)
# ---------------------------------------------------------------------------
def expected_calibration_error(probs: np.ndarray, y: np.ndarray,
                               n_bins: int = 10) -> float:
    """ECE (Guo et al., 2017): Σ_b |B_b|/n · |acc_b − conf_b|.

    - probs: predicted probabilities trong [0,1].
    - y: labels 0/1.
    - Bin edges: 10 uniform bins on [0,1]; empty bins are skipped.
    """
    probs = np.asarray(probs, dtype=float)
    y = np.asarray(y, dtype=float)
    n = len(y)
    if n == 0:
        return 0.0
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    for b in range(n_bins):
        lo, hi = edges[b], edges[b + 1]
        if b == n_bins - 1:
            mask = (probs >= lo) & (probs <= hi)
        else:
            mask = (probs >= lo) & (probs < hi)
        nb = int(mask.sum())
        if nb == 0:
            continue
        acc = float(y[mask].mean())
        conf = float(probs[mask].mean())
        ece += (nb / n) * abs(acc - conf)
    return ece


# ---------------------------------------------------------------------------
# Execution trace analysis and verification
# ---------------------------------------------------------------------------
def seed_train_data() -> tuple[np.ndarray, np.ndarray, tuple[str, ...]]:
    """Seed synthetic training distribution for offline demonstration and testing.

    Generates X (n_samples, 4 views) representing realistic behavioral distributions:
      * Attack samples: high average scores with variance reflecting diverse attack vectors.
      * Benign samples: low average scores representing baseline transaction distributions.
    """
    rng = np.random.default_rng(SEED)
    views = LogisticFusion.DEFAULT_VIEWS
    n_attack, n_benign = 80, 80
    # Execution trace analysis and verification
    attack = np.clip(rng.normal([0.60, 0.65, 0.50, 0.45], [0.18, 0.20, 0.10, 0.22],
                                size=(n_attack, 4)), 0.20, 0.99)
    benign = np.clip(rng.normal([0.20, 0.15, 0.10, 0.10], [0.06, 0.05, 0.05, 0.05],
                                size=(n_benign, 4)), 0.02, 0.8)
    X = np.vstack([attack, benign])
    y = np.concatenate([np.ones(n_attack), np.zeros(n_benign)])
    return X, y, views


def fit_seed_default() -> LogisticFusion:
    """Fit default: seed train (80 attack + 80 benign), offset c nh −1.5,
    Fits logistic fusion model, computes optimal threshold tau, and calculates ECE."""
    X, y, views = seed_train_data()
    m = fit_logistic_fusion(X, y, view_names=views, offset_fixed=-1.5, l2=1.0)
    probs = m.predict(X)
    m.train_recall_99_tau = _tau_recall(probs, y, target_recall=0.99)
    m.ece = expected_calibration_error(probs, y)
    return m


def _tau_recall(probs: np.ndarray, y: np.ndarray, target_recall: float = 0.99) -> float:
    """Minimum threshold tau achieving target recall on training set."""
    pos = probs[y == 1]
    if len(pos) == 0:
        return 0.0
    n_keep = max(1, int(math.ceil(target_recall * len(pos))))
    sorted_pos = np.sort(pos)[::-1]
    return float(sorted_pos[min(n_keep - 1, len(sorted_pos) - 1)])


def calibrate_temperature(m: LogisticFusion, X: np.ndarray, y: np.ndarray) -> LogisticFusion:
    """Calibrate bng temperature scaling (Guo et al., 2017): scale logit T > 0.

    Temperature-scaled model for calibrated probability estimation.
    Maintains rank ordering while improving calibration.
    """
    from scipy.optimize import minimize_scalar

    def _ece_of_T(T: float) -> float:
        z = np.array([m._logit({v: s for v, s in zip(m.view_names, row)})
                      for row in X])
        return expected_calibration_error(_sigmoid(z / max(T, 1e-3)), y)

    res = minimize_scalar(_ece_of_T, bounds=(0.1, 10.0), method="bounded")
    T = max(float(res.x), 0.1)
    m2 = LogisticFusion(weights=m.weights, view_names=tuple(m.view_names),
                        offset=m.offset / T)
    m2.train_recall_99_tau = m.train_recall_99_tau
    m2.ece = expected_calibration_error(m2.predict(X), y)
    return m2
