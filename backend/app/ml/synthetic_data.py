"""
Synthetic training data.

Why synthetic, stated plainly: this project doesn't have months of real
labeled traffic the way a production SOC would. A real deployment would
train on historical, analyst-confirmed incidents (once case management —
Phase 8 — exists to produce those labels) or a public labeled dataset
(CICIDS2017, UNSW-NB15). Synthetic data here proves the full pipeline
works end-to-end — feature engineering, training, evaluation, inference,
explainability — correctly. It does NOT prove the model is accurate
against real-world attack traffic. That's a real, stated limitation, not
a claim being quietly avoided.

Overlap between the two classes is deliberate: benign samples occasionally
have a few failed logins (real users mistype passwords), and malicious
samples sometimes look quiet (a slow, low-and-slow attacker). A dataset
with zero overlap between classes would make both models look artificially
perfect — precision/recall near 1.0 on cleanly-separable synthetic data
proves nothing about a model's real-world value, and that kind of result
should raise suspicion, not confidence, in an interview.
"""

import numpy as np

from app.ml.features import FEATURE_NAMES

RANDOM_SEED = 42


def generate_dataset(
    n_benign: int = 500,
    n_malicious: int = 150,
    seed: int = RANDOM_SEED,
    edge_case_fraction: float = 0.15,
):
    rng = np.random.default_rng(seed)

    n_benign_noisy = int(n_benign * edge_case_fraction)
    n_benign_typical = n_benign - n_benign_noisy
    n_malicious_stealthy = int(n_malicious * edge_case_fraction)
    n_malicious_typical = n_malicious - n_malicious_stealthy

    benign_typical = np.column_stack(
        [
            rng.poisson(4, n_benign_typical),
            rng.binomial(2, 0.15, n_benign_typical),
            rng.poisson(1, n_benign_typical) + 1,
            np.ones(n_benign_typical),
            rng.binomial(1, 0.05, n_benign_typical),
            rng.poisson(1, n_benign_typical) + 1,
            rng.exponential(0.3, n_benign_typical),
            rng.uniform(0, 1, n_benign_typical),
        ]
    )
    # A noisy-but-legitimate subset — an internal vulnerability scanner, a
    # shared workstation with several users, someone who mistypes their
    # password repeatedly. Genuinely benign, but statistically closer to
    # the malicious profile than "typical" benign traffic is.
    benign_noisy = np.column_stack(
        [
            rng.poisson(15, n_benign_noisy) + 3,
            rng.binomial(5, 0.3, n_benign_noisy),
            rng.poisson(2, n_benign_noisy) + 1,
            rng.poisson(1, n_benign_noisy) + 1,
            rng.binomial(1, 0.15, n_benign_noisy),
            rng.poisson(1, n_benign_noisy) + 1,
            rng.exponential(1.0, n_benign_noisy) + 0.2,
            rng.uniform(0, 1, n_benign_noisy),
        ]
    )
    benign = np.vstack([benign_typical, benign_noisy])

    malicious_typical = np.column_stack(
        [
            rng.poisson(60, n_malicious_typical) + 10,
            rng.poisson(40, n_malicious_typical) + 5,
            rng.poisson(8, n_malicious_typical) + 1,
            rng.poisson(3, n_malicious_typical) + 1,
            rng.binomial(3, 0.5, n_malicious_typical),
            rng.poisson(1.5, n_malicious_typical) + 1,
            rng.exponential(3.0, n_malicious_typical) + 0.5,
            rng.beta(2, 1.5, n_malicious_typical),
        ]
    )
    # A stealthy, low-and-slow subset — genuinely malicious, but
    # deliberately shaped to overlap with benign traffic. This is what
    # keeps the evaluation honest: without cases like this, both models
    # would look artificially perfect, which would say more about the
    # dataset than about either model.
    malicious_stealthy = np.column_stack(
        [
            rng.poisson(8, n_malicious_stealthy) + 2,
            rng.poisson(4, n_malicious_stealthy) + 1,
            rng.poisson(2, n_malicious_stealthy) + 1,
            rng.poisson(1, n_malicious_stealthy) + 1,
            rng.binomial(1, 0.2, n_malicious_stealthy),
            rng.poisson(1, n_malicious_stealthy) + 1,
            rng.exponential(0.5, n_malicious_stealthy) + 0.1,
            rng.beta(1.5, 1.5, n_malicious_stealthy),
        ]
    )
    malicious = np.vstack([malicious_typical, malicious_stealthy])

    X = np.vstack([benign, malicious])
    y = np.concatenate([np.zeros(len(benign)), np.ones(len(malicious))])

    # Shuffle — otherwise the train/test split downstream would be trivially
    # separable by row order alone, which would be a different, sillier bug.
    shuffle_idx = rng.permutation(len(X))
    return X[shuffle_idx], y[shuffle_idx]


assert (
    len(FEATURE_NAMES) == 8
)  # keeps generate_dataset's column order honest if features.py changes
