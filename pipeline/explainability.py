"""Explainability layer.

Turns a model's per-host anomaly score into ranked, signed feature contributions
(which features pushed the score up, and by how much). This is the ONLY module that
touches the underlying attribution engine, so the rest of the pipeline depends on
`TreeAttribution` and never on a specific library. Swap the engine here and nothing
else in the pipeline has to change.
"""
import shap as _engine


class TreeAttribution:
    """Local feature attribution for a tree model (Isolation Forest, gradient-boosted trees).

    contributions(X) returns, for each row, the per-feature contribution to that row's
    score — positive means the feature pushed the score up.
    """

    def __init__(self, model):
        self._explainer = _engine.TreeExplainer(model)

    def contributions(self, X):
        return self._explainer.shap_values(X)


class _Precomputed:
    """Wrap already-computed contributions in the same interface (used for the re-ranker)."""

    def __init__(self, values):
        self._values = values

    def contributions(self, _X):
        return self._values
