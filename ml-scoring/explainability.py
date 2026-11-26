"""Explainability layer for the connection scorer.

The only module that touches the underlying attribution engine; the scorer depends on
`TreeAttribution` and never on a specific library, so the engine can be swapped here alone.
"""
import shap as _engine


class TreeAttribution:
    """Local per-feature attribution for a tree model. contributions(X) returns, for each
    row, how much each feature pushed that row's score (positive = pushed it up)."""

    def __init__(self, model):
        self._explainer = _engine.TreeExplainer(model)

    def contributions(self, X):
        return self._explainer.shap_values(X)
