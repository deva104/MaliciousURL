"""Consistent plotting style + numbered figure saving for the EDA notebook."""
from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import seaborn as sns

from .config import FIGURES

# Validated categorical palette (colour-blind safe adjacent pairs, light surface).
# Colour follows the ENTITY: benign is always blue, malicious always orange.
TYPE_COLORS = {
    "benign": "#2a78d6",
    "defacement": "#1baf7a",
    "phishing": "#eb6834",
    "malware": "#6250d6",
}
TYPE_ORDER = ["benign", "defacement", "phishing", "malware"]
LABEL_COLORS = {0: "#2a78d6", 1: "#eb6834"}
LABEL_NAMES = {0: "benign", 1: "malicious"}
BINARY_PALETTE = {"benign": "#2a78d6", "malicious": "#eb6834"}
NEUTRAL = "#898781"
INK = "#0b0b0b"
INK_2 = "#52514e"
GRID = "#e1e0d9"
SURFACE = "#fcfcfb"
SEQ_CMAP = "Blues"
DIV_CMAP = "RdBu_r"


def set_style() -> None:
    sns.set_theme(style="whitegrid", context="notebook")
    plt.rcParams.update({
        "figure.facecolor": SURFACE,
        "axes.facecolor": SURFACE,
        "savefig.facecolor": SURFACE,
        "axes.edgecolor": "#c3c2b7",
        "axes.labelcolor": INK_2,
        "axes.titlecolor": INK,
        "axes.titlesize": 12,
        "axes.titleweight": "bold",
        "axes.labelsize": 10,
        "xtick.color": INK_2,
        "ytick.color": INK_2,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "grid.color": GRID,
        "grid.linewidth": 0.8,
        "legend.frameon": False,
        "legend.fontsize": 9,
        "figure.dpi": 100,
        "savefig.dpi": 150,
        "savefig.bbox": "tight",
        "font.family": "sans-serif",
    })


def savefig(fig: plt.Figure, number: int, name: str, folder: Path = FIGURES) -> Path:
    """Save as reports/figures/NN_name.png (dpi 150) and return the path."""
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{number:02d}_{name}.png"
    fig.savefig(path, dpi=150)
    return path


def pct_labels(ax: plt.Axes, fmt: str = "{:.1f}%", inside: bool = False, **kw) -> None:
    """Label bar ends with their value (only used where every bar matters)."""
    for container in ax.containers:
        ax.bar_label(container, fmt=fmt, padding=2 if not inside else -12,
                     fontsize=8, color=INK_2, **kw)
