from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class Proportion:
    numerator: int
    denominator: int
    value: float | None
    wilson_95: tuple[float, float] | None


@dataclass(frozen=True)
class SessionMetrics:
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    unknown: int
    recall: Proportion
    precision: Proportion
    false_positive_rate: Proportion
    status: str


def session_metrics(*, tp: int, fp: int, tn: int, fn: int, unknown: int = 0) -> SessionMetrics:
    positive = tp + fn
    negative = fp + tn
    return SessionMetrics(
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        unknown=unknown,
        recall=_proportion(tp, positive),
        precision=_proportion(tp, tp + fp),
        false_positive_rate=_proportion(fp, negative),
        status="measured" if positive >= 10 and negative >= 20 else "insufficient_sample",
    )


def _proportion(numerator: int, denominator: int) -> Proportion:
    if denominator == 0:
        return Proportion(numerator, denominator, None, None)
    value = numerator / denominator
    z = 1.959963984540054
    z2 = z * z
    scale = 1 + z2 / denominator
    centre = (value + z2 / (2 * denominator)) / scale
    margin = z * math.sqrt((value * (1 - value) + z2 / (4 * denominator)) / denominator) / scale
    return Proportion(
        numerator, denominator, value, (max(0.0, centre - margin), min(1.0, centre + margin))
    )
