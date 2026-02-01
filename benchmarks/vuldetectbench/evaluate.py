#!/usr/bin/env python3
"""Mini evaluation harness for VulDetectBench-style metrics."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple


def _load_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _normalize_type(t: str) -> str:
    if not t:
        return "unknown"
    return t.lower().replace("_", "-").replace(" ", "-")


def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return max(a_start, b_start) <= min(a_end, b_end)


def _find_match(predictions: List[Dict[str, Any]], gt: Dict[str, Any]) -> Tuple[Dict[str, Any] | None, bool]:
    gt_file = gt.get("file")
    gt_type = _normalize_type(gt.get("type", ""))
    for pred in predictions:
        if gt_file and pred.get("file") != gt_file:
            continue
        pred_type = _normalize_type(pred.get("type", ""))
        if pred_type == gt_type:
            return pred, True
    return None, False


def evaluate(predictions: List[Dict[str, Any]], ground_truth: List[Dict[str, Any]]) -> Dict[str, Any]:
    detection_hits = 0
    classification_hits = 0
    localization_hits = 0
    trigger_hits = 0

    for gt in ground_truth:
        pred, type_match = _find_match(predictions, gt)
        if pred:
            detection_hits += 1
        if type_match:
            classification_hits += 1

        if pred and gt.get("line_start") is not None:
            p_start = int(pred.get("line_start", pred.get("line", 0)) or 0)
            p_end = int(pred.get("line_end", p_start) or p_start)
            g_start = int(gt.get("line_start", 0))
            g_end = int(gt.get("line_end", g_start))
            if _overlaps(p_start, p_end, g_start, g_end):
                localization_hits += 1

        if pred and gt.get("trigger_line") is not None:
            if int(pred.get("trigger_line", 0) or 0) == int(gt.get("trigger_line", 0)):
                trigger_hits += 1

    total = len(ground_truth) or 1
    return {
        "total": len(ground_truth),
        "detection_recall": round(detection_hits / total, 3),
        "classification_recall": round(classification_hits / total, 3),
        "localization_recall": round(localization_hits / total, 3),
        "trigger_recall": round(trigger_hits / total, 3),
        "detection_hits": detection_hits,
        "classification_hits": classification_hits,
        "localization_hits": localization_hits,
        "trigger_hits": trigger_hits,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--predictions", required=True, help="Path to predictions JSON")
    parser.add_argument(
        "--ground-truth",
        required=True,
        help="Path to ground truth JSON",
    )
    args = parser.parse_args()

    preds_raw = _load_json(args.predictions)
    if isinstance(preds_raw, dict):
        predictions = preds_raw.get("findings", preds_raw.get("enhanced_findings", []))
    else:
        predictions = preds_raw

    ground_raw = _load_json(args.ground_truth)
    ground_truth = ground_raw.get("findings", ground_raw)

    report = evaluate(predictions, ground_truth)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
