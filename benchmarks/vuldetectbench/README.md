# VulDetectBench Mini Harness

This directory provides a lightweight evaluation harness inspired by VulDetectBench. It focuses on:

- Detection (does the model detect the vulnerability?)
- Classification (does it label the correct vulnerability type?)
- Root-cause localization (does the finding overlap the correct line range?)
- Trigger localization (does it identify the triggering line?)

## Contents

- `evaluate.py`: CLI evaluator for prediction JSON vs ground truth
- `golden/`: Small golden suite of Solidity contracts + labels

## Usage

```bash
python benchmarks/vuldetectbench/evaluate.py \
  --predictions path/to/predictions.json \
  --ground-truth benchmarks/vuldetectbench/golden/ground_truth.json
```

The predictions JSON should contain a list of findings with fields like:

```json
[
  {
    "file": "ReentrancyVuln.sol",
    "type": "reentrancy",
    "line_start": 11,
    "line_end": 12,
    "trigger_line": 11
  }
]
```
