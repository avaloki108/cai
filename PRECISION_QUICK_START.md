# CAI Precision Enhancements - Quick Start Guide

Get started with the new precision enhancements in 5 minutes.

---

## Installation

### Minimal Setup (Rules + Calibration)

```bash
pip install pyyaml scikit-learn
```

### Full ML Features

```bash
pip install pyyaml scikit-learn transformers torch xgboost
```

---

## Quick Usage

### 1. Use Adversarial Pattern with Skeptics

```python
from cai.agents.patterns import adversarial_pattern_with_skeptics

# Create pattern with integrated skeptic critics
pattern = adversarial_pattern_with_skeptics(
    name="audit_with_skeptics",
    auditors=[your_auditor_agent],
    consensus_threshold=0.66
)

# Execute
results = await pattern.execute("contracts/MyContract.sol")
print(f"Validated: {len(results['validated'])} findings")
print(f"Rejected by skeptics: {len(results['rejected'])} findings")
```

### 2. Apply Protocol-Specific Analysis

```python
from cai.tools.web3_security.protocols import LendingAnalyzer

# Analyze lending protocol
analyzer = LendingAnalyzer()
vulnerabilities = analyzer.analyze(contract_code, "AavePool")

# Generate report
report = analyzer.generate_report(vulnerabilities)
print(report["summary"])
```

### 3. Use Rule-Based Validation

```python
from cai.tools.web3_security.rules import get_rule_for_finding

finding = {"type": "reentrancy-eth", "confidence": 0.7}

# Get rule and check false positives
rule = get_rule_for_finding(finding["type"])
if rule and not rule.is_false_positive(code_context):
    adjusted_confidence = rule.calculate_adjusted_confidence(
        base_confidence=0.7,
        tool="slither",
        code_context=code_context
    )
```

### 4. Enable SmartBERT Embeddings

```bash
# Set environment variable
export CAI_USE_SMARTBERT=true

# Or in Python
import os
os.environ["CAI_USE_SMARTBERT"] = "true"
```

```python
from cai.ml.embeddings import get_embedder

embedder = get_embedder()
similarity = embedder.compute_similarity(code1, code2)
```

### 5. Use ML Classifier

```python
from cai.ml.classifier import get_classifier

classifier = get_classifier()
result = classifier.predict(finding, code_context)

if result.is_true_positive:
    print(f"True positive ({result.probability:.1%} probability)")
else:
    print(f"Likely false positive ({result.probability:.1%} probability)")
```

### 6. Calibrate Confidence Scores

```python
from cai.ml.calibration import get_calibrator

calibrator = get_calibrator()

# Calibrate single score
calibrated = calibrator.calibrate(
    tool="slither",
    vuln_type="reentrancy",
    score=0.7
)

# Or batch calibrate
calibrated_findings = calibrator.calibrate_batch(findings)
```

### 7. Use Composite Pattern (Maximum Precision)

```python
from cai.agents.patterns import composite_audit_pattern

# Full precision pipeline
pattern = composite_audit_pattern(
    name="max_precision",
    hmaw_agents={
        "vulnerability": [vuln_hunters],
        "economic": [econ_analyzer],
        "access": [access_checker]
    },
    auditors=[auditor1, auditor2],
    ensemble_agents=[validator1, validator2, validator3]
)

# Execute all stages
results = await pattern.execute(target="contracts/")

# Final findings have passed:
# - HMAW domain analysis
# - Adversarial skeptic validation
# - Ensemble consensus voting
high_precision_findings = results["final_findings"]
```

---

## Configuration

### Environment Variables

```bash
# Enable SmartBERT embeddings
export CAI_USE_SMARTBERT=true

# Use composite pattern by default
export CAI_PATTERN=composite_audit

# Enable all skeptics
export CAI_SKEPTIC_LEVEL=all

# Set ensemble voting method
export CAI_ENSEMBLE_VOTING=weighted_majority
```

---

## Verification

### Check All Components

```python
# 1. Check rules loaded
from cai.tools.web3_security.rules import get_rule_manager
manager = get_rule_manager()
print(f"✅ Loaded {len(manager.list_rules())} rules")

# 2. Check embeddings
from cai.ml.embeddings import get_embedder
embedder = get_embedder()
emb = embedder.embed_code("contract Test {}")
print(f"✅ Embeddings: {len(emb)}-dim")

# 3. Check classifier
from cai.ml.classifier import get_classifier
classifier = get_classifier()
print(f"✅ Classifier available: {classifier.model is not None or 'fallback'}")

# 4. Check calibrator
from cai.ml.calibration import get_calibrator
calibrator = get_calibrator()
print(f"✅ Calibrator: {len(calibrator.list_calibrations())} calibrations loaded")

# 5. Check patterns
from cai.agents.patterns import (
    adversarial_pattern_with_skeptics,
    composite_audit_pattern
)
print("✅ Enhanced patterns available")

# 6. Check protocol analyzers
from cai.tools.web3_security.protocols import (
    LendingAnalyzer, AMMAnalyzer, GovernanceAnalyzer, StakingAnalyzer
)
print("✅ Protocol analyzers available")

# 7. Check symbolic modules
from cai.tools.web3_security.symbolic.constraint_analyzer import (
    extract_constraints_from_mythril
)
from cai.tools.web3_security.symbolic.correlator import (
    correlate_slither_mythril
)
print("✅ Symbolic analysis modules available")
```

---

## Example: Complete Precision Workflow

```python
from cai.agents.patterns import composite_audit_pattern
from cai.ml.classifier import get_classifier
from cai.ml.calibration import get_calibrator
from cai.tools.web3_security.protocols import LendingAnalyzer
from cai.tools.web3_security.symbolic.correlator import correlate_slither_mythril

async def precision_audit(contract_path: str):
    # 1. Protocol-specific pre-analysis
    with open(contract_path) as f:
        code = f.read()
    
    if "borrow" in code.lower() or "lend" in code.lower():
        protocol_analyzer = LendingAnalyzer()
        protocol_vulns = protocol_analyzer.analyze(code)
        print(f"Protocol analysis: {len(protocol_vulns)} issues")
    
    # 2. Composite pattern execution
    pattern = composite_audit_pattern(
        name="precision_audit",
        hmaw_agents={"vulnerability": [hunter], "economic": [econ]},
        auditors=[auditor],
        ensemble_agents=[val1, val2]
    )
    
    results = await pattern.execute(contract_path)
    findings = results["final_findings"]
    
    # 3. ML classification
    classifier = get_classifier()
    for finding in findings:
        classification = classifier.predict(finding, code)
        finding["ml_probability"] = classification.probability
    
    # 4. Confidence calibration
    calibrator = get_calibrator()
    calibrated = calibrator.calibrate_batch(findings)
    
    # 5. Final high-precision report
    high_confidence = [
        f for f in calibrated
        if f.get("calibrated_confidence", 0) >= 0.8
    ]
    
    return {
        "total_findings": len(findings),
        "high_confidence_findings": len(high_confidence),
        "findings": high_confidence,
        "precision_estimate": results["summary"]["adversarial_precision"]
    }
```

---

## Troubleshooting

### Issue: SmartBERT not loading

**Solution:**
```bash
pip install transformers torch
export CAI_USE_SMARTBERT=true
```

Falls back to hash-based if unavailable (no error).

### Issue: Rules not found

**Solution:**
```python
from cai.tools.web3_security.rules import get_rule_manager
manager = get_rule_manager()
manager.load_rules(force_reload=True)
```

### Issue: Classifier shows "fallback"

**Expected** - Train classifier on your audit data:
```python
classifier.train(X_features, y_labels)
classifier.save_model("~/.cache/cai/models/classifier.pkl")
```

---

## What's Next?

1. **Train your classifier** on your historical audit data
2. **Calibrate confidence** using validated findings
3. **Add custom rules** for your specific use cases
4. **Use composite pattern** for highest precision audits

**All components are production-ready!**
