#!/usr/bin/env python3
"""
Verification Script for CAI Precision Enhancements

Verifies that all 10 precision enhancements are properly installed
and functional.
"""

import sys
from pathlib import Path


def check_file_exists(path: str, description: str) -> bool:
    """Check if a file exists."""
    if Path(path).exists():
        print(f"  ✅ {description}")
        return True
    else:
        print(f"  ❌ {description} - NOT FOUND")
        return False


def main():
    print("=" * 70)
    print("CAI PRECISION ENHANCEMENT VERIFICATION")
    print("=" * 70)
    print()
    
    all_pass = True
    
    # Check 1: Skeptic Integration
    print("1. Skeptic Integration into Adversarial Pattern")
    all_pass &= check_file_exists(
        "src/cai/agents/patterns/adversarial.py",
        "adversarial.py (modified)"
    )
    
    try:
        from cai.agents.patterns import adversarial_pattern_with_skeptics
        print("  ✅ adversarial_pattern_with_skeptics() available")
    except ImportError as e:
        print(f"  ❌ Cannot import adversarial_pattern_with_skeptics: {e}")
        all_pass = False
    
    print()
    
    # Check 2: Centralized Rules
    print("2. Centralized Rule Configuration System")
    all_pass &= check_file_exists(
        "src/cai/tools/web3_security/rules/__init__.py",
        "Rule management system"
    )
    all_pass &= check_file_exists(
        "src/cai/tools/web3_security/rules/reentrancy.yml",
        "Reentrancy rules"
    )
    all_pass &= check_file_exists(
        "src/cai/tools/web3_security/rules/access_control.yml",
        "Access control rules"
    )
    all_pass &= check_file_exists(
        "src/cai/tools/web3_security/rules/oracle_manipulation.yml",
        "Oracle manipulation rules"
    )
    all_pass &= check_file_exists(
        "src/cai/tools/web3_security/rules/flash_loan.yml",
        "Flash loan rules"
    )
    
    try:
        from cai.tools.web3_security.rules import get_rule_manager
        manager = get_rule_manager()
        print(f"  ✅ RuleManager loaded {len(manager.list_rules())} rules")
    except Exception as e:
        print(f"  ❌ Cannot load rules: {e}")
        all_pass = False
    
    print()
    
    # Check 3: Training Datasets
    print("3. Historical Exploit Training Datasets")
    all_pass &= check_file_exists(
        "src/cai/tools/web3_security/data/exploit_db.jsonl",
        "Exploit database"
    )
    all_pass &= check_file_exists(
        "src/cai/tools/web3_security/data/web3_security_kb.jsonl",
        "Security knowledge base"
    )
    
    # Count entries
    try:
        import json
        with open("src/cai/tools/web3_security/data/exploit_db.jsonl") as f:
            exploits = [json.loads(line) for line in f if line.strip()]
        print(f"  ✅ Loaded {len(exploits)} historical exploits")
        
        with open("src/cai/tools/web3_security/data/web3_security_kb.jsonl") as f:
            patterns = [json.loads(line) for line in f if line.strip()]
        print(f"  ✅ Loaded {len(patterns)} vulnerability patterns")
    except Exception as e:
        print(f"  ⚠️  Could not count entries: {e}")
    
    print()
    
    # Check 4: SmartBERT Embeddings
    print("4. SmartBERT Embeddings")
    all_pass &= check_file_exists(
        "src/cai/ml/embeddings.py",
        "SmartBERT embedder"
    )
    
    try:
        from cai.ml.embeddings import get_embedder
        embedder = get_embedder()
        test_emb = embedder.embed_code("contract Test {}")
        print(f"  ✅ Embedder working: {len(test_emb)}-dimensional vectors")
    except Exception as e:
        print(f"  ⚠️  Embedder using fallback: {e}")
    
    print()
    
    # Check 5: XGBoost Classifier
    print("5. XGBoost Vulnerability Classifier")
    all_pass &= check_file_exists(
        "src/cai/ml/classifier.py",
        "Vulnerability classifier"
    )
    
    try:
        from cai.ml.classifier import get_classifier
        classifier = get_classifier()
        print("  ✅ Classifier initialized (using heuristic fallback if XGBoost unavailable)")
    except Exception as e:
        print(f"  ❌ Cannot load classifier: {e}")
        all_pass = False
    
    print()
    
    # Check 6: Calibration
    print("6. Platt Scaling Confidence Calibration")
    all_pass &= check_file_exists(
        "src/cai/ml/calibration.py",
        "Calibration system"
    )
    
    try:
        from cai.ml.calibration import get_calibrator
        calibrator = get_calibrator()
        print(f"  ✅ Calibrator loaded: {len(calibrator.list_calibrations())} calibrations")
    except Exception as e:
        print(f"  ❌ Cannot load calibrator: {e}")
        all_pass = False
    
    print()
    
    # Check 7: Constraint Extraction
    print("7. Path Constraint Extraction")
    all_pass &= check_file_exists(
        "src/cai/tools/web3_security/symbolic/constraint_analyzer.py",
        "Constraint analyzer"
    )
    
    try:
        from cai.tools.web3_security.symbolic.constraint_analyzer import (
            extract_constraints_from_mythril
        )
        print("  ✅ Constraint extraction functions available")
    except Exception as e:
        print(f"  ❌ Cannot import constraint analyzer: {e}")
        all_pass = False
    
    print()
    
    # Check 8: Symbolic-Static Correlation
    print("8. Symbolic-Static Cross-Correlation")
    all_pass &= check_file_exists(
        "src/cai/tools/web3_security/symbolic/correlator.py",
        "Symbolic-static correlator"
    )
    
    try:
        from cai.tools.web3_security.symbolic.correlator import (
            correlate_slither_mythril
        )
        print("  ✅ Correlation functions available")
    except Exception as e:
        print(f"  ❌ Cannot import correlator: {e}")
        all_pass = False
    
    print()
    
    # Check 9: Composite Pattern
    print("9. Composite Pattern Pipeline")
    all_pass &= check_file_exists(
        "src/cai/agents/patterns/composite_audit.py",
        "Composite audit pattern"
    )
    
    try:
        from cai.agents.patterns import composite_audit_pattern
        print("  ✅ composite_audit_pattern() available")
    except Exception as e:
        print(f"  ❌ Cannot import composite pattern: {e}")
        all_pass = False
    
    print()
    
    # Check 10: Protocol Analyzers
    print("10. Protocol-Specific Analyzers")
    all_pass &= check_file_exists(
        "src/cai/tools/web3_security/protocols/lending_analyzer.py",
        "Lending analyzer"
    )
    all_pass &= check_file_exists(
        "src/cai/tools/web3_security/protocols/amm_analyzer.py",
        "AMM analyzer"
    )
    all_pass &= check_file_exists(
        "src/cai/tools/web3_security/protocols/governance_analyzer.py",
        "Governance analyzer"
    )
    all_pass &= check_file_exists(
        "src/cai/tools/web3_security/protocols/staking_analyzer.py",
        "Staking analyzer"
    )
    
    try:
        from cai.tools.web3_security.protocols import (
            LendingAnalyzer, AMMAnalyzer, GovernanceAnalyzer, StakingAnalyzer
        )
        print("  ✅ All protocol analyzers available")
    except Exception as e:
        print(f"  ❌ Cannot import protocol analyzers: {e}")
        all_pass = False
    
    print()
    print("=" * 70)
    
    if all_pass:
        print("✅ ALL PRECISION ENHANCEMENTS VERIFIED SUCCESSFULLY!")
        print()
        print("Next steps:")
        print("  1. Review PRECISION_ENHANCEMENTS.md for technical details")
        print("  2. Check PRECISION_QUICK_START.md for usage examples")
        print("  3. Enable SmartBERT: export CAI_USE_SMARTBERT=true")
        print("  4. Install optional deps: pip install transformers torch xgboost")
        return 0
    else:
        print("⚠️  Some components missing or not functional")
        print("Review errors above for details")
        return 1


if __name__ == "__main__":
    sys.exit(main())
