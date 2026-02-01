"""
IRIS-Style Neuro-Symbolic Integration for Slither.

From the IRIS paper: "IRIS: LLM-ASSISTED STATIC ANALYSIS FOR DETECTING 
SECURITY VULNERABILITIES"

IRIS combines LLMs with static analysis (CodeQL in the paper, Slither here)
for better vulnerability detection:

1. LLM infers taint specifications (sources, sinks, propagators)
2. Static analysis runs with LLM-inferred specs
3. LLM performs contextual analysis to filter false positives

Results from paper:
- GPT-4 + IRIS detected 55/120 vulnerabilities (vs 27 for CodeQL alone)
- 103.7% improvement in detection
- 5% lower false discovery rate

This module adapts IRIS methodology for Solidity smart contracts using Slither.
"""

import os
import json
import re
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from enum import Enum

from cai.sdk.agents import function_tool


class TaintType(Enum):
    """Types of taint specifications."""
    SOURCE = "source"        # Where untrusted data enters
    SINK = "sink"            # Where data causes harm if tainted
    PROPAGATOR = "propagator"  # Functions that pass taint through


@dataclass
class TaintSpec:
    """A taint specification for a function or variable."""
    
    name: str
    taint_type: TaintType
    contract: Optional[str] = None
    confidence: float = 0.8
    reasoning: str = ""
    
    # For sources
    source_type: Optional[str] = None  # "external_call", "user_input", "storage"
    
    # For sinks  
    sink_type: Optional[str] = None  # "ether_transfer", "state_change", "external_call"
    
    # For propagators
    propagates_from: List[str] = field(default_factory=list)
    propagates_to: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.taint_type.value,
            "contract": self.contract,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "source_type": self.source_type,
            "sink_type": self.sink_type,
            "propagates_from": self.propagates_from,
            "propagates_to": self.propagates_to
        }


@dataclass
class TaintPath:
    """A path from a source to a sink through propagators."""
    
    source: TaintSpec
    sink: TaintSpec
    propagators: List[TaintSpec] = field(default_factory=list)
    
    # Analysis metadata
    file_path: Optional[str] = None
    source_line: Optional[int] = None
    sink_line: Optional[int] = None
    
    # Contextual analysis result
    is_true_positive: Optional[bool] = None
    contextual_reasoning: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source.to_dict(),
            "sink": self.sink.to_dict(),
            "propagators": [p.to_dict() for p in self.propagators],
            "file_path": self.file_path,
            "source_line": self.source_line,
            "sink_line": self.sink_line,
            "is_true_positive": self.is_true_positive,
            "contextual_reasoning": self.contextual_reasoning
        }


@dataclass
class IRISAnalysisResult:
    """Complete IRIS analysis result."""
    
    target: str
    
    # Inferred specs
    inferred_sources: List[TaintSpec] = field(default_factory=list)
    inferred_sinks: List[TaintSpec] = field(default_factory=list)
    inferred_propagators: List[TaintSpec] = field(default_factory=list)
    
    # Detected paths
    taint_paths: List[TaintPath] = field(default_factory=list)
    
    # Filtered results
    true_positives: List[TaintPath] = field(default_factory=list)
    false_positives: List[TaintPath] = field(default_factory=list)
    uncertain: List[TaintPath] = field(default_factory=list)
    
    # Statistics
    slither_findings: int = 0
    llm_filtered_findings: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "specs": {
                "sources": [s.to_dict() for s in self.inferred_sources],
                "sinks": [s.to_dict() for s in self.inferred_sinks],
                "propagators": [p.to_dict() for p in self.inferred_propagators]
            },
            "paths": [p.to_dict() for p in self.taint_paths],
            "results": {
                "true_positives": [p.to_dict() for p in self.true_positives],
                "false_positives": [p.to_dict() for p in self.false_positives],
                "uncertain": [p.to_dict() for p in self.uncertain]
            },
            "stats": {
                "slither_findings": self.slither_findings,
                "llm_filtered_findings": self.llm_filtered_findings,
                "improvement": (
                    f"{(self.llm_filtered_findings / max(self.slither_findings, 1) - 1) * 100:.1f}%"
                    if self.slither_findings else "N/A"
                )
            }
        }


# Common Solidity taint sources
SOLIDITY_SOURCES = [
    ("msg.sender", "user_input", "Address of transaction sender, can be any address"),
    ("msg.value", "user_input", "Ether sent with transaction, user-controlled"),
    ("msg.data", "user_input", "Full calldata, user-controlled"),
    ("tx.origin", "user_input", "Original transaction sender, can be manipulated via phishing"),
    ("block.timestamp", "external", "Block timestamp, can be slightly manipulated by miners"),
    ("block.number", "external", "Block number, predictable"),
    ("blockhash", "external", "Block hash, only available for recent blocks"),
    ("calldata", "user_input", "Function arguments from external calls"),
]

# Common Solidity taint sinks
SOLIDITY_SINKS = [
    ("transfer", "ether_transfer", "Transfers ETH to an address"),
    ("send", "ether_transfer", "Sends ETH, returns bool"),
    ("call", "external_call", "Low-level call, can transfer ETH and execute code"),
    ("delegatecall", "external_call", "Executes code in context of caller"),
    ("selfdestruct", "destruction", "Destroys contract and sends balance"),
    ("SSTORE", "state_change", "Writes to storage, may affect critical state"),
]


@function_tool
def iris_infer_taint_specs(
    contract_code: str,
    contract_name: str = "Unknown",
    focus_on: str = "all"
) -> str:
    """
    Use LLM to infer taint specifications for a contract.
    
    This is Phase 1 of IRIS: LLM analyzes code to identify:
    - Sources: Where untrusted data enters
    - Sinks: Where tainted data causes harm
    - Propagators: How taint flows through the code
    
    Args:
        contract_code: Solidity source code to analyze
        contract_name: Name of the contract
        focus_on: What to focus on: "sources", "sinks", "propagators", or "all"
        
    Returns:
        Prompt for LLM to infer taint specifications
    """
    # Add known Solidity sources/sinks as context
    known_sources = "\n".join([f"- `{s[0]}` ({s[1]}): {s[2]}" for s in SOLIDITY_SOURCES])
    known_sinks = "\n".join([f"- `{s[0]}` ({s[1]}): {s[2]}" for s in SOLIDITY_SINKS])
    
    return f"""## IRIS Taint Specification Inference

Analyze this Solidity contract to identify taint specifications.

### Contract: {contract_name}

```solidity
{contract_code[:3000]}{'...(truncated)' if len(contract_code) > 3000 else ''}
```

### Known Solidity Sources (built-in)
{known_sources}

### Known Solidity Sinks (built-in)
{known_sinks}

### Your Task

Identify **contract-specific** taint specifications:

#### 1. SOURCES (where untrusted data enters)
Look for:
- External function parameters
- Return values from external calls
- Oracle data / price feeds
- User-provided addresses
- Data from other contracts

#### 2. SINKS (where tainted data causes harm)
Look for:
- ETH transfers to user-controlled addresses
- State changes based on external input
- Authorization decisions
- Price calculations
- Token transfers

#### 3. PROPAGATORS (how taint flows)
Look for:
- Functions that take tainted input and return derived values
- State variables that store and later use tainted data
- Mappings indexed by tainted keys

### Output Format

For each specification, provide:
```json
{{
  "name": "function or variable name",
  "type": "source|sink|propagator",
  "contract": "{contract_name}",
  "confidence": 0.0-1.0,
  "reasoning": "why this is a source/sink/propagator",
  "source_type": "if source: user_input|external_call|oracle|storage",
  "sink_type": "if sink: ether_transfer|state_change|external_call|auth_decision"
}}
```

Focus on: {focus_on}
"""


@function_tool
def iris_contextual_filter(
    finding_description: str,
    source_code: str,
    source_line: int,
    sink_code: str,
    sink_line: int,
    context_lines: int = 5
) -> str:
    """
    Use LLM to perform contextual analysis on a finding.
    
    This is Phase 3 of IRIS: After Slither finds a potential issue,
    LLM analyzes the surrounding context to determine if it's a true positive.
    
    Args:
        finding_description: Description of the vulnerability
        source_code: Code around the source (taint origin)
        source_line: Line number of the source
        sink_code: Code around the sink (vulnerable operation)
        sink_line: Line number of the sink
        context_lines: Number of context lines to show
        
    Returns:
        Prompt for LLM contextual analysis
    """
    return f"""## IRIS Contextual Analysis

Determine if this potential vulnerability is a TRUE POSITIVE or FALSE POSITIVE.

### Finding
{finding_description}

### Source Context (line {source_line})
```solidity
{source_code}
```

### Sink Context (line {sink_line})
```solidity
{sink_code}
```

### Analysis Questions

1. **Is the taint actually dangerous?**
   - Could the tainted data cause harm at the sink?
   - Is there any sanitization between source and sink?
   
2. **Are there existing protections?**
   - Access control modifiers (onlyOwner, etc.)?
   - Input validation / require statements?
   - Reentrancy guards?
   
3. **Is the attack path realistic?**
   - Can an attacker control the source?
   - Can they reach the sink with tainted data?
   - Are there economic barriers?

4. **Context-specific considerations?**
   - What is the business logic here?
   - Does the finding make sense in context?

### Your Verdict

Respond with:
- **VERDICT**: TRUE_POSITIVE | FALSE_POSITIVE | UNCERTAIN
- **CONFIDENCE**: 0.0 - 1.0
- **REASONING**: Explain your decision

If FALSE_POSITIVE, explain what protection prevents exploitation.
If TRUE_POSITIVE, explain the attack path.
If UNCERTAIN, explain what additional information is needed.
"""


@function_tool
def iris_enhanced_slither_analysis(
    target: str,
    inferred_specs: str = "",
    focus_detectors: str = ""
) -> str:
    """
    Run Slither with IRIS-style enhancements.
    
    This is Phase 2 of IRIS: Run static analysis with LLM-inferred specs
    to find taint paths.
    
    Args:
        target: Path to the contract to analyze
        inferred_specs: JSON string of LLM-inferred taint specs
        focus_detectors: Specific Slither detectors to focus on
        
    Returns:
        Instructions for running enhanced Slither analysis
    """
    if not target:
        return "ERROR: target path is required"
    
    # Parse inferred specs if provided
    specs_info = ""
    if inferred_specs:
        try:
            specs = json.loads(inferred_specs)
            sources = [s for s in specs if s.get("type") == "source"]
            sinks = [s for s in specs if s.get("type") == "sink"]
            specs_info = f"""
### LLM-Inferred Specifications

**Sources ({len(sources)}):**
{chr(10).join([f"- {s['name']}: {s.get('reasoning', '')[:50]}..." for s in sources[:5]])}

**Sinks ({len(sinks)}):**
{chr(10).join([f"- {s['name']}: {s.get('reasoning', '')[:50]}..." for s in sinks[:5]])}
"""
        except json.JSONDecodeError:
            specs_info = "\n(Could not parse inferred specs)\n"
    
    # Suggest relevant detectors based on inferred specs
    suggested_detectors = [
        "arbitrary-send-eth",
        "arbitrary-send-erc20",
        "unchecked-transfer", 
        "reentrancy-eth",
        "reentrancy-no-eth",
        "controlled-delegatecall",
        "external-function",
        "uninitialized-state",
    ]
    
    if focus_detectors:
        suggested_detectors = focus_detectors.split(",")
    
    return f"""## IRIS-Enhanced Slither Analysis

### Target
{target}

{specs_info}

### Recommended Slither Command

Run Slither with these taint-focused detectors:

```bash
slither {target} --detect {','.join(suggested_detectors)} --json iris_results.json
```

### Post-Processing

After Slither completes:

1. For each finding, extract:
   - Source location (where tainted data enters)
   - Sink location (where it's used dangerously)
   - Data flow path

2. Use `iris_contextual_filter` on each finding to classify as:
   - TRUE_POSITIVE: Real vulnerability
   - FALSE_POSITIVE: Protected or not exploitable
   - UNCERTAIN: Needs manual review

3. Only report TRUE_POSITIVE findings

### Expected Improvement

Based on IRIS paper results:
- ~100% improvement in true positive detection
- ~5% reduction in false discovery rate

This is achieved by combining Slither's precision with LLM's contextual understanding.
"""


@function_tool
def iris_generate_custom_detector(
    vulnerability_type: str,
    source_pattern: str,
    sink_pattern: str,
    description: str
) -> str:
    """
    Generate a custom Slither detector for a specific vulnerability pattern.
    
    Based on IRIS methodology of using LLM to generate analysis specifications.
    
    Args:
        vulnerability_type: Type of vulnerability (e.g., "oracle_manipulation")
        source_pattern: Pattern for identifying sources
        sink_pattern: Pattern for identifying sinks
        description: Description of the vulnerability
        
    Returns:
        Python code for a custom Slither detector
    """
    # Generate safe identifier from vulnerability type
    safe_name = re.sub(r'[^a-z0-9]', '_', vulnerability_type.lower())
    class_name = ''.join(word.title() for word in safe_name.split('_'))
    
    return f'''"""
Custom Slither Detector: {vulnerability_type}

Generated by IRIS-style LLM inference.

Description: {description}
Source Pattern: {source_pattern}
Sink Pattern: {sink_pattern}
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.core.declarations import Function

class {class_name}Detector(AbstractDetector):
    """
    Detector for {vulnerability_type}.
    
    {description}
    """
    
    ARGUMENT = "{safe_name}"
    HELP = "{description}"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    
    WIKI = "https://github.com/aegis/wiki/{safe_name}"
    WIKI_TITLE = "{vulnerability_type}"
    WIKI_DESCRIPTION = """{description}"""
    WIKI_EXPLOIT_SCENARIO = """
    1. Attacker identifies source: {source_pattern}
    2. Attacker crafts input to reach sink: {sink_pattern}
    3. Exploitation occurs
    """
    WIKI_RECOMMENDATION = "Add validation between source and sink"
    
    def _detect(self):
        results = []
        
        for contract in self.compilation_unit.contracts:
            for function in contract.functions:
                # Check for source pattern
                has_source = self._check_source_pattern(function)
                
                # Check for sink pattern
                has_sink = self._check_sink_pattern(function)
                
                if has_source and has_sink:
                    info = [
                        f"{{function.canonical_name}} contains potential {vulnerability_type}\\n",
                        f"\\tSource: {source_pattern}\\n",
                        f"\\tSink: {sink_pattern}\\n"
                    ]
                    results.append(self.generate_result(info))
        
        return results
    
    def _check_source_pattern(self, function: Function) -> bool:
        """Check if function contains source pattern."""
        # Pattern: {source_pattern}
        source_keywords = {source_pattern.lower().split()}
        
        for node in function.nodes:
            node_str = str(node).lower()
            if any(kw in node_str for kw in source_keywords):
                return True
        
        return False
    
    def _check_sink_pattern(self, function: Function) -> bool:
        """Check if function contains sink pattern."""
        # Pattern: {sink_pattern}
        sink_keywords = {sink_pattern.lower().split()}
        
        for node in function.nodes:
            node_str = str(node).lower()
            if any(kw in node_str for kw in sink_keywords):
                return True
        
        return False


# Register the detector
if __name__ == "__main__":
    print(f"Custom detector for {vulnerability_type} generated.")
'''


@function_tool
def iris_batch_contextual_filter(
    findings_json: str,
    contract_code: str
) -> str:
    """
    Batch contextual filtering for multiple findings.
    
    Args:
        findings_json: JSON array of Slither findings
        contract_code: Full contract source code
        
    Returns:
        Structured prompt for batch contextual analysis
    """
    try:
        findings = json.loads(findings_json)
    except json.JSONDecodeError:
        return "ERROR: Could not parse findings JSON"
    
    if not findings:
        return "No findings to filter."
    
    output = f"""## IRIS Batch Contextual Analysis

Analyze {len(findings)} findings for true/false positive classification.

### Contract Code
```solidity
{contract_code[:5000]}{'...(truncated)' if len(contract_code) > 5000 else ''}
```

### Findings to Analyze

"""
    
    for i, finding in enumerate(findings, 1):
        output += f"""
#### Finding {i}: {finding.get('check', 'Unknown')}
- **Description**: {finding.get('description', 'N/A')[:200]}
- **Severity**: {finding.get('impact', 'Unknown')}
- **Location**: {finding.get('elements', [{}])[0].get('source_mapping', {}).get('filename_relative', 'Unknown')}

**Verdict**: [TRUE_POSITIVE / FALSE_POSITIVE / UNCERTAIN]
**Confidence**: [0.0-1.0]
**Reasoning**: [Your analysis]

---
"""
    
    output += """
### Output Format

Return a JSON array with your verdicts:
```json
[
  {
    "finding_index": 1,
    "verdict": "TRUE_POSITIVE|FALSE_POSITIVE|UNCERTAIN",
    "confidence": 0.0-1.0,
    "reasoning": "explanation"
  }
]
```
"""
    
    return output


__all__ = [
    'TaintType',
    'TaintSpec',
    'TaintPath',
    'IRISAnalysisResult',
    'SOLIDITY_SOURCES',
    'SOLIDITY_SINKS',
    'iris_infer_taint_specs',
    'iris_contextual_filter',
    'iris_enhanced_slither_analysis',
    'iris_generate_custom_detector',
    'iris_batch_contextual_filter',
]
