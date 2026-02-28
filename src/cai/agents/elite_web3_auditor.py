"""
Elite Web3 Auditor Agent
Highly precise, multi-stage autonomous bug bounty hunter.
"""

import os
from typing import List, Dict, Any, Optional
from cai.sdk.agents import Agent, OpenAIChatCompletionsModel
from openai import AsyncOpenAI

from cai.agents.patterns.composite_audit import composite_audit_pattern
from cai.agents.skeptic_alpha import skeptic_alpha
from cai.agents.skeptic_beta import skeptic_beta
from cai.agents.skeptic_gamma import skeptic_gamma
from cai.agents.bug_bounter import bug_bounter
from cai.agents.mev_analyzer import mev_analyzer

def create_elite_web3_auditor(name: str = "Elite Web3 Auditor") -> Agent:
    """
    Creates an Elite Web3 Auditor agent using the Composite Audit Pattern.
    
    This agent orchestrates:
    1. Discovery via specialized domain agents (Vulnerability, Economic, Access Control).
    2. Adversarial validation via Skeptic agents (Alpha, Beta, Gamma).
    3. Ensemble consensus for final high-precision findings.
    """
    
    # 1. Define Domain Workers (Stage 1)
    vuln_worker = bug_bounter
    economic_worker = mev_analyzer
    # We can add more specialized workers here
    
    # 2. Define Auditors and Critics (Stage 2)
    # Skeptics act as critics in the adversarial stage
    auditors = [vuln_worker, economic_worker]
    critics = [skeptic_alpha, skeptic_beta, skeptic_gamma]
    
    # 3. Define Ensemble Agents (Stage 3)
    ensemble_agents = [skeptic_alpha, skeptic_beta, skeptic_gamma]
    
    # 4. Create the Composite Pattern
    pattern = composite_audit_pattern(
        name="elite_audit_pipeline",
        hmaw_agents={
            "vulnerability": [vuln_worker],
            "economic": [economic_worker],
            "access_control": [skeptic_gamma] # Gamma is good at access control
        },
        auditors=auditors,
        ensemble_agents=ensemble_agents,
        description="Elite multi-stage Web3 audit pipeline"
    )
    
    # 5. Define the Agent that uses this pattern
    api_key = os.getenv("OPENAI_API_KEY") or "sk-placeholder"
    
    elite_agent = Agent(
        name=name,
        instructions=f"""You are an Elite Web3 Bug Bounty Hunter.
        Your goal is to find real, permissionless, exploitable bugs with deadly precision.
        
        You use a multi-stage process:
        1. Parallel Domain Analysis: Specialized agents look at vulnerability, economics, and access control.
        2. Adversarial Validation: Skeptics Alpha, Beta, and Gamma challenge every finding.
        3. Ensemble Consensus: Only findings that pass multiple independent checks are reported.
        
        Focus on findings that lead to user fund loss or protocol insolvency.
        Filter out all false positives and low-impact issues.
        """,
        model=OpenAIChatCompletionsModel(
            model=os.getenv("CAI_MODEL", "alias1"),
            openai_client=AsyncOpenAI(api_key=api_key)
        )
    )
    
    # Attach the pattern to the agent (conceptual, depends on how patterns are used in the SDK)
    # In CAI, patterns can be executed directly or wrapped in an agent's logic.
    
    return elite_agent

# For backward compatibility and factory discovery
elite_web3_auditor = create_elite_web3_auditor()
