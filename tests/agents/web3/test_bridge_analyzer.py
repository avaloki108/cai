"""
Unit tests for Bridge Analyzer Agent

Tests the cross-chain bridge security analysis capabilities including
replay protection, signature verification, message validation, and
validator security analysis.
"""

import pytest
import json
from unittest.mock import patch, MagicMock


class TestBridgeAnalyzer:
    """Test suite for Bridge Analyzer agent tools."""
    
    @pytest.fixture
    def sample_vulnerable_bridge_code(self):
        """Sample vulnerable bridge contract code."""
        return '''
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.0;
        
        contract VulnerableBridge {
            mapping(address => uint256) public balances;
            address public owner;
            
            function receiveMessage(
                address token,
                address recipient,
                uint256 amount,
                bytes memory signature
            ) external {
                // Missing nonce tracking - replay vulnerable
                // Missing chain ID - cross-chain replay vulnerable
                address signer = ecrecover(
                    keccak256(abi.encodePacked(token, recipient, amount)),
                    27, bytes32(0), bytes32(0)
                );
                // Missing zero address check
                balances[recipient] += amount;
            }
            
            function setValidator(address newValidator) external {
                // No timelock on validator change
                owner = newValidator;
            }
        }
        '''
    
    @pytest.fixture
    def sample_secure_bridge_code(self):
        """Sample secure bridge contract code."""
        return '''
        // SPDX-License-Identifier: MIT
        pragma solidity ^0.8.0;
        
        import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
        import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
        
        contract SecureBridge is ReentrancyGuard {
            using ECDSA for bytes32;
            
            mapping(bytes32 => bool) public executedMessages;
            mapping(address => bool) public validators;
            uint256 public threshold = 5;
            uint256 public chainId;
            
            constructor() {
                chainId = block.chainid;
            }
            
            function receiveMessage(
                uint256 sourceChain,
                address trustedSender,
                address token,
                address recipient,
                uint256 amount,
                uint256 nonce,
                bytes[] memory signatures
            ) external nonReentrant {
                require(sourceChain != chainId, "Same chain");
                require(trustedSender == address(this), "Invalid sender");
                require(amount > 0, "Zero amount");
                
                bytes32 messageHash = keccak256(abi.encodePacked(
                    sourceChain,
                    chainId,
                    trustedSender,
                    token,
                    recipient,
                    amount,
                    nonce
                ));
                
                require(!executedMessages[messageHash], "Already executed");
                executedMessages[messageHash] = true;
                
                // Verify signatures
                uint256 validSignatures = 0;
                for (uint i = 0; i < signatures.length; i++) {
                    address signer = messageHash.toEthSignedMessageHash().recover(signatures[i]);
                    require(signer != address(0), "Invalid signature");
                    if (validators[signer]) {
                        validSignatures++;
                    }
                }
                require(validSignatures >= threshold, "Insufficient signatures");
                
                // Transfer tokens
                // ...
            }
        }
        '''
    
    def test_analyze_replay_protection_vulnerable(self, sample_vulnerable_bridge_code):
        """Test replay protection analysis on vulnerable code."""
        from cai.agents.bridge_analyzer import analyze_replay_protection
        
        result_json = analyze_replay_protection(sample_vulnerable_bridge_code)
        result = json.loads(result_json)
        
        assert result["verdict"] == "VULNERABLE"
        assert result["has_nonce"] == False or result["has_nonce_tracking"] == False
        assert result["has_chain_id"] == False
        assert result["findings_count"] > 0
        assert any(f["severity"] == "CRITICAL" for f in result["findings"])
    
    def test_analyze_replay_protection_secure(self, sample_secure_bridge_code):
        """Test replay protection analysis on secure code."""
        from cai.agents.bridge_analyzer import analyze_replay_protection
        
        result_json = analyze_replay_protection(sample_secure_bridge_code)
        result = json.loads(result_json)
        
        assert result["has_nonce"] == True
        assert result["has_chain_id"] == True
        assert result["has_message_hash"] == True
    
    def test_analyze_signature_verification_vulnerable(self, sample_vulnerable_bridge_code):
        """Test signature verification analysis on vulnerable code."""
        from cai.agents.bridge_analyzer import analyze_signature_verification
        
        result_json = analyze_signature_verification(sample_vulnerable_bridge_code)
        result = json.loads(result_json)
        
        assert result["uses_ecrecover"] == True
        assert result["uses_ecdsa_library"] == False
        assert result["findings_count"] > 0
        assert any(f["issue"] == "RAW_ECRECOVER" for f in result["findings"])
    
    def test_analyze_signature_verification_secure(self, sample_secure_bridge_code):
        """Test signature verification analysis on secure code."""
        from cai.agents.bridge_analyzer import analyze_signature_verification
        
        result_json = analyze_signature_verification(sample_secure_bridge_code)
        result = json.loads(result_json)
        
        assert result["uses_ecdsa_library"] == True
        assert result["has_threshold"] == True
    
    def test_analyze_message_validation_vulnerable(self, sample_vulnerable_bridge_code):
        """Test message validation analysis on vulnerable code."""
        from cai.agents.bridge_analyzer import analyze_message_validation
        
        result_json = analyze_message_validation(sample_vulnerable_bridge_code)
        result = json.loads(result_json)
        
        assert result["findings_count"] > 0
        assert result["has_source_validation"] == False or result["has_sender_validation"] == False
    
    def test_analyze_message_validation_secure(self, sample_secure_bridge_code):
        """Test message validation analysis on secure code."""
        from cai.agents.bridge_analyzer import analyze_message_validation
        
        result_json = analyze_message_validation(sample_secure_bridge_code)
        result = json.loads(result_json)
        
        assert result["has_source_validation"] == True
        assert result["has_sender_validation"] == True
        assert result["has_amount_check"] == True
    
    def test_analyze_validator_security(self, sample_vulnerable_bridge_code):
        """Test validator security analysis."""
        from cai.agents.bridge_analyzer import analyze_validator_security
        
        result_json = analyze_validator_security(sample_vulnerable_bridge_code)
        result = json.loads(result_json)
        
        # Should find issues with lack of timelock
        assert "findings" in result
    
    def test_check_known_bridge_exploits(self, sample_vulnerable_bridge_code):
        """Test known exploit pattern matching."""
        from cai.agents.bridge_analyzer import check_known_bridge_exploits
        
        result_json = check_known_bridge_exploits(sample_vulnerable_bridge_code)
        result = json.loads(result_json)
        
        assert "exploit_patterns" in result
        assert "matches_found" in result
    
    def test_render_bridge_audit_report(self):
        """Test audit report generation."""
        from cai.agents.bridge_analyzer import render_bridge_audit_report
        
        replay_findings = [{"issue": "NO_NONCE", "severity": "CRITICAL", "description": "Test"}]
        signature_findings = []
        message_findings = []
        validator_findings = []
        exploit_matches = []
        
        report = render_bridge_audit_report(
            "TestBridge",
            replay_findings,
            signature_findings,
            message_findings,
            validator_findings,
            exploit_matches
        )
        
        assert "TestBridge" in report
        assert "CRITICAL" in report
        assert "NO_NONCE" in report


class TestBridgeAnalyzerAgent:
    """Test suite for Bridge Analyzer agent instantiation."""
    
    def test_agent_creation(self):
        """Test that the agent can be created."""
        from cai.agents.bridge_analyzer import bridge_analyzer
        
        assert bridge_analyzer is not None
        assert bridge_analyzer.name == "Bridge Analyzer"
        assert len(bridge_analyzer.tools) > 0
    
    def test_agent_has_required_tools(self):
        """Test that agent has all required tools."""
        from cai.agents.bridge_analyzer import bridge_analyzer
        
        tool_names = [t.name for t in bridge_analyzer.tools]
        
        required_tools = [
            "analyze_replay_protection",
            "analyze_signature_verification",
            "analyze_message_validation",
            "analyze_validator_security",
            "check_known_bridge_exploits",
            "render_bridge_audit_report",
        ]
        
        for tool in required_tools:
            assert tool in tool_names, f"Missing tool: {tool}"
    
    def test_agent_description(self):
        """Test agent description is informative."""
        from cai.agents.bridge_analyzer import bridge_analyzer
        
        assert "cross-chain" in bridge_analyzer.description.lower()
        assert "bridge" in bridge_analyzer.description.lower()
