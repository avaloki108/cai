
import json
import os
from pathlib import Path
from cai.tools.web3_security.enhancements.repo_context import detect_web3_repo_context, _detect_roles

def test_repo_context():
    # Create a dummy repo structure
    repo_path = Path("./test_dummy_repo")
    repo_path.mkdir(exist_ok=True)
    
    # Add a contract with roles
    contract_content = """
    pragma solidity ^0.8.0;
    import "@openzeppelin/contracts/access/Ownable.sol";
    
    contract MyContract is Ownable {
        address public governance;
        
        modifier onlyGovernance() {
            require(msg.sender == governance, "Not gov");
            _;
        }
        
        function propose(address target) external onlyGovernance {
            // ...
        }
        
        function setRelayer(address _relayer) external onlyOwner {
            // ...
        }
    }
    """
    (repo_path / "MyContract.sol").write_text(contract_content)
    (repo_path / "foundry.toml").write_text("[profile.default]")
    
    # Test _detect_roles directly
    roles_result = _detect_roles([contract_content])
    print("Roles detected:", roles_result)
    
    assert "owner" in roles_result["roles"]
    assert "governance" in roles_result["roles"]
    assert "relayer" in roles_result["roles"]
    
    # Cleanup
    import shutil
    shutil.rmtree(repo_path)
    print("Test passed!")

if __name__ == "__main__":
    test_repo_context()
