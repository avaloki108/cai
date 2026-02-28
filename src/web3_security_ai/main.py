"""
Web3 Security Audit System — compatibility adapter.

Delegates to the CAI-native EliteWeb3Pipeline for all audit workflows.
Legacy agent initialization is preserved for backward compatibility but
is not used in the primary audit path.
"""

import asyncio
import json
import logging
import warnings
from datetime import datetime
from typing import Any, Dict, List

from cai.web3.pipeline import EliteWeb3Pipeline


class Web3SecurityAuditSystem:
    """Thin adapter around the CAI-native EliteWeb3Pipeline."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.pipeline = EliteWeb3Pipeline()
        self.initialized = False

    async def initialize(self):
        self.initialized = True
        self.logger.info("Web3SecurityAuditSystem initialized (adapter mode)")

    async def run_audit_workflow(
        self,
        contract_source: str,
        contract_address: str = "0x0",
    ) -> Dict[str, Any]:
        if not self.initialized:
            await self.initialize()

        self.logger.info(f"Starting audit for contract: {contract_address}")
        start_time = datetime.now()

        report = await self.pipeline.run(contract_source)

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        report["contract_address"] = contract_address
        report["timestamp"] = start_time.isoformat()
        report["duration_seconds"] = duration
        report["final_score"] = float(
            report["summary"]["critical_findings_count"]
        )
        return report

    async def run_parallel_audits(
        self, contracts: List[Dict[str, str]]
    ) -> List[Dict[str, Any]]:
        if not self.initialized:
            await self.initialize()

        self.logger.info(f"Running parallel audits for {len(contracts)} contracts")
        tasks = [
            self.run_audit_workflow(
                c["source"], c.get("address", "0x0")
            )
            for c in contracts
        ]
        return list(await asyncio.gather(*tasks))

    async def cleanup(self):
        self.logger.info("Web3SecurityAuditSystem cleaned up")

    def get_system_status(self) -> Dict[str, Any]:
        return {"initialized": self.initialized, "mode": "cai_adapter"}


async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    system = Web3SecurityAuditSystem()

    try:
        await system.initialize()

        sample_contract = """pragma solidity ^0.8.0;

contract SampleVulnerableContract {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0;
    }
}"""

        result = await system.run_audit_workflow(
            contract_source=sample_contract,
            contract_address="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        )

        print(f"\nAudit Results: {result.get('contract_address')}")
        print(f"Duration: {result.get('duration_seconds', 0):.2f}s")
        print(f"Critical Findings: {result['summary']['critical_findings_count']}")

        await system.cleanup()
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
