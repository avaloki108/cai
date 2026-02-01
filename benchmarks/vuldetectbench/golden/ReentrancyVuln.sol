// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ReentrancyVuln {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "bal");
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send");
        balances[msg.sender] -= amount;
    }
}
