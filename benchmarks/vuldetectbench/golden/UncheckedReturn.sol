// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract UncheckedReturn {
    IERC20 public token;

    constructor(address token_) {
        token = IERC20(token_);
    }

    function pay(address to, uint256 amount) external {
        token.transfer(to, amount);
    }
}
