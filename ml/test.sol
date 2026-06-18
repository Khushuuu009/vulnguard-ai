// test.sol - Vulnerable contract
pragma solidity ^0.8.0;

contract Test {
    address public owner;
    
    function withdraw() public {
        // Re-entrancy vulnerability
        msg.sender.call{value: 1}("");
    }
    
    function bad() public {
        // tx.origin vulnerability
        require(tx.origin == owner);
    }
    
    function noVisibility() {
        // No visibility specifier
    }
    
    function timeBased() public {
        // Timestamp dependence
        require(block.timestamp > 1000);
    }
}