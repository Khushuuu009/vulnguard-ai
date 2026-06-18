// test-api.js
import fetch from 'node-fetch';

const code = `
pragma solidity ^0.8.0;
contract Test {
    function foo() public {
        tx.origin;
    }
}
`;

async function testScan() {
  try {
    const response = await fetch('http://localhost:3001/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code })
    });
    
    const data = await response.json();
    console.log('✅ Scan Result:');
    console.log(JSON.stringify(data, null, 2));
  } catch (error) {
    console.error('❌ Error:', error.message);
  }
}

testScan();