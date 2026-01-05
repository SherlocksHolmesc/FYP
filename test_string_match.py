msg = "Could not decode contract function call to balanceOf(address) with return data: b'', output_types: ['uint256']"
print('Full message:', msg)
print()
print('Check 1:', "with return data: b''" in msg)
print('Check 2:', "return data: b''" in msg)
print('Check 3:', "b''" in msg)
