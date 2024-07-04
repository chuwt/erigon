// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;
pragma experimental ABIEncoderV2;


contract BalanceChecker {

    function balance(address[] memory tokens) view public returns (bool[] memory) {
        bool[] memory results = new bool[](tokens.length);
        for (uint i=0;i<tokens.length;i++) {
            (bool success, ) = tokens[i].staticcall(abi.encodeWithSignature("balanceOf(address)", address(this)));
            results[i] = success;
        }
        return results;
    }

    function _decodeBalance(bytes memory data) public pure returns (uint256) {
        return abi.decode(data, (uint256));
    }

    function tokenBalance(address[] memory tokens, address[][] memory users) view public returns (uint256[][] memory) {
        uint256[][] memory userBalances = new uint256[][](tokens.length);
        for (uint256 i = 0; i < tokens.length; i++) {
            address[] memory tokenUsers = users[i];
            uint256[] memory balances = new uint256[](tokenUsers.length);
            for (uint256 j = 0; j < tokenUsers.length; j++) {
                (bool success, bytes memory data) = tokens[i].staticcall(abi.encodeWithSignature("balanceOf(address)", tokenUsers[j]));
                if (success) {
                    if (data.length == 0) {
                        balances[j] = 0;
                    } else {
                        try this._decodeBalance(data) returns (uint256 bal) {
                            balances[j] = bal;
                        } catch {
                            balances[j] = 0;
                        }
                    }
                } else {
                    balances[j] = 0;
                }
            }
            userBalances[i] = balances;
        }
        return userBalances;
    }

    function bytes32ToString(bytes32 _bytes32) internal pure returns (string memory) {
        uint8 i = 0;
        while(i < 32 && _bytes32[i] != 0) {
            i++;
        }
        bytes memory bytesArray = new bytes(i);
        for (uint8 j = 0; j < i; j++) {
            bytesArray[j] = _bytes32[j];
        }
        return string(bytesArray);
    }

    function tokenInfo(address[] memory tokens) view public returns (string[] memory names, string[] memory symbols, uint256[] memory decimals, bool[] memory hasDecimals, uint256[] memory totalSupplies, bool[] memory hasTotalSupply) {
        names = new string[](tokens.length);
        symbols = new string[](tokens.length);
        decimals = new uint256[](tokens.length);
        hasDecimals = new bool[](tokens.length);
        totalSupplies = new uint256[](tokens.length);
        hasTotalSupply = new bool[](tokens.length);

        bool success;
        bytes memory data;
        for (uint i = 0; i < tokens.length; i++) {
            address token = tokens[i];

            (success, data) = token.staticcall(abi.encodeWithSignature("name()"));
            if (success) {
                if (data.length == 32) {
                    bytes32 nameBytes32;
                    assembly {
                        nameBytes32 := mload(add(data, 32))
                    }
                    names[i] = bytes32ToString(nameBytes32);
                } else if (data.length > 32) {
                    names[i] = abi.decode(data, (string));
                } else {
                    names[i] = "";
                }
            } else {
                names[i] = "certik-false";
            }
            (success, data) = token.staticcall(abi.encodeWithSignature("symbol()"));
            if (success) {
                if (data.length == 32) {
                    bytes32 symbolBytes32;
                    assembly {
                        symbolBytes32 := mload(add(data, 32))
                    }
                    symbols[i] = bytes32ToString(symbolBytes32);
                } else if (data.length > 32) {
                    symbols[i] = abi.decode(data, (string));
                } else {
                    symbols[i] = "";
                }
            } else {
                symbols[i] = "certik-false";
            }

            (success, data) = token.staticcall(abi.encodeWithSignature("decimals()"));
            if (success) {
                hasDecimals[i] = true;
                if (data.length == 0) {
                    decimals[i] = 0;
                } else {
                    decimals[i] = abi.decode(data, (uint256));
                }
            } else {
                hasDecimals[i] = false;
                decimals[i] = 0;
            }
            (success, data) = token.staticcall(abi.encodeWithSignature("totalSupply()"));
            if (success) {
                hasTotalSupply[i] = true;
                if (data.length == 0) {
                    totalSupplies[i] = 0;
                } else {
                    totalSupplies[i] = abi.decode(data, (uint256));
                }
            } else {
                hasTotalSupply[i] = false;
                totalSupplies[i] = 0;
            }
        }
        return (names, symbols, decimals, hasDecimals, totalSupplies, hasTotalSupply);
    }
}
