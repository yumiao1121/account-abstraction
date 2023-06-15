// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "./UserOperation.sol";

interface IAccount {

    /**
     * Validate user's signature and nonce
     * the entryPoint will make the call to the recipient only if this validation call returns successfully.
     * signature failure should be reported by returning SIG_VALIDATION_FAILED (1).
     * This allows making a "simulation call" without a valid signature
     * Other failures (e.g. nonce mismatch, or invalid signature format) should still revert to signal failure.
     *
     * @dev Must validate caller is the entryPoint.
     *      Must validate the signature and nonce
     * @param userOp the operation that is about to be executed.
     * @param userOpHash hash of the user's request data. can be used as the basis for signature.
     * @param missingAccountFunds missing funds on the account's deposit in the entrypoint.
     *      This is the minimum amount to transfer to the sender(entryPoint) to be able to make the call.
     *      The excess is left as a deposit in the entrypoint, for future calls.
     *      can be withdrawn anytime using "entryPoint.withdrawTo()"
     *      In case there is a paymaster in the request (or the current deposit is high enough), this value will be zero.
     * @return validationData packaged ValidationData structure. use `_packValidationData` and `_unpackValidationData` to encode and decode
     *      <20-byte> sigAuthorizer - 0 for valid signature, 1 to mark signature failure,
     *         otherwise, an address of an "authorizer" contract.
     *      <6-byte> validUntil - last timestamp this operation is valid. 0 for "indefinite"
     *      <6-byte> validAfter - first timestamp this operation is valid
     *      If an account doesn't use time-range, it is enough to return SIG_VALIDATION_FAILED value (1) for signature failure.
     *      Note that the validation code cannot use block.timestamp (or block.number) directly.
     */
     /*
        daewoo:
        这段代码是用于验证用户签名和令牌的。
        如果签名失败，则应该返回 SIG_VALIDATION_FAILED(1) 信号。这允许在没有有效签名的情况下进行“模拟调用”。其他失败情况 (例如nonce不匹配或无效的签名格式) 仍然会发出失败信号。

        @dev 注释指出必须验证调用者是 entryPoint。必须验证签名和nonce。
        返回的 validationData 结构已被打包。使用_packValidationData和_unpackValidationData函数进行编码和解码。@param sigAuthorizer 参数是有效的签名标识符，为 0。
        如果签名失败，则为 1。否则，它是“authorizer”合同的地址。
        @param validUntil 参数是此操作有效的最后时间戳。0 表示“无限期”。
        @param validAfter 参数是此操作有效的最早时间戳。如果账户不使用时间范围，则 SIG_VALIDATION_FAILED 值 (1) 就足够了。
        注意，验证代码不能直接使用 block.timestamp(或 block.number)。
     */
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
    external returns (uint256 validationData);
}
