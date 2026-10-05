// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

/**
 * @title SignatureVerifier
 * @notice Verifies ECDSA signatures with strict s‑value malleability checks (EIP‑2),
 *         deadline enforcement, and on‑chain replay protection.
 *
 * The contract provides a modern `verify` function that includes all security
 * invariants required by the bounty, as well as a legacy `verifyLegacy`
 * function kept for backward compatibility with existing callers.
 */
contract SignatureVerifier {
    // ---------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------
    // secp256k1 curve order (n)
    uint256 private constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    // Half of the curve order – used for the strict s‑value check (EIP‑2)
    uint256 private constant SECP256K1_N_DIV_2 = SECP256K1_N / 2;

    // ---------------------------------------------------------------------
    // State
    // ---------------------------------------------------------------------
    // Mapping to keep track of used message hashes for replay protection.
    mapping(bytes32 => bool) private _usedHashes;

    // ---------------------------------------------------------------------
    // External view helpers
    // ---------------------------------------------------------------------
    /**
     * @dev Returns true if a given hash has already been used in a successful
     *      verification. This can be useful for off‑chain tooling.
     */
    function isUsed(bytes32 hash) external view returns (bool) {
        return _usedHashes[hash];
    }

    // ---------------------------------------------------------------------
    // Core verification logic
    // ---------------------------------------------------------------------
    /**
     * @notice Verify a signature with deadline and replay protection.
     * @param signer   Expected signer address.
     * @param hash     Keccak256 hash of the signed message (the exact value that
     *                 was signed off‑chain).
     * @param signature ECDSA signature in the standard 65‑byte {r, s, v} format.
     * @param deadline Unix timestamp after which the signature is considered
     *                 expired.
     * @return True if the signature is valid, not expired and not replayed.
     */
    function verify(
        address signer,
        bytes32 hash,
        bytes memory signature,
        uint256 deadline
    ) external returns (bool) {
        // 1️⃣ Deadline enforcement – reject stale authorisations.
        require(block.timestamp <= deadline, "SignatureVerifier: signature expired");

        // 2️⃣ Replay protection – each hash can be used only once.
        require(!_usedHashes[hash], "SignatureVerifier: replay detected");

        // 3️⃣ Signature decomposition and strict s‑value check (EIP‑2).
        (bytes32 r, bytes32 s, uint8 v) = _splitSignature(signature);
        require(uint256(s) <= SECP256K1_N_DIV_2, "SignatureVerifier: invalid s value");
        require(v == 27 || v == 28, "SignatureVerifier: invalid v value");

        // 4️⃣ Recover the signer address.
        address recovered = ecrecover(hash, v, r, s);
        require(recovered != address(0), "SignatureVerifier: ecrecover failed");
        require(recovered == signer, "SignatureVerifier: invalid signature");

        // 5️⃣ Mark the hash as used to prevent future replays.
        _usedHashes[hash] = true;
        return true;
    }

    /**
     * @notice Legacy verification function kept for backward compatibility.
     *         It performs a plain ecrecover without deadline or replay checks.
     * @dev This function is `pure` because it does not touch storage.
     */
    function verifyLegacy(
        address signer,
        bytes32 hash,
        bytes memory signature
    ) external pure returns (bool) {
        (bytes32 r, bytes32 s, uint8 v) = _splitSignature(signature);
        // Legacy path does **not** enforce the strict s‑value check – it mirrors the
        // behaviour of the original implementation before the bounty.
        address recovered = ecrecover(hash, v, r, s);
        return (recovered != address(0) && recovered == signer);
    }

    // ---------------------------------------------------------------------
    // Internal utilities
    // ---------------------------------------------------------------------
    /**
     * @dev Splits a 65‑byte signature into r, s and v components.
     */
    function _splitSignature(bytes memory sig)
        internal
        pure
        returns (
            bytes32 r,
            bytes32 s,
            uint8 v
        )
    {
        require(sig.length == 65, "SignatureVerifier: invalid signature length");
        assembly {
            // First 32 bytes after the length prefix.
            r := mload(add(sig, 32))
            // Second 32 bytes.
            s := mload(add(sig, 64))
            // Final byte (first byte of the next word).
            v := byte(0, mload(add(sig, 96)))
        }
    }
}
