// SPDX-License-Identifier: MIT

pragma solidity 0.8.9;

import "./VRF.sol";

/**
 * @title Test Helper for the VRF contract
 * @dev The aim of this contract is twofold:
 * 1. Raise the visibility modifier of VRF contract functions for testing purposes
 * 2. Removal of the `pure` modifier to allow gas consumption analysis.
 */
contract VRFVerifier {
    event VRFStatus(bool success);

    function hashToTryAndIncrement(uint256[2] memory _publicKey, bytes memory _message) public returns (uint, uint) {
        return VRF.hashToTryAndIncrement(_publicKey, _message);
    }

    function gammaToHash(uint256 gammaX, uint256 gammaY) public returns (bytes32) {
        return VRF.gammaToHash(gammaX, gammaY);
    }

    function verify(
        uint256[2] memory _publicKey,
        uint256[4] memory _proof,
        bytes memory _message)
    public returns (bool)
    {
        bool success = VRF.verify(_publicKey, _proof, _message);
        emit VRFStatus(success);
        return success;
    }

    function fastVerify(
        uint256[2] memory _publicKey,
        uint256[4] memory _proof,
        bytes memory _message,
        uint256[2] memory _uPoint,
        uint256[4] memory _vComponents)
    public returns (bool)
    {
        return VRF.fastVerify(
            _publicKey,
            _proof,
            _message,
            _uPoint,
            _vComponents);
    }

    function decodeProof(bytes memory _proof) public returns (uint[4] memory) {
        return VRF.decodeProof(_proof);
    }

    function decodePoint(bytes memory _point) public returns (uint[2] memory) {
        return VRF.decodePoint(_point);
    }

    function encodePoint(uint _x, uint _y) public returns (bytes memory) {
        return VRF.encodePoint(_x, _y);
    }

    function hashPoints(
        uint256 _hPointX,
        uint256 _hPointY,
        uint256 _gammaX,
        uint256 _gammaY,
        uint256 _uPointX,
        uint256 _uPointY,
        uint256 _vPointX,
        uint256 _vPointY)
    public returns (bytes16)
    {
       return VRF.hashPoints(
         _hPointX,
         _hPointY,
         _gammaX,
         _gammaY,
         _uPointX,
         _uPointY,
         _vPointX,
         _vPointY
       );
    }

    function computeFastVerifyParams(
        uint256[2] memory _publicKey,
        uint256[4] memory _proof,
        bytes memory _message)
    public returns (uint256[2] memory, uint256[4] memory)
    {
        return VRF.computeFastVerifyParams(_publicKey, _proof, _message);
    }
}
