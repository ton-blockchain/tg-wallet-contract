import "@acton/crypto"
import "@acton/emulation/network"
import "@acton/testing/expect"
import "@acton/types/message"
import "@wrappers/WalletTrampoline.gen"
import "@wrappers/utils"
import "@contracts/WalletTg/errors"
import "@contracts/WalletTg/messages"

/*
    This file checks public key rotation: external/internal success paths,
    repeated rotations, current-key signatures, and new-key rotation proofs.
*/

get fun `test change-key: rotates the key and the new key takes over`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val (wallet, _) = deployWalletWithKey(oldKey);

    val reqRotation = prepareChangePublicKeyE(
        oldKey,
        seqnoHeader(0),
        wallet.address,
        newKey,
    );
    val rotation = wallet.requestExternal(reqRotation);
    expect(rotation).toBeAccepted();
    expect(rotation.unwrap()).toHaveTx({ exitCode: 0 });
    expect(wallet.getPublicKey()).toEqual(newKey.publicKey);
    expect(wallet.seqno()).toEqual(1);

    val receiver = randomAddress("receiver");
    val forwardValue = ton("0.001");
    val messageToSend = makeTransferToSend(receiver, forwardValue);

    val reqStale = prepareSendMessagesE(
        oldKey,
        seqnoHeader(1),
        [messageToSend],
    );
    val stale = wallet.requestExternal(reqStale);
    expect(stale).toBeNotAccepted();
    expect(stale).toHaveExternalVmExitCode(Errors.InvalidSignature);
    expect(wallet.seqno()).toEqual(1);

    val reqTransfer = prepareSendMessagesE(
        newKey,
        seqnoHeader(1),
        [messageToSend],
    );
    val transfer = wallet.requestExternal(reqTransfer);
    expect(transfer).toBeAccepted();
    expect(transfer.unwrap()).toHaveTx({
        from: wallet.address,
        to: receiver,
        value: forwardValue,
    });
    expect(wallet.seqno()).toEqual(2);
}

get fun `test change-key: the key can be rotated repeatedly externally`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val thirdKey = crypto.generateKeyPair();
    val (wallet, _) = deployWalletWithKey(oldKey);

    val reqFirst = prepareChangePublicKeyE(
        oldKey,
        seqnoHeader(0),
        wallet.address,
        newKey,
    );
    val first = wallet.requestExternal(reqFirst);
    expect(first).toBeAccepted();
    expect(first.unwrap()).toHaveTx({ exitCode: 0 });
    expect(wallet.getPublicKey()).toEqual(newKey.publicKey);
    expect(wallet.seqno()).toEqual(1);

    val reqSecond = prepareChangePublicKeyE(
        newKey,
        seqnoHeader(1),
        wallet.address,
        thirdKey,
    );
    val second = wallet.requestExternal(reqSecond);
    expect(second).toBeAccepted();
    expect(second.unwrap()).toHaveTx({ exitCode: 0 });
    expect(wallet.getPublicKey()).toEqual(thirdKey.publicKey);
    expect(wallet.seqno()).toEqual(2);
}

get fun `test change-key: a refused rotation keeps the current key and can be retried`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val (wallet, _) = deployWalletWithKey(oldKey);
    val wrongProof = createKeyRotationProof(wallet.address, oldKey);

    val reqRefused = prepareChangePublicKeyWithProofE(
        oldKey,
        seqnoHeader(0),
        newKey.publicKey,
        wrongProof,
    );
    val refused = wallet.requestExternal(reqRefused);

    expect(refused).toBeNotAccepted();
    expect(refused).toHaveExternalVmExitCode(Errors.NewKeySignatureIsInvalid);
    expect(wallet.getPublicKey()).toEqual(oldKey.publicKey);
    expect(wallet.seqno()).toEqual(0);

    val receiver = randomAddress("receiver-after-refused-rotation");
    val paymentValue = ton("0.001");
    val messageToSend = makeTransferToSend(receiver, paymentValue);
    val reqStillCurrent = prepareSendMessagesE(
        oldKey,
        seqnoHeader(0),
        [messageToSend],
    );
    val stillCurrent = wallet.requestExternal(reqStillCurrent);
    expect(stillCurrent).toBeAccepted();
    expect(stillCurrent.unwrap()).toHaveTx({
        from: wallet.address,
        to: receiver,
        value: paymentValue,
    });
    expect(wallet.seqno()).toEqual(1);

    val reqRetry = prepareChangePublicKeyE(
        oldKey,
        seqnoHeader(1),
        wallet.address,
        newKey,
    );
    val retry = wallet.requestExternal(reqRetry);
    expect(retry).toBeAccepted();
    expect(retry.unwrap()).toHaveTx({ exitCode: 0 });
    expect(wallet.getPublicKey()).toEqual(newKey.publicKey);
    expect(wallet.seqno()).toEqual(2);
}

get fun `test change-key: rotates through an internal signed request too`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val (wallet, deployer) = deployWalletWithKey(oldKey);

    val req = prepareChangePublicKeyI(
        oldKey,
        seqnoHeader(0),
        wallet.address,
        newKey,
    );
    val receipt = wallet.requestInternal(deployer.address, req, { value: ton("0.1") });

    expect(receipt).toHaveSuccessfulTx({ from: deployer.address, to: wallet.address });
    expect(wallet.getPublicKey()).toEqual(newKey.publicKey);
    expect(wallet.seqno()).toEqual(1);
}

get fun `test change-key: internal request rejects the same key`() {
    val keyPair = crypto.generateKeyPair();
    val (wallet, deployer) = deployWalletWithKey(keyPair);

    val req = prepareChangePublicKeyI(
        keyPair,
        seqnoHeader(0),
        wallet.address,
        keyPair,
    );
    val receipt = wallet.requestInternal(deployer.address, req, { value: ton("0.1") });

    expect(receipt).toHaveTx({ exitCode: Errors.NewKeyMustDiffer });
    expect(wallet.getPublicKey()).toEqual(keyPair.publicKey);
    expect(wallet.seqno()).toEqual(0);
}

get fun `test change-key: internal request can rotate the key repeatedly`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val thirdKey = crypto.generateKeyPair();
    val (wallet, deployer) = deployWalletWithKey(oldKey);

    val reqFirst = prepareChangePublicKeyI(
        oldKey,
        seqnoHeader(0),
        wallet.address,
        newKey,
    );
    val first = wallet.requestInternal(deployer.address, reqFirst, { value: ton("0.1") });
    expect(first).toHaveSuccessfulTx({ from: deployer.address, to: wallet.address });
    expect(wallet.getPublicKey()).toEqual(newKey.publicKey);
    expect(wallet.seqno()).toEqual(1);

    val reqSecond = prepareChangePublicKeyI(
        newKey,
        seqnoHeader(1),
        wallet.address,
        thirdKey,
    );
    val second = wallet.requestInternal(deployer.address, reqSecond, { value: ton("0.1") });
    expect(second).toHaveSuccessfulTx({ from: deployer.address, to: wallet.address });
    expect(wallet.getPublicKey()).toEqual(thirdKey.publicKey);
    expect(wallet.seqno()).toEqual(2);
}

get fun `test change-key: internal request rejects proof from the wrong key`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val (wallet, deployer) = deployWalletWithKey(oldKey);
    val wrongProof = createKeyRotationProof(wallet.address, oldKey);

    val req = prepareChangePublicKeyWithProofI(
        oldKey,
        seqnoHeader(0),
        newKey.publicKey,
        wrongProof,
    );
    val receipt = wallet.requestInternal(deployer.address, req, { value: ton("0.1") });

    expect(receipt).toHaveTx({ exitCode: Errors.NewKeySignatureIsInvalid });
    expect(wallet.getPublicKey()).toEqual(oldKey.publicKey);
    expect(wallet.seqno()).toEqual(0);
}

get fun `test change-key: a rotation the new key did not sign is rejected`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val (wallet, _) = deployWalletWithKey(oldKey);
    val wrongProof = createKeyRotationProof(wallet.address, oldKey);

    val req = prepareChangePublicKeyWithProofE(
        oldKey,
        seqnoHeader(0),
        newKey.publicKey,
        wrongProof,
    );
    val result = wallet.requestExternal(req);

    expect(result).toBeNotAccepted();
    expect(result).toHaveExternalVmExitCode(Errors.NewKeySignatureIsInvalid);
    expect(wallet.getPublicKey()).toEqual(oldKey.publicKey);
    expect(wallet.seqno()).toEqual(0);
}

get fun `test change-key: rotating to the same key is rejected`() {
    val keyPair = crypto.generateKeyPair();
    val (wallet, _) = deployWalletWithKey(keyPair);

    val req = prepareChangePublicKeyE(
        keyPair,
        seqnoHeader(0),
        wallet.address,
        keyPair,
    );
    val result = wallet.requestExternal(req);
    expect(result).toBeNotAccepted();
    expect(result).toHaveExternalVmExitCode(Errors.NewKeyMustDiffer);
    expect(wallet.getPublicKey()).toEqual(keyPair.publicKey);
    expect(wallet.seqno()).toEqual(0);
}

get fun `test change-key: a request the current key did not sign is rejected`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val attackerKey = crypto.generateKeyPair();
    val (wallet, _) = deployWalletWithKey(oldKey);

    val req = prepareChangePublicKeyE(
        attackerKey,
        seqnoHeader(0),
        wallet.address,
        newKey,
    );
    val forged = wallet.requestExternal(req);
    expect(forged).toBeNotAccepted();
    expect(forged).toHaveExternalVmExitCode(Errors.InvalidSignature);
    expect(wallet.getPublicKey()).toEqual(oldKey.publicKey);
    expect(wallet.seqno()).toEqual(0);
}

get fun `test change-key: a proof made for one wallet is rejected by another`() {
    val sharedKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val subwalletIdA: uint32 = DEFAULT_SUBWALLET_ID;
    val subwalletIdB: uint32 = DEFAULT_SUBWALLET_ID + 1;
    val (walletA, _) = deployWallet(makeStorage(sharedKey.publicKey, 0, subwalletIdA));
    val (walletB, _) = deployWallet(makeStorage(sharedKey.publicKey, 0, subwalletIdB));
    val proofForA = createKeyRotationProof(walletA.address, newKey);

    val reqB = prepareChangePublicKeyWithProofE(
        sharedKey,
        seqnoHeader(0, null, subwalletIdB),
        newKey.publicKey,
        proofForA,
    );
    val forB = walletB.requestExternal(reqB);
    expect(forB).toBeNotAccepted();
    expect(forB).toHaveExternalVmExitCode(Errors.NewKeySignatureIsInvalid);
    expect(walletB.getPublicKey()).toEqual(sharedKey.publicKey);
    expect(walletB.seqno()).toEqual(0);

    val reqA = prepareChangePublicKeyWithProofE(
        sharedKey,
        seqnoHeader(0, null, subwalletIdA),
        newKey.publicKey,
        proofForA,
    );
    val forA = walletA.requestExternal(reqA);
    expect(forA).toBeAccepted();
    expect(forA.unwrap()).toHaveTx({ exitCode: 0 });
    expect(walletA.getPublicKey()).toEqual(newKey.publicKey);
    expect(walletA.seqno()).toEqual(1);
}

get fun `test change-key: external rotation logs the encrypted previous key`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val (wallet, _) = deployWalletWithKey(oldKey);
    val req = prepareChangePublicKeyE(oldKey, seqnoHeader(0), wallet.address, newKey, 0x1234);

    val result = wallet.requestExternal(req);
    expect(result).toBeAccepted();
    val event = result.findExternalOutMessage<RotationEvent>()!;
    expect(event.loadBody().encryptedPrevPrivateKey).toEqual(0x1234);
}

get fun `test change-key: internal rotation logs the encrypted previous key`() {
    val oldKey = crypto.generateKeyPair();
    val newKey = crypto.generateKeyPair();
    val (wallet, deployer) = deployWalletWithKey(oldKey);
    val req = prepareChangePublicKeyI(oldKey, seqnoHeader(0), wallet.address, newKey, 0x1234);

    val result = wallet.requestInternal(deployer.address, req, { value: ton("0.1") });
    expect(result).toHaveSuccessfulTx({ to: wallet.address });
    val event = result.findExternalOutMessage<RotationEvent>()!;
    expect(event.loadBody().encryptedPrevPrivateKey).toEqual(0x1234);
}
