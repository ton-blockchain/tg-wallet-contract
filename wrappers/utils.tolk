import "@acton/build"
import "@acton/crypto"
import "@acton/emulation/config"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@contracts/WalletTg/WalletTg"
import "@contracts/WalletTg/messages"
import "@contracts/WalletTg/revisions"
import "@contracts/WalletTg/storage"
import "WalletTrampoline.gen"

const DEFAULT_SUBWALLET_ID = 0x7FFF7FFD as uint32
const CONFIG_KEY_OF_BYTECODE = -123 // the same as in `WalletTrampoline.fif`

const ALL_REVISIONS_BOC_PATHS = array<string> [
    "contracts/revisions-boc/WalletTg-rev00.boc",
    // appended manually when starting developing the next revision
]

fun setWalletBytecodeInConfig(revision: Revision = LAST_REVISION): void {
    build("WalletTg"); // updates last revision boc (output in Acton.toml)
    val bocFilePath = ALL_REVISIONS_BOC_PATHS.get(revision as int);
    val codeCell = build("WalletTg", bocFilePath);

    var config = testing.getConfig();
    config.setParamRaw(CONFIG_KEY_OF_BYTECODE, codeCell);
    expect(testing.setConfig(config)).toBeTrue();
}

fun makeStorage(
    publicKey: uint256 = 0,
    seqno: uint32 = 0,
    subwalletId: uint32 = DEFAULT_SUBWALLET_ID,
): Storage {
    return {
        seqno,
        subwalletId,
        publicKey,
    };
}

fun WalletTrampoline.requestInternal(
    self,
    from: address,
    prepared: SignedRequest<AllowedInternalMsg>,
    config: SendParams = {},
): SendResultList {
    return self.sendSignedRequest(from, prepared.signature, prepared.request, config);
}

fun WalletTrampoline.requestExternal(
    self,
    prepared: SignedRequest<AllowedExternalMsg>,
): ExternalSendResult {
    return self.sendExternalSignedRequest(prepared.signature, prepared.request);
}

fun seqnoHeader(
    seqno: uint32,
    validUntil: uint32? = null,
    subwalletId: uint32 = DEFAULT_SUBWALLET_ID,
): SeqnoHeader {
    return {
        subwalletId,
        validUntil: validUntil == null ? blockchain.now() + 1000 : validUntil,
        seqno,
    };
}

fun prepareSendMessagesI(
    keyPair: KeyPair,
    header: SeqnoHeader,
    toSend: array<MessageToSend> | builder | slice,
): SignedRequest<AllowedInternalMsg> {
    var request: AllowedInternalMsg;
    if (toSend is array<MessageToSend> && toSend.size() == 1) {
        request = SendOneMessageRequestI {
            header,
            msg: toSend.first(),
        };
    } else {
        request = SendBulkMessagesRequestI {
            header,
            // `msgArr` is `array` in @abi.clientType, but raw slice for a contract
            msgArr: match (toSend) {
                array<MessageToSend> => toSend.toCell().beginParse(),
                builder => toSend.toSlice(),
                slice => toSend,
            },
        };
    }
    val signature = crypto.sign(keyPair.privateKey, request.toCell()) as bits512;
    return { signature, request };
}

fun prepareSendMessagesE(
    keyPair: KeyPair,
    header: SeqnoHeader,
    toSend: array<MessageToSend> | builder | slice,
): SignedRequest<AllowedExternalMsg> {
    var request: AllowedExternalMsg;
    if (toSend is array<MessageToSend> && toSend.size() == 1) {
        request = SendOneMessageRequestE {
            header,
            msg: toSend.first(),
        };
    } else {
        request = SendBulkMessagesRequestE {
            header,
            // `msgArr` is `array` in @abi.clientType, but raw slice for a contract
            msgArr: match (toSend) {
                array<MessageToSend> => toSend.toCell().beginParse(),
                builder => toSend.toSlice(),
                slice => toSend,
            },
        };
    }
    val signature = crypto.sign(keyPair.privateKey, request.toCell()) as bits512;
    return { signature, request };
}

fun prepareChangePublicKeyWithProofI(
    currentKey: KeyPair,
    header: SeqnoHeader,
    newPublicKey: uint256,
    rotationSignature: bits512,
    encryptedPrevPrivateKey: EncryptedPrivateKey = 0,
): SignedRequest<AllowedInternalMsg> {
    val request = ChangePublicKeyRequestI {
        header,
        newPublicKey,
        rotationSignature: rotationSignature.toCell(),
        encryptedPrevPrivateKey: encryptedPrevPrivateKey.toCell(),
    };
    val signature = crypto.sign(currentKey.privateKey, request.toCell()) as bits512;
    return { signature, request };
}

fun prepareChangePublicKeyI(
    currentKey: KeyPair,
    header: SeqnoHeader,
    walletAddress: address,
    newKey: KeyPair,
    encryptedPrevPrivateKey: EncryptedPrivateKey = 0,
): SignedRequest<AllowedInternalMsg> {
    val request = ChangePublicKeyRequestI {
        header,
        newPublicKey: newKey.publicKey,
        rotationSignature: createKeyRotationProof(walletAddress, newKey).toCell(),
        encryptedPrevPrivateKey: encryptedPrevPrivateKey.toCell(),
    };
    val signature = crypto.sign(currentKey.privateKey, request.toCell()) as bits512;
    return { signature, request };
}

fun prepareChangePublicKeyWithProofE(
    currentKey: KeyPair,
    header: SeqnoHeader,
    newPublicKey: uint256,
    rotationSignature: bits512,
    encryptedPrevPrivateKey: EncryptedPrivateKey = 0,
): SignedRequest<AllowedExternalMsg> {
    val request = ChangePublicKeyRequestE {
        header,
        newPublicKey,
        rotationSignature: rotationSignature.toCell(),
        encryptedPrevPrivateKey: encryptedPrevPrivateKey.toCell(),
    };
    val signature = crypto.sign(currentKey.privateKey, request.toCell()) as bits512;
    return { signature, request };
}

fun prepareChangePublicKeyE(
    currentKey: KeyPair,
    header: SeqnoHeader,
    walletAddress: address,
    newKey: KeyPair,
    encryptedPrevPrivateKey: EncryptedPrivateKey = 0,
): SignedRequest<AllowedExternalMsg> {
    val request = ChangePublicKeyRequestE {
        header,
        newPublicKey: newKey.publicKey,
        rotationSignature: createKeyRotationProof(walletAddress, newKey).toCell(),
        encryptedPrevPrivateKey: encryptedPrevPrivateKey.toCell(),
    };
    val signature = crypto.sign(currentKey.privateKey, request.toCell()) as bits512;
    return { signature, request };
}

fun makeTransferToSend(dest: address, value: coins): MessageToSend {
    val innerMsg = createMessage({
        bounce: false,
        value,
        dest,
    });
    return { sendMode: SEND_MODE_PAY_FEES_SEPARATELY | SEND_MODE_IGNORE_ERRORS, messageCell: innerMsg.messageCell };
}

/// Build the raw `SignedRequest` envelope for deliberately untyped or malformed
/// payload tests. The referenced payload itself is what the outer key signs.
fun createRawSignedEnvelope<TRequest>(keyPair: KeyPair, request: TRequest): cell {
    val bodyCell = request.toCell();
    val signature = crypto.sign(keyPair.privateKey, bodyCell);
    return beginCell().storeSlice(signature).storeSlice(bodyCell.beginParse()).endCell();
}

fun createKeyRotationProof(walletAddress: address, proofKey: KeyPair): bits512 {
    val (walletWorkchain, walletAddrHash) = walletAddress.getWorkchainAndHash();
    val payload = KeyRotationProofPayload { walletWorkchain, walletAddrHash };
    return crypto.sign(proofKey.privateKey, payload.toCell()) as bits512;
}

fun deployWallet(storage: Storage): (WalletTrampoline, Treasury) {
    setWalletBytecodeInConfig(); // NB: deploys the LAST revision with the LAST storage shape
    val deployer = testing.treasury("deployer");
    val wallet = WalletTrampoline.fromStorage(storage);
    val deployResult = wallet.deploy(deployer.address, { value: ton("5"), bounce: false });

    expect(deployResult).toHaveSuccessfulDeploy({ to: wallet.address });
    return (wallet, deployer);
}

fun deployWalletWithKey(keyPair: KeyPair): (WalletTrampoline, Treasury) {
    val storage = makeStorage(keyPair.publicKey);
    return deployWallet(storage);
}
