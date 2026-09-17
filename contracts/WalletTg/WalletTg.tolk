import "@stdlib/gas-payments"
import "send-to-c5"
import "revisions"
import "errors"
import "messages"
import "storage"

/// WalletTg, the Telegram Wallet contract, is a wallet whose bytecode is stored in config.
/// Its blockchain logic is shared by all Telegram users and atomically updated by validator voting.
contract WalletTg {
    author: "TON Core"
    version: "1.0"
    description: "Telegram wallet contract; bytecode stays in config and is updated by validator voting"
    storage: Storage
    incomingMessages: SignedRequest<AllowedInternalMsg>
    incomingExternal: SignedRequest<AllowedExternalMsg>
    thrownErrors: Errors
    emittedEvents: RotationEvent
}

type AllowedInternalMsg =
    | SendOneMessageRequestI
    | SendBulkMessagesRequestI
    | ChangePublicKeyRequestI
type AllowedExternalMsg =
    | SendOneMessageRequestE
    | SendBulkMessagesRequestE
    | ChangePublicKeyRequestE

/// Validate the message header (present in all internal/external messages) against replay attacks.
@inline
fun SeqnoHeader.validateRequest(self, storage: Storage) {
    assert (self.seqno == storage.seqno) throw Errors.InvalidSeqno;
    assert (self.subwalletId == storage.subwalletId) throw Errors.InvalidSubwalletId;
    assert (self.validUntil > blockchain.now()) throw Errors.Expired;
}

/// Changing the wallet key requires a special "rotation proof" signed with the new private key.
fun checkRotationProof(rotationSignature: Cell<bits512>, newPublicKey: uint256): bool {
    // a "change key" message is signed by two keys:
    // 1) signature of the message itself (current key)
    // 2) a special "proof" signed by a new private key
    val (myWorkchain, myAddrHash) = contract.getAddress().getWorkchainAndHash();
    val expectedPayload = KeyRotationProofPayload {
        walletWorkchain: myWorkchain,
        walletAddrHash: myAddrHash,
    };
    return isSignatureValid(
        expectedPayload.toCell().hash(),    // the same payload is built by the client and signed
        rotationSignature.load() as slice,
        newPublicKey,
    );
}

@on_bounced_policy("manual")    // tell the compiler "don't insert code to filter out bounced messages"
fun onInternalMessage(in: InMessage) {
    // we should NOT throw until the signature proves that the owner signed the message;
    // WalletTrampoline already checked that `in.body` >= 512 bits;
    // in.body is `SignedRequest`: signature + rest, parse rest after checking
    val signature = in.body.loadBits(512);
    val rest = in.body;

    var storage = Storage.load();
    if (!isSignatureValid(rest.hash(), signature, storage.publicKey)) {
        return;
    }

    // after checking the signature, we may throw: if a message is invalid, it's still signed by the user
    val msg = lazy AllowedInternalMsg.fromSlice(rest);
    match (msg) {
        SendOneMessageRequestI => {
            msg.header.validateRequest(storage);

            storage.seqno += 1;
            storage.save();

            msg.msg.validateAndSend(false);
        }

        SendBulkMessagesRequestI => {
            msg.header.validateRequest(storage);

            storage.seqno += 1;
            storage.save();

            msg.msgArr.parseArrayAndSend(false);
        }

        ChangePublicKeyRequestI => {
            msg.header.validateRequest(storage);

            assert (storage.publicKey != msg.newPublicKey) throw Errors.NewKeyMustDiffer;
            assert (checkRotationProof(msg.rotationSignature, msg.newPublicKey)) throw Errors.NewKeySignatureIsInvalid;
            val encryptedPrevPrivateKey = msg.encryptedPrevPrivateKey.load();

            storage.seqno += 1;
            storage.publicKey = msg.newPublicKey;
            storage.save();

            RotationEvent {
                encryptedPrevPrivateKey,
            }.send();
        }

        else => {
            throw Errors.InvalidOpcode;
        }
    }
}

fun onExternalMessage(inMsgBody: slice) {
    // unlike onInternalMessage, we may throw here;
    // WalletTrampoline did not check anything for external, load 512 may throw;
    // expect inMsgBody to be `SignedRequest`: signature + rest, parse rest after checking
    val signature = inMsgBody.loadBits(512);
    val rest = inMsgBody;

    var storage = Storage.load();
    if (!isSignatureValid(rest.hash(), signature, storage.publicKey)) {
        throw Errors.InvalidSignature;
    }

    val msg = lazy AllowedExternalMsg.fromSlice(rest);
    match (msg) {
        SendOneMessageRequestE => {
            msg.header.validateRequest(storage);
            acceptExternalMessage();

            storage.seqno += 1;
            storage.save();
            commitContractDataAndActions();

            msg.msg.validateAndSend(true);
        }

        SendBulkMessagesRequestE => {
            msg.header.validateRequest(storage);
            acceptExternalMessage();

            storage.seqno += 1;
            storage.save();
            commitContractDataAndActions();

            // if parsing fails, the contract throws, and its balance is charged for gas;
            // this is expected: if we are here, the user signed this incorrectly packed message;
            // anyway, it cannot be replayed, because seqno is already bumped
            msg.msgArr.parseArrayAndSend(true);
        }

        ChangePublicKeyRequestE => {
            msg.header.validateRequest(storage);

            assert (storage.publicKey != msg.newPublicKey) throw Errors.NewKeyMustDiffer;
            assert (checkRotationProof(msg.rotationSignature, msg.newPublicKey)) throw Errors.NewKeySignatureIsInvalid;
            val encryptedPrevPrivateKey = msg.encryptedPrevPrivateKey.load();
            acceptExternalMessage();

            storage.seqno += 1;
            storage.publicKey = msg.newPublicKey;
            storage.save();

            RotationEvent {
                encryptedPrevPrivateKey,
            }.send();
        }

        else => {
            throw Errors.InvalidOpcode;
        }
    }
    // note: we don't need ENDS here, because an attack "hijack and append garbage to data"
    // is impossible: signature will mismatch
}

/// Returns current storage revision. It does not trigger migration.
/// After bytecode upgrade, returns the old revision until the first valid incoming message migrates `c4`.
get fun revision(): Revision {
    return getC4Revision()
}

/// Returns current seqno from the storage. Bumped on every valid incoming message.
get fun seqno(): uint32 {
    val storage = Storage.load();
    return storage.seqno;
}

/// Returns the subwallet id from the storage.
get fun get_subwallet_id(): uint32 {
    val storage = Storage.load();
    return storage.subwalletId;
}

/// Returns the public key corresponding to the signer's private key.
get fun get_public_key(): uint256 {
    val storage = Storage.load();
    return storage.publicKey;
}
