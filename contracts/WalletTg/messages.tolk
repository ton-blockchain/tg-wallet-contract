/// WalletTg can send up to 255 out messages.
/// Note: in contrast with w5, which accepts a well-formed c5 register, WalletTg accepts messages.
/// This is a clearer API, although it costs more gas unless WalletTg is precompiled.
struct MessageToSend {
    sendMode: uint8
    messageCell: cell
}

/// Bulk requests carry `array<MessageToSend>`, a standard-encoded Tolk array.
/// The contract parses it manually as a raw slice to avoid materializing the array.
type RawArrayOfMessagesToSend = RemainingBitsAndRefs

/// Previous private key encrypted by the client: prevPrivateKey XOR sha256(newPrivateKey ++ "old-key-encryption").
/// The contract copies this value to `RotationEvent` without decrypting it.
type EncryptedPrivateKey = uint256

/// A payload signed by a new private key for the "change key" request.
struct KeyRotationProofPayload {
    private tag: uint96 = 0x4B45595F524F544154494F4E
    walletWorkchain: int8
    walletAddrHash: uint256
}

/// Every internal/external message is signed by a private key and checked against `storage.publicKey`.
/// The client-side signing process has three steps.
/// 1. Compose some valid request (body).
/// 2. Sign it with their private key (derived from a mnemonic) — resulting in `signature`.
/// 3. Prepend the signature to the serialized request and send.
///
/// Note that signing DIFFERS FROM WALLET V5, where signature lies at the end.
/// W5 is ABI-unfriendly: we can't describe "signature at the end" after RemainingBitsAndRefs.
/// Current (Telegram) version is Tolk-friendly, ABI-friendly, and client-friendly.
struct SignedRequest<T> {
    /// Signature of the body with the client's private key.
    signature: bits512
    /// Body of the incoming message (with opcode and data).
    request: T
}

/// Every internal/external request starts with a header.
/// For instance, it contains seqno to protect against replay attacks.
struct SeqnoHeader {
    /// Must match `Storage.subwalletId`, so one key can control multiple wallets.
    subwalletId: uint32
    /// Unix timestamp until which the message is valid. Must be greater than `blockchain.now`.
    /// Protects against replay after expiration.
    validUntil: uint32
    /// Seqno protects against replay attacks. Must match `Storage.seqno`.
    seqno: uint32
}

/// Check the signature and forward ONE message.
/// `MessageToSend` is stored inline, reducing import fee and gas.
/// Internal (not external) is used for gasless.
struct (0x63896E74) SendOneMessageRequestI {
    /// Header protects against replay attacks.
    header: SeqnoHeader
    /// A message to send. The contract builds c5 itself.
    msg: MessageToSend
}

/// Check the signature and forward ONE message.
/// Differs from "internal" struct only in opcode to prevent cross-channel replay.
struct (0x63896E75) SendOneMessageRequestE {
    /// Header protects against replay attacks.
    header: SeqnoHeader
    /// A message to send. The contract builds c5 itself.
    msg: MessageToSend
}

/// Check the signature and forward MANY messages (1-255).
/// Analogous to w5 "internal signed request".
/// Internal (not external) is used for gasless.
struct (0x73896E74) SendBulkMessagesRequestI {
    /// Header protects against replay attacks.
    header: SeqnoHeader
    /// Messages to send (1-255). The contract builds c5 itself.
    @abi.clientType(array<MessageToSend>)
    msgArr: RawArrayOfMessagesToSend
}

/// Check the signature and forward MANY messages (1-255).
/// Analogous to w5 "external signed request".
/// Differs from "internal" struct only in opcode to prevent cross-channel replay.
struct (0x73896E75) SendBulkMessagesRequestE {
    /// Header protects against replay attacks.
    header: SeqnoHeader
    /// Messages to send (1-255). The contract builds c5 itself.
    @abi.clientType(array<MessageToSend>)
    msgArr: RawArrayOfMessagesToSend
}

/// Change the wallet signing key.
/// Can be repeated: each request is signed by the current key and proven by the new key.
/// Internal (not external) is used for gasless.
struct (0xFBBA99C7) ChangePublicKeyRequestI {
    /// Header protects against replay attacks.
    header: SeqnoHeader
    /// Resets `Storage.publicKey` to this value.
    newPublicKey: uint256
    /// Signed `KeyRotationProofPayload`. The "change key" request is signed twice.
    /// First, by the current key (SignedRequest, the incoming message itself).
    /// Second, by the new key (rotation proof).
    rotationSignature: Cell<bits512>
    /// Previous private key encrypted by the new key, so the client can decrypt older messages.
    encryptedPrevPrivateKey: Cell<EncryptedPrivateKey>
}

/// Change the wallet signing key.
/// Can be repeated: each request is signed by the current key and proven by the new key.
/// Differs from "internal" struct only in opcode to prevent cross-channel replay.
struct (0xFBBA99C8) ChangePublicKeyRequestE {
    /// Header protects against replay attacks.
    header: SeqnoHeader
    /// Resets `Storage.publicKey` to this value.
    newPublicKey: uint256
    /// Signed `KeyRotationProofPayload`. The "change key" request is signed twice.
    /// First, by the current key (SignedRequest, the incoming message itself).
    /// Second, by the new key (rotation proof).
    rotationSignature: Cell<bits512>
    /// Previous private key encrypted by the new key, so the client can decrypt older messages.
    encryptedPrevPrivateKey: Cell<EncryptedPrivateKey>
}

/// External log emitted on a successful key rotation.
/// Carries the previous private key encrypted by the new key, so the client can decrypt older messages.
struct (0x5D1CD02F) RotationEvent {
    encryptedPrevPrivateKey: EncryptedPrivateKey
}
