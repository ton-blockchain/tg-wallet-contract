import "errors"
import "messages"


/// Emit the encrypted previous private key as an external log for the wallet client.
fun RotationEvent.send(self) {
    val msg = createExternalLogMessage({
        dest: createAddressNone(),
        body: self,
    });
    msg.send(SEND_MODE_REGULAR);
}

/// Every client-provided message is sent via `sendRawMessage`, which appends an out action to c5.
fun MessageToSend.validateAndSend(self, isExternal: bool) {
    if (isExternal) {
        val hasIgnoreErrors = (self.sendMode & SEND_MODE_IGNORE_ERRORS) != 0;
        assert (hasIgnoreErrors) throw Errors.ExternalSendMessageMustHaveIgnoreErrorsSendMode;
    }
    // the most expensive line in WalletTg: 526 gas, it builds a cell for the c5-snake;
    // it's worse in gas than wallet-v5 which accepts raw c5 from a client,
    // but much CHEAPER in importFee, because
    // 1) each message is not wrapped to an extra cell
    // 2) bulk sending: 3 messages per chunk in an array, 3 times less incoming cells
    sendRawMessage(self.messageCell, self.sendMode);
}

/// Parse `array<MessageToSend>` encoded as a standard Tolk array, processing every message.
/// Instead of doing `array.fromSlice` (to a tuple of sub-tuples) + iterate this array,
/// parse-and-process on the fly: this is much cheaper.
/// We CAN throw here if an array is wrong-encoded ("cell underflow" and other parsing errors).
@inline
fun RawArrayOfMessagesToSend.parseArrayAndSend(self, isExternal: bool): slice {
    // self is raw slice encoded as an array: uint8 len + snaked chunks
    var cs = self;
    var count = 0;
    val len = cs.loadUint(8);
    var head = cs.loadMaybeRef();

    // we expect at least 1 message; an empty array (head == null) or malformed fails at beginParse
    head = head!;
    // do-while is cheaper than while
    do {
        // format of cur chunk: maybe ref to next chunk + N items
        var s = head.beginParse();
        head = s.loadMaybeRef();
        // possible:
        // 1 MessageToSend =  8 bits + 1 ref
        // 2 MessageToSend = 16 bits + 2 refs
        // 3 MessageToSend = 24 bits + 3 refs
        // 4 MessageToSend = 32 bits + 4 refs (last chunk, when no head ref)
        val chunkSize = s.remainingRefsCount();
        count += chunkSize;
        repeat (chunkSize) {
            val msg = s.loadAny<MessageToSend>();
            msg.validateAndSend(isExternal);
        }
        s.assertEnd();
    } while (head != null);

    // verify that encoded array len equals to actually provided chunks;
    // since len is uint8, there can't be more than 255 messages failing the action phase
    assert (count != 0) throw Errors.InvalidOutArrayLen;
    assert (count == len) throw Errors.InvalidOutArrayLen;
    // return what's following in "remaining", in case the caller needs this
    return cs;
}
