
<div class="row">
# Handshake Protocol
`---snip---`

<!-- 
The handshake protocol is used to negotiate the secure attributes
of a session. Handshake messages are supplied to the TLS record layer, where
they are encapsulated within one or more TLSPlaintext or TLSCiphertext structures, which are
processed and transmitted as specified by the current active session state.
-->


<div class="row">
<div class="col1">
```C
%%% Handshake Protocol

       enum {
           hello_request_RESERVED(0),
           client_hello(1),
           server_hello(2),
           hello_verify_request_RESERVED(3),
           new_session_ticket(4),
           end_of_early_data(5),
           hello_retry_request(6),
           encrypted_extensions(8),
           certificate(11),
           server_key_exchange_RESERVED(12),
           certificate_request(13),
           server_hello_done_RESERVED(14),
           certificate_verify(15),
           client_key_exchange_RESERVED(16),
           finished(20),
           key_update(24),
           message_hash(254),
           (255)
       } HandshakeType;

       struct {
           HandshakeType msg_type;    /* handshake type */
           uint24 length;             /* bytes in message */
           select (Handshake.msg_type) {
               case client_hello:          ClientHello;
               case server_hello:          ServerHello;
               case end_of_early_data:     EndOfEarlyData;
               case hello_retry_request:   HelloRetryRequest;
               case encrypted_extensions:  EncryptedExtensions;
               case certificate_request:   CertificateRequest;
               case certificate:           Certificate;
               case certificate_verify:    CertificateVerify;
               case finished:              Finished;
               case new_session_ticket:    NewSessionTicket;
               case key_update:            KeyUpdate;
           } body;
       } Handshake;
```
`---snip---`

<!--
Protocol messages MUST be sent in the order defined below (and
shown in the diagrams in {{protocol-overview}}).
A peer which receives a handshake message in an unexpected order
MUST abort the handshake with an "unexpected_message" alert.
Unneeded handshake messages are omitted, however.

New handshake message types are assigned by IANA as described in
{{iana-considerations}}.
 -->

</div>
<div class="col2">
Handshake messages are constructed with the macro `handshake_record('num', body...)`
which simply produces the tuple `<'24', 'num', body...>` where `'num'` is the enum
value from `HandshakeType`, and body is the contents of the message as defined later.

We omit a length parameter.

</div>
</div>
