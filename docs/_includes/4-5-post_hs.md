<div class="row">
## Post-Handshake Messages
</div>
<div class="row">
<div class="col1">
TLS also allows other messages to be sent after the main handshake.
These messages use a handshake content type and are encrypted under the
appropriate application traffic key.
</div>
<div class="col2"></div>
</div>

<div class="row">
### New Session Ticket Message {#NSTMessage}
</div>
<div class="row">
<div class="col1">
At any time after the server has received the client Finished message, it MAY send
a NewSessionTicket message. This message creates a pre-shared key
(PSK) binding between the ticket value and the resumption master secret.

The client MAY use this PSK for future handshakes by including the
ticket value in the "pre_shared_key" extension in its ClientHello
({{pre-shared-key-extension}}). Servers MAY send multiple tickets on a
single connection, either immediately after each other or
after specific events. For instance, the server might send
a new ticket after post-handshake
authentication in order to encapsulate the additional client
authentication state. Clients SHOULD attempt to use each
ticket no more than once, with more recent tickets being used
first.

Any ticket MUST only be resumed with a cipher suite that has the
same KDF hash algorithm as that used to establish the original connection,
and only if the client provides the same SNI value as in the original
connection, as described in Section 3 of {{RFC6066}}.

Note: Although the resumption master secret depends on the client's second
flight, servers which do not request client authentication MAY compute
the remainder of the transcript independently and then send a
NewSessionTicket immediately upon sending its Finished rather than
waiting for the client Finished.  This might be appropriate in cases
where the client is expected to open multiple TLS connections in
parallel and would benefit from the reduced overhead of a resumption
handshake, for example.


%%% Ticket Establishment

       struct {
           uint32 ticket_lifetime;
           uint32 ticket_age_add;
           opaque ticket<1..2^16-1>;
           Extension extensions<0..2^16-2>;
       } NewSessionTicket;

ticket_lifetime

`---snip---`

<!--
: Indicates the lifetime in seconds as a 32-bit unsigned integer in
  network byte order from the time of ticket issuance.
  Servers MUST NOT use any value more than 604800 seconds (7 days).
  The value of zero indicates that the ticket should be discarded
  immediately. Clients MUST NOT cache session tickets for longer than
  7 days, regardless of the ticket_lifetime and MAY delete the ticket
  earlier based on local policy. A server MAY treat a ticket as valid
  for a shorter period of time than what is stated in the
  ticket_lifetime.
-->

ticket_age_add
: A securely generated, random 32-bit value that is used to obscure the age of
  the ticket that the client includes in the "pre_shared_key" extension.
  The client-side ticket age is added to this value modulo 2^32 to
  obtain the value that is transmitted by the client. The server MUST
  generate a fresh value for each ticket it sends.

ticket
: The value of the ticket to be used as the PSK identity.
The ticket itself is an opaque label. It MAY either be a database
lookup key or a self-encrypted and self-authenticated value. Section
4 of {{RFC5077}} describes a recommended ticket construction mechanism.


extensions
: A set of extension values for the ticket. The "Extension"
  format is defined in {{extensions}}. Clients MUST ignore
  unrecognized extensions.
{:br }

The sole extension currently defined for NewSessionTicket is
"early_data", indicating that the ticket may be used to send 0-RTT data
({{early-data-indication}})). It contains the following value:

max_early_data_size
: The maximum amount of 0-RTT data that the client is allowed to send when using
  this ticket, in bytes. Only Application Data payload (i.e., plaintext but
  not padding or the inner content type byte) is counted. A server
  receiving more than max_early_data_size bytes of 0-RTT data
  SHOULD terminate the connection with an "unexpected_message" alert.
  Note that servers that reject early data due to lack of cryptographic material
  will be unable to differentiate padding from content, so clients SHOULD NOT
  depend on being able to send large quantities of padding in early data records.
{:br }

Note that in principle it is possible to continue issuing new tickets
which indefinitely extend the lifetime of the keying
material originally derived from an initial non-PSK handshake (which
was most likely tied to the peer's certificate). It is RECOMMENDED
that implementations place limits on the total lifetime of such keying
material; these limits should take into account the lifetime of the
peer's certificate, the likelihood of intervening revocation,
and the time since the peer's online CertificateVerify signature.

</div>
<div class="col2">

We have a `new_session_ticket` which models the server sending a
`NewSessionTicket` message. The corresponding `recv_` rule on the client side
completes the exchange by receiving the message and generating the relevant
values.

The `NewSessionTicket` message is defined as:
```
define(<!NewSessionTicket!>, <!handshake_record('4',
  $ticket_lifetime,
  ticket_age_add,
  ticket,
  TicketExtensions
)!>)
``` 

That is, we do not currently model the session ticket as having a particular
lifetime, though we note that as usual if the server rejects a PSK then this is
effectively covered by viewing a trace which terminates at
`recv_client_hello_psk` or other.

`ticket_age_add` is a fresh value as used in [PSK extension](#pre-shared-key-
extension).

`ticket` is also a fresh value and is used by the client as the identity to
resume a session. We do not currently model the server storing state by using
`ticket` as an encrypted blob, however we would like to investigate this in 
future work, since it appears to be a common way of implementing PSKs.

For the extensions, we simply have:
```
define(<!TicketExtensions!>, <!<Extension('46', $max_early_data_size)>!>)
```

When the server/client sends/receives resp. the `NewSessionTicket` message, they
also output a `!Server/!ClientPSK` fact which encapsulates the PSK state:
```
  !ServerPSK(S, C, res_psk, auth_status, NewSessionTicket, 'nst'),
```

This stores: 
 - server and client identities
 - resumption master secret (`res_psk`)
 - authentication status of the peer
 - `NewSessionTicket` message blob, containing all other variables (`ticket`,
   `ticket_age_add`, etc.)
 - type of session ticket (`'nst'` for `NewSessionTicket`, `'oob'` for out of
   band PSK)

This fact is used in the `client_hello_psk` etc. rules to initialise the
required variables.

We do not currently model anything to do with the cipher suites used, but this
variable could also be used to ensure these are equal in the resumed session.

We believe there are some interesting scenarios which we can capture by
modifying the above assumptions of what the server stores in the PSK state.
For example:

  - Server only stores limited information: e.g. just `res_psk`
  - Server stores full set of information (usual case)
  - Server encrypts state within ticket and avoid storing state

Furthermore, each of these scenarios have different implications for an adversary
who is able to compromise the entire server state. 

PSKs are currently modelled as persistanct facts; they live forever and can be
reused as many time as desired.
</div> </div>

<div class="row">
### Post-Handshake Authentication
</div>
<div class="row">
<div class="col1">

When the client has sent the "post_handshake_auth" extension (see
{{post_handshake_auth}}), a server MAY request client authentication at any time
after the handshake has completed by sending a CertificateRequest message. The
client MUST respond with the appropriate Authentication messages (see
{{authentication-messages}}). If the client chooses to authenticate, it MUST
send Certificate, CertificateVerify, and Finished. If it declines, it MUST send
a Certificate message containing no certificates followed by Finished.
All of the client's messages for a given response
MUST appear consecutively on the wire with no intervening messages of other types.

A client that receives a CertificateRequest message without having sent
the "post_handshake_auth" extension MUST send an "unexpected_message" fatal
alert.

Note: Because client authentication could involve prompting the user, servers
MUST be prepared for some delay, including receiving an arbitrary number of
other messages between sending the CertificateRequest and receiving a
response. In addition, clients which receive multiple CertificateRequests in
close succession MAY respond to them in a different order than they were
received (the certificate_request_context value allows the server to
disambiguate the responses).

</div>
<div class="col2">
Here we have two main concerns to model:
1. Optional client auth
2. Multiple concurrent auth reqs/responses

We do not currently support the first. That is, the client will either never
reply, or will send a certificate. We can look into supporting empty certificates
in the future to model not authenticating.

We do, however, support the second option. Server certificate requests generate
a new `ServerCertReq` fact which encapsulates the server storing additional state
to track the certificate requests. This value is:
```
      ServerCertReq(tid, S, C, certificate_request_context),
```
which tracks the current session (`tid`), the identities of server and client, 
and the context value used to disambiguate the requests.

The client has equivalent facts for the same purpose.
</div>
</div>


<div class="row">
### Key and IV Update {#key-update}
</div>
<div class="row">
<div class="col1">

%%% Updating Keys

       enum {
           update_not_requested(0), update_requested(1), (255)
       } KeyUpdateRequest;

       struct {
           KeyUpdateRequest request_update;
       } KeyUpdate;


request_update
: Indicates whether the recipient of the KeyUpdate should respond with its
own KeyUpdate. If an implementation receives any other value, it MUST
terminate the connection with an "illegal_parameter" alert.
{:br }

The KeyUpdate handshake message is used to indicate that the sender is
updating its sending cryptographic keys. This message can be sent by
either peer after it has sent a Finished message.
Implementations that receive a KeyUpdate message
prior to receiving a Finished message
MUST terminate the connection with an "unexpected_message" alert.
After sending a KeyUpdate message, the sender SHALL send all its traffic using the
next generation of keys, computed as described in
{{updating-traffic-keys}}. Upon receiving a KeyUpdate, the receiver
MUST update its receiving keys.

If the request_update field is set to "update_requested" then the receiver MUST
send a KeyUpdate of its own with request_update set to "update_not_requested" prior
to sending its next application data record. This mechanism allows either side to force an update to the
entire connection, but causes an implementation which
receives multiple KeyUpdates while it is silent to respond with
a single update. Note that implementations may receive an arbitrary
number of messages between sending a KeyUpdate with request_update set
to update_requested and receiving the
peer's KeyUpdate, because those messages may already be in flight.
However, because send and receive keys are derived from independent
traffic secrets, retaining the receive traffic secret does not threaten
the forward secrecy of data sent before the sender changed keys.

If implementations independently send their own KeyUpdates with
request_update set to "update_requested", and they cross in flight, then each side
will also send a response, with the result that each side increments
by two generations.

Both sender and receiver MUST encrypt their KeyUpdate
messages with the old keys. Additionally, both sides MUST enforce that
a KeyUpdate with the old key is received before accepting any messages
encrypted with the new key. Failure to do so may allow message truncation
attacks.

</div>
<div class="col2">

The way we view the `KeyUpdate` mechanism is as follows:
```
          Client                              Server

            senc{data1}kc1   ----->
                             <-----   senc{data2}ks1
            senc{data3}kc1   ----->

                              ...

KeyUpdate(update_requested)  ----->
kc2 = keygen(...)                                    kc2 = keygen(...)

            senc{data4}kc2   ----->      (not yet processed by Server)

                             <-----    KeyUpdate(update_not_requested)
ks2 = keygen(...)                                    ks2 = keygen(...)

                                                     (processes data4)
                             <-----   senc{data5}ks2
```

(And equivalently in the other direction)

When one actor requests a key update, the other party attempts to immediately
respond with their own `KeyUpdate` message. However, clearly messages may
arrive or be processed in a different order than they are sent.

We have a single rule `update_recv_{client,server}` which models receiving
the initial `KeyUpdate` message, and immediately sending a new `KeyUpdate`
message, updating both receiving and sendings keys. Technically, this means
that the party cannot receive a message in between updating the receiving key
and updating the sending key, however we argue (as shown above) that this is
equivalent to the server not processing the received data until after they
generate their new key.

While we could modify this, it would further increase the number of rules 
needed for modelling the post-handshake key update mechanism.

The messages themselves are very simply defined as:
```
define(<!KeyUpdate!>, <!handshake_record('24', update_requested)!>)
define(<!KeyUpdateReply!>, <!handshake_record('24', update_not_requested)!>)
define(<!update_not_requested!>, <!'0'!>)
define(<!update_requested!>, <!'1'!>)
```

To update the keys, the rules take in the old `Send/RecvStream` fact, and
output a new one, with the updated keys. The `KeyUpdate` messages are encrypred
with the old keys, as defined in the specification:
``` 
    [ ...
      SendStream(tid, S, C, prev_app_keys)
    ]
  --[ 
    ...
    ]->
    [ ...
      SendStream(tid, S, C, app_keys),
      Out(senc{KeyUpdate}prev_app_keys)
    ]
```


</div>
</div>