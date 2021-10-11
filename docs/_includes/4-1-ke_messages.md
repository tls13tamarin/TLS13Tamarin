

<div class="row">  
## Key Exchange Messages
`---snip---`
</div>

<!-- 
The key exchange messages are used to exchange security capabilities
between the client and server and to establish the traffic keys used to protect
the handshake and data.
 -->

<div class="row">
<div class="col1">
## Cryptographic Negotiation

TLS cryptographic negotiation proceeds by the client offering the
following four sets of options in its ClientHello:

- A list of cipher suites which indicates the AEAD algorithm/HKDF hash
  pairs which the client supports.
- A "supported_groups" ({{negotiated-groups}}) extension which indicates the (EC)DHE groups
  which the client supports and a "key_share" ({{key-share}}) extension which contains
  (EC)DHE shares for some or all of these groups.
- A "signature_algorithms" ({{signature-algorithms}}) extension which indicates the signature
  algorithms which the client can accept.
- A "pre_shared_key" ({{pre-shared-key-extension}}) extension which
  contains a list of symmetric key identities known to the client and a
  "psk_key_exchange_modes" ({{pre-shared-key-exchange-modes}})
  extension which indicates the key exchange modes that may be used
  with PSKs.
If the server does not select a PSK, then the first three of these
options are entirely orthogonal: the server independently selects a
cipher suite, an (EC)DHE group and key share for key establishment,
and a signature algorithm/certificate pair to authenticate itself to
the client. If there is overlap in the "supported_groups" extension
but the client did not offer a compatible "key_share" extension,
then the server will respond with a HelloRetryRequest ({{hello-retry-request}}) message.
If there is no overlap in "supported_groups" then the server MUST
abort the handshake.

If the server selects a PSK, then it MUST also select a key
establishment mode from the set indicated by client's
"psk_key_exchange_modes" extension (PSK alone or with (EC)DHE). Note
that if the PSK can be used without (EC)DHE then non-overlap in the
"supported_groups" parameters need not be fatal, as it is in the
non-PSK case discussed in the previous paragraph.

The server indicates its selected parameters in the ServerHello as
follows:

- If PSK is being used then the server will send a
"pre_shared_key" extension indicating the selected key.
- If PSK is not being used, then (EC)DHE and certificate-based
authentication are always used.
- When (EC)DHE is in use, the server will also provide a
"key_share" extension.
- When authenticating via a certificate (i.e., when a PSK is not
in use), the server will send the Certificate ({{certificate}}) and
CertificateVerify ({{certificate-verify}}) messages.

If the server is unable to negotiate a supported set of parameters
(i.e., there is no overlap between the client and server parameters),
it MUST abort the handshake with either
a "handshake_failure" or "insufficient_security" fatal alert
(see {{alert-protocol}}).
  
</div>
<div class="col2">
We currently support a very limited amount of negotiation. However, this is quite
a large improvement over previous symbolic models.

We support negotiation of handshake modes in the following way:
The client in their initial message can include support for both PSK modes.
The server can optionally choose either of these, or even fall back to a vanilla
handshake.

Furthermore, we do include some support for group negotiation, which is detailed
later.
</div>
</div>

<div class="row">
##  Client Hello
</div>

<div class="row">
<div class="col1">
When a client first connects to a server, it is REQUIRED to send the
ClientHello as its first message. The client will also send a
ClientHello when the server has responded to its ClientHello with a
HelloRetryRequest. In that case, the client MUST send the same
ClientHello (without modification) except:

- If a "key_share" extension was supplied in the HelloRetryRequest,
  replacing the list of shares with a list containing a single
  KeyShareEntry from the indicated group.

- Removing the "early_data" extension ({{early-data-indication}}) if one was
  present. Early data is not permitted after HelloRetryRequest.

- Including a "cookie" extension if one was provided in the
  HelloRetryRequest.

- Updating the "pre_shared_key" extension if present by
  recomputing the "obfuscated_ticket_age" and binder values
  and (optionally) removing
  any PSKs which are incompatible with the server's indicated
  cipher suite.


`---snip---`

<!--
Because TLS 1.3 forbids renegotiation, if a server receives a
ClientHello at any other time, it MUST terminate the connection.

If a server established a TLS connection with a previous version of TLS
and receives a TLS 1.3 ClientHello in a renegotiation, it MUST retain the
previous protocol version. In particular, it MUST NOT negotiate TLS 1.3.
-->
</div>
<div class="col2">
We represent a single instantation of a TLS client using the state fact:
`State(C1, tid, C, S, ClientState)`.
There are actually multiple macros which are unfolded here. First, the 
macro `State(X, ...) = State_X(...)` which is a convenience. By writing rules
which take in specifc state facts, we effectively constrain the state machine
to only follow legal moves. That is, after `client_hello`, the fact `State_C1(...)`
is constructed. This can only be consumed by `hello_retry_request` and `recv_server_hello`
(ignoring PSK variants for now).

The other macro is `ClientState` which
expands to a large tuple of variables, but can thought of as a struct containing all
state variables.

For the HelloRetryRequest scenario, the client sends all the same variables
as previously generated, but removes the "early_data_indication". We
do not currently cover the "cookie" extension.

We cover the specifics of the "key_share" and "pre_shared_key" selection later.

</div> </div>


<div class="row">
<div class="col1">

Structure of this message:

%%% Key Exchange Messages

       uint16 ProtocolVersion;
       opaque Random[32];

       uint8 CipherSuite[2];    /* Cryptographic suite selector */

       struct {
           ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
           Random random;
           opaque legacy_session_id<0..32>;
           CipherSuite cipher_suites<2..2^16-2>;
           opaque legacy_compression_methods<1..2^8-1>;
           Extension extensions<8..2^16-1>;
       } ClientHello;

`---snip---`

<!--
All versions of TLS allow extensions to optionally follow the
compression_methods field as an extensions field.  TLS 1.3
ClientHellos will contain at least two extensions,
"supported_versions" and either "key_share" or "pre_shared_key".  The
presence of extensions can be detected by determining whether there
are bytes following the compression_methods at the end of the
ClientHello. Note that this method of detecting optional data differs
from the normal TLS method of having a variable-length field, but it
is used for compatibility with TLS before extensions were defined.
TLS 1.3 servers will need to perform this check first and only
attempt to negotiate TLS 1.3 if a "supported_version" extension
is present.
-->

legacy_version
`---snip---`

<!--
: In previous versions of TLS, this field was used for version negotiation
  and represented the highest version number supported by the client.
  Experience has shown that many servers do not properly implement
  version negotiation, leading to "version intolerance" in which
  the server rejects an otherwise acceptable ClientHello with a version
  number higher than it supports.
  In TLS 1.3, the client indicates its version preferences in the
  "supported_versions" extension ({{supported-versions}}) and the legacy_version field MUST
  be set to 0x0303, which was the version number for TLS 1.2.
  (See {{backward-compatibility}} for details about backward compatibility.)
-->

</div>
<div class="col2">
We define the `ClientHello` message as a macro defined in the following way:

```
define(<!ProtocolVersion!>, <!'0x0303'!>)
define(<!ClientRandom!>, <!nc!>)
define(<!ClientHello!>, <!handshake_record('1',
  ProtocolVersion,
  ClientRandom,
  '0', // legacy_session_id
  $cipher_suites,
  '0', // legacy_compression_methods
  ClientHelloExtensions 
)!>)
```

where `ClientHelloExtensions` is defined before a specific rule in order to 
contain the relevant extensions.

</div>
</div>

<div class="row">
<div class="col1">
random
: 32 bytes generated by a secure random number generator.
  See {{implementation-notes}} for additional information.
</div>
<div class="col2">
The random value is generated in the `client_hello{_psk}` rules as
a fresh value `Fr(~nc)` which is guaranteed to be unpredictable and
never repeats (unless used maliciously by an adversary).
</div>
</div>


<div class="row">
<div class="col1">


legacy_session_id
`---snip---`

<!-- 
: Versions of TLS before TLS 1.3 supported a session resumption
  feature which has been merged with Pre-Shared Keys in this version
  (see {{resumption-and-psk}}).
  This field MUST be ignored by a server negotiating TLS 1.3 and
  MUST be set as a zero length vector (i.e., a single zero byte
  length field) by clients which do not have a cached session ID
  set by a pre-TLS 1.3 server.
-->

cipher_suites
`---snip---`

<!-- 
: This is a list of the symmetric cipher options supported by the
  client, specifically the record protection algorithm (including
  secret key length) and a hash to be used with HKDF, in descending
  order of client preference. If the list contains cipher suites
  the server does not recognize, support, or wish to use, the server
  MUST ignore those cipher suites, and process the remaining ones as
  usual. Values are defined in {{cipher-suites}}.
-->

legacy_compression_methods
`---snip---`

<!-- 
: Versions of TLS before 1.3 supported compression with the list of
  supported compression methods being sent in this field. For every TLS 1.3
  ClientHello, this vector MUST contain exactly one byte set to
  zero, which corresponds to the "null" compression method in
  prior versions of TLS. If a TLS 1.3 ClientHello is
  received with any other value in this field, the server MUST
  abort the handshake with an "illegal_parameter" alert. Note that TLS 1.3
  servers might receive TLS 1.2 or prior ClientHellos which contain
  other compression methods and MUST follow the procedures for
  the appropriate prior version of TLS.
-->
</div>
<div class="col2">
We do not attempt to model cipher suite negotiation, nor compatability with
older version of TLS and simply set both
`legacy_session_id` and `legacy_compression_methods` to `'0'` 
</div>
</div>

<div class="row">
<div class="col1">
extensions
: Clients request extended functionality from servers by sending
  data in the extensions field.  The actual "Extension" format is
  defined in {{extensions}}.
{:br }

`---snip---`

<!--
In the event that a client requests additional functionality using
extensions, and this functionality is not supplied by the server, the
client MAY abort the handshake. Note that TLS 1.3 ClientHello messages
always contain extensions (minimally they must contain
"supported_versions" or they will be interpreted as TLS 1.2 ClientHello
messages). TLS 1.3 servers may receive TLS 1.2 ClientHello messages
without extensions. If negotiating TLS 1.2, a server MUST check that
the message either contains no data after legacy_compression_methods
or that it contains a valid extensions block with no data following.
If not, then it MUST abort the handshake with a "decode_error" alert.
-->
</div>
<div class="col2">
We cover the extensions in more details later. For the different client hello rules, the
extensions used are:

**`client_hello`**:
```
define(<!ClientHelloExtensions!>, <!<SupportedVersions, NamedGroupList,
 SignatureSchemeList, KeyShareCH >!>)
```
**`client_hello_psk`**:
```
define(<!ClientHelloExtensions!>, <!<
  SupportedVersions,
  NamedGroupList,
  KeyShareCH,
  PskKeyExchangeModes,
  PreSharedKeyExtensionCH,
  EarlyDataIndication
>!>)
```
</div>
</div>


<div class="row">
<div class="col1">
After sending the ClientHello message, the client waits for a ServerHello
or HelloRetryRequest message. If early data
is in use, the client may transmit early application data
{{zero-rtt-data}} while waiting for the next handshake message.
</div>
<div class="col2">
The state `State_C1` is consumed by `recv_hello_retry_request`, `recv_client_hello`, 
`recv_client_hello_psk` and `recv_client_hello_psk_dhe` representing this.
</div>
</div>

<div class="row">
##  Server Hello

`---snip---`

<!--
The server will send this message in response to a ClientHello message when
it was able to find an acceptable set of algorithms and the client's
"key_share" extension was acceptable. If it is not able to find an acceptable
set of parameters, the server will respond with a "handshake_failure" fatal alert.
-->
</div>

<div class="row">
<div class="col1">

Structure of this message:

%%% Key Exchange Messages

       struct {
           ProtocolVersion version;
           Random random;
           CipherSuite cipher_suite;
           Extension extensions<0..2^16-1>;
       } ServerHello;

</div>
<div class="col2">
<br>
```
define(<!ProtocolVersion!>, <!'0x0303'!>)
define(<!ServerRandom!>, <!ns!>)
define(<!ServerHello!>, <!handshake_record('2',
  ProtocolVersion,
  ServerRandom,
  $cipher_suite,
  ServerHelloExtensions
)!>)
```
</div>
</div>

<div class="row">
<div class="col1">
`---snip---`

<!--

version
: This field contains the version of TLS negotiated for this session.  Servers
  MUST select a version from the list in ClientHello.supported_versions extension.
  A client which receives a version that was not offered MUST abort the handshake.
  For this version of the specification, the version is 0x0304.  (See
  {{backward-compatibility}} for details about backward compatibility.)

random
: This structure is generated by the server and MUST be
  generated independently of the ClientHello.random.

cipher_suite
: The single cipher suite selected by the server from the list in
  ClientHello.cipher_suites. A client which receives a cipher suite
  that was not offered MUST abort the handshake.
-->
extensions
: A list of extensions.  The ServerHello MUST only include extensions
  which are required to establish the cryptographic context. Currently
  the only such extensions are "key_share" and "pre_shared_key".
  All current TLS 1.3 ServerHello messages will contain one of these
  two extensions.

`---snip---`

<!--
{:br }

TLS 1.3 has a downgrade protection mechanism embedded in the server's
random value. TLS 1.3 servers which negotiate TLS 1.2 or below in
response to a ClientHello MUST set the last eight bytes of their
Random value specially.

If negotiating TLS 1.2, servers MUST set the last eight bytes of their
Random value to the bytes:

      44 4F 57 4E 47 52 44 01

If negotiating TLS 1.1, TLS 1.3 servers MUST and TLS 1.2 servers SHOULD
set the last eight bytes of their Random value to the bytes:

      44 4F 57 4E 47 52 44 00

TLS 1.3 clients receiving a TLS 1.2 or below ServerHello MUST check
that the last eight octets are not equal to either of these values.
TLS 1.2 clients SHOULD also check that the last eight bytes are not
equal to the second value if the ServerHello indicates TLS 1.1 or
below.  If a match is found, the client MUST abort the handshake
with an "illegal_parameter" alert.  This mechanism provides limited
protection against downgrade attacks over and above that provided
by the Finished exchange: because the ServerKeyExchange, a message
present in TLS 1.2 and below, includes a signature over both random
values, it is not possible for an active attacker to modify the
randoms without detection as long as ephemeral ciphers are used.
It does not provide downgrade protection when static RSA is used.

Note: This is an update to TLS 1.2 so in practice many TLS 1.2 clients
and servers will not behave as specified above.

A client that receives a TLS 1.3 ServerHello during renegotiation
MUST abort the handshake with a "protocol_version" alert.

RFC EDITOR: PLEASE REMOVE THE FOLLOWING PARAGRAPH
Implementations of draft versions (see {{draft-version-indicator}}) of this
specification SHOULD NOT implement this mechanism on either client and server.
A pre-RFC client connecting to RFC servers, or vice versa, will appear to
downgrade to TLS 1.2. With the mechanism enabled, this will cause an
interoperability failure.
-->
</div>
<div class="col2">
The ServerHello message behaves similarly to the ClientHello message. As before, 
we cover the extensions in more detail later. The Extensions sent are:

**`server_hello`**:

```define(<!ServerHelloExtensions!>, <!<SignatureSchemeList, KeyShareSH>!>)```

**`server_hello_psk_dhe`**:
```
define(<!ServerHelloExtensions!>, <!<
  SignatureSchemeList,
  KeyShareSH,
  PreSharedKeyExtensionSH,
  EarlyDataIndication
>!>)
```

**`server_hello_psk`**:
```
define(<!ServerHelloExtensions!>, <!<
  SignatureSchemeList,
  PreSharedKeyExtensionSH,
  EarlyDataIndication
>!>)
```
</div>
</div>

<div class="row">
##  Hello Retry Request
</div>
<div class="row">
<div class="col1">

The server will send this message in response to a ClientHello message if it is
able to find an acceptable set of parameters but the ClientHello does not
contain sufficient information to proceed with the handshake.

Structure of this message:

%%% Key Exchange Messages

       struct {
           ProtocolVersion server_version;
           CipherSuite cipher_suite;
           Extension extensions<2..2^16-1>;
       } HelloRetryRequest;

{:br }

The version, cipher_suite, and extensions fields have the
same meanings as their corresponding values in the ServerHello.
The server SHOULD send only the extensions necessary for the client to
generate a correct ClientHello pair. As with ServerHello, a
HelloRetryRequest MUST NOT contain any extensions that were not first
offered by the client in its ClientHello, with the exception of optionally the
"cookie" (see {{cookie}}) extension.

Upon receipt of a HelloRetryRequest, the client MUST verify that the
extensions block is not empty and otherwise MUST abort the handshake
with a "decode_error" alert. Clients MUST abort the handshake with
an "illegal_parameter" alert if the HelloRetryRequest would not result in
any change in the ClientHello. If a client receives a second
HelloRetryRequest in the same connection (i.e., where
the ClientHello was itself in response to a HelloRetryRequest), it
MUST abort the handshake with an "unexpected_message" alert.

Otherwise, the client MUST process all extensions in the HelloRetryRequest and
send a second updated ClientHello. The HelloRetryRequest extensions defined in
this specification are:

- cookie (see {{cookie}})

- key_share (see {{key-share}})

In addition, in its updated ClientHello, the client SHOULD NOT offer
any pre-shared keys associated with a hash other than that of the
selected cipher suite. This allows the client to avoid having to
compute partial hash transcripts for multiple hashes in the second
ClientHello.  A client which receives a cipher suite that was not
offered MUST abort the handshake.  Servers MUST ensure that they
negotiate the same cipher suite when receiving a conformant updated
ClientHello (if the server selects the cipher suite as the first step
in the negotiation, then this will happen automatically). Upon
receiving the ServerHello, clients MUST check that the cipher suite
supplied in the ServerHello is the same as that in the
HelloRetryRequest and otherwise abort the handshake with an
"illegal_parameter" alert.
</div>
<div class="col2">
Capturing this process is one of the trickier aspects of the model. Currently, 
it does not seem feasible to have a selection process wherein the server takes
two lists and outputs a selected group, or reject. Instead we model the following
limited version of group negotiation:

```
   Client                        Server
supports g1, g2               supports g

<g1, g2>, <g1, g1^x> ---->  if g != g1

                    <----- HRR <g>

checks g2 == g 
<g1, g2>, <g2, g2^x2> ---->  checks g == g2

```

That is, the client *always* sends two groups as supported, and the server checks
whether the provided key share `g1^x` is in the supported group `g`.

If not, the server responds with `g` in  a hello retry request. The client makes
sure this is equal to the other group, `g2`, and sends a new client hello.

At the start of the model, `g1, g2`, and `g` are not restricted (they are modelled
as public variables `$g1`). And the server does not necessarily know that the client
sends the same groups in both handshakes. This is an overapproximation which guarantees the 
following:
 - If the server reaches `server_hello` then the server has negotiated a
   supported group (so `$g` is either `$g1` or `$g2`)
 - The server only does HRR if `$g != $g1'
 - The server only does HRR once.

The above three guarantee that the client must have offered `$g` as a supported
group with a key share entry either in the first flight, or the retry.

The message is defined as:
```

define(<!HelloRetryRequest!>, <!handshake_record('6',
    ProtocolVersion,
    HelloRetryRequestExtensions
)!>)
``` 
where extensions are defined as:

**`hello_retry_request`**:
```
define(<!HelloRetryRequestExtensions!>, <!<KeyShareHRR>!>)
```

**`hello_retry_request_psk`**:
```
define(<!HelloRetryRequestExtensions!>, <!<KeyShareHRR>!>)
```

We do not currently support the `Cookie` extension, nor the server storing
state using this extension.
</div>
</div>
