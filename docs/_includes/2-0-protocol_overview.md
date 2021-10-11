

<div class="row">
<div class="col1">


TLS supports three basic key exchange modes:

- (EC)DHE (Diffie-Hellman both the finite field and elliptic curve
  varieties),

- PSK-only, and

- PSK with (EC)DHE

{{tls-full}} below shows the basic full TLS handshake:

~~~
       Client                                               Server

Key  ^ ClientHello
Exch | + key_share*
     | + signature_algorithms*
     | + psk_key_exchange_modes*
     v + pre_shared_key*         -------->
                                                       ServerHello  ^ Key
                                                      + key_share*  | Exch
                                                 + pre_shared_key*  v
                                             {EncryptedExtensions}  ^  Server
                                             {CertificateRequest*}  v  Params
                                                    {Certificate*}  ^
                                              {CertificateVerify*}  | Auth
                                                        {Finished}  v
                                 <--------     [Application Data*]
     ^ {Certificate*}
Auth | {CertificateVerify*}
     v {Finished}                -------->
       [Application Data]        <------->      [Application Data]

              +  Indicates noteworthy extensions sent in the
                 previously noted message.

              *  Indicates optional or situation-dependent
                 messages/extensions that are not always sent.

              {} Indicates messages protected using keys
                 derived from a [sender]_handshake_traffic_secret.

              [] Indicates messages protected using keys
                 derived from [sender]_application_traffic_secret_N
~~~
{: #tls-full title="Message flow for full TLS Handshake"}

`---snip---`

<!--
```

The handshake can be thought of as having three phases (indicated
in the diagram above):

- Key Exchange: Establish shared keying material and select the
   cryptographic parameters. Everything after this phase is
   encrypted.

- Server Parameters: Establish other handshake parameters
   (whether the client is authenticated, application layer protocol support, etc.).

- Authentication: Authenticate the server (and optionally the client)
   and provide key confirmation and handshake integrity.

In the Key Exchange phase, the client sends the ClientHello
({{client-hello}}) message, which contains a random nonce
(ClientHello.random); its offered protocol versions; a list of
symmetric cipher/HKDF hash pairs; some set of Diffie-Hellman key shares (in the
"key_share" extension {{key-share}}), a set of pre-shared key labels (in the
"pre_shared_key" extension {{pre-shared-key-extension}}) or both; and
potentially some other extensions.

The server processes the ClientHello and determines the appropriate
cryptographic parameters for the connection. It then responds with its
own ServerHello, which indicates the negotiated connection
parameters. [{{server-hello}}]. The combination of the ClientHello
and the ServerHello determines the shared keys. If (EC)DHE
key establishment is in use, then the ServerHello
contains a "key_share" extension with the server's ephemeral
Diffie-Hellman share which MUST be in the same group as one of the
client's shares. If PSK key establishment is
in use, then the ServerHello contains a "pre_shared_key"
extension indicating which of the client's offered PSKs was selected.
Note that implementations can use (EC)DHE and PSK together, in which
case both extensions will be supplied.

The server then sends two messages to establish the Server Parameters:

EncryptedExtensions:
: responses to any extensions that are not required to
  determine the cryptographic parameters, other than those
  that are specific to individual certificates. [{{encrypted-extensions}}]

CertificateRequest:
: if certificate-based client authentication is desired, the
  desired parameters for that certificate. This message is
  omitted if client authentication is not desired. [{{certificate-request}}]

Finally, the client and server exchange Authentication messages. TLS
uses the same set of messages every time that authentication is needed.
Specifically:

Certificate:
: the certificate of the endpoint and any per-certificate extensions.
  This message is omitted by the server if not authenticating with a
  certificate and by the client if the server did not send
  CertificateRequest (thus indicating that the client should not
  authenticate with a certificate). Note that if raw
  public keys {{RFC7250}} or the cached information extension
  {{?RFC7924}} are in use, then this message will not
  contain a certificate but rather some other value corresponding to
  the server's long-term key.  [{{certificate}}]

CertificateVerify:
: a signature over the entire handshake using the private key
  corresponding to the public key in the Certificate message. This
  message is omitted if the endpoint is not authenticating via a
  certificate. [{{certificate-verify}}]

Finished:
: a MAC (Message Authentication Code) over the entire handshake.
  This message provides key confirmation, binds the endpoint's identity
  to the exchanged keys, and in PSK mode
  also authenticates the handshake. [{{finished}}]
{:br }
-->
</div>
<div class="col2">

We model the different phases, options and message flights through a series of 
rule invocations. The basic full handshake is captured by this state machine
diagram:

<a target="_blank" href="img/state_machines.png">
<img src="img/state_machines.png" title="Click to view full screen image in new tab"
alt="State machine diagram" style="width: 100%;"/>
</a>

For example, we see that a PSK-only handshake is captured through the invocation
of the rules `client_hello_psk -> recv_client_hello_psk -> server_hello_psk -> ...`
for the PSK-DHE handshake, the rule `server_hello_psk_dhe` would be used instead.

We associate with each handshake *message* (i.e. not necessarily each flight)
a distinct rule, to help separate concerns.

</div>
</div>
<div class="row">
<div class="col1">
Upon receiving the server's messages, the client responds with its Authentication
messages, namely Certificate and CertificateVerify (if requested), and Finished.

At this point, the handshake is complete, and the client and server may exchange
application-layer data. Application data MUST NOT be sent prior to sending the
Finished message. Note that while the server may send application data
prior to receiving the client's Authentication messages, any data sent at
that point is, of course, being sent to an unauthenticated peer.
</div>
<div class="col2">
In Tamarin, we model the application data using the `SendStream` and `RecvStream`
facts. These are output as indicated on the diagram, after the `Finished` messages
have been sent.
</div>
</div>