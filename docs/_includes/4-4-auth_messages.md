
<div class="row">
## Authentication Messages
</div>
<div class="row">
<div class="col1">

As discussed in {{protocol-overview}}, TLS generally uses a common
set of messages for authentication, key confirmation, and handshake
integrity: Certificate, CertificateVerify, and Finished.
(The PreSharedKey binders also perform key confirmation, in a
similar fashion.) These three
messages are always sent as the last messages in their handshake
flight. The Certificate and CertificateVerify messages are only
sent under certain circumstances, as defined below. The Finished
message is always sent as part of the Authentication block.
These messages are encrypted under keys derived from
\[sender]_handshake_traffic_secret.

The computations for the Authentication messages all uniformly
take the following inputs:

- The certificate and signing key to be used.
- A Handshake Context consisting of the set of messages to be
  included in the transcript hash.
- A base key to be used to compute a MAC key.
`---snip---`

<!--
Based on these inputs, the messages then contain:

Certificate
: The certificate to be used for authentication, and any
supporting certificates in the chain. Note that certificate-based
client authentication is not available in the 0-RTT case.

CertificateVerify
: A signature over the value Transcript-Hash(Handshake Context, Certificate)

Finished
: A MAC over the value Transcript-Hash(Handshake Context, Certificate, CertificateVerify)
using a MAC key derived from the base key.
{:br}


The following table defines the Handshake Context and MAC Base Key
for each scenario:

| Mode | Handshake Context | Base Key |
|------|-------------------|----------|
| Server | ClientHello ... later of EncryptedExtensions/CertificateRequest | server_handshake_traffic_secret |
| Client | ClientHello ... later of server Finished/EndOfEarlyData | client_handshake_traffic_secret |
| Post-Handshake | ClientHello ... client Finished + CertificateRequest | client_application_traffic_secret_N |


### The Transcript Hash

Many of the cryptographic computations in TLS make use of a transcript
hash. This value is computed by hashing the concatenation of
each included handshake message, including the handshake
message header carrying the handshake message type and length fields,
but not including record layer headers. I.e.,

     Transcript-Hash(M1, M2, ... MN) = Hash(M1 || M2 ... MN)

As an exception to this general rule, when the server responds to a
ClientHello with a HelloRetryRequest, the value of ClientHello1 is
replaced with a special synthetic handshake message of handshake
type "message_hash" containing Hash(ClientHello1). I.e.,

     Transcript-Hash(ClientHello1, HelloRetryRequest, ... MN) =
         Hash(message_hash ||                 // Handshake Type
              00 00 Hash.length ||   // Handshake message length
              Hash(ClientHello1) ||  // Hash of ClientHello1
              HelloRetryRequest ... MN)

The reason for this construction is to allow the server to do a
stateless HelloRetryRequest by storing just the hash of ClientHello1
in the cookie, rather than requiring it to export the entire intermediate
hash state (see {{cookie}}).

For concreteness, the transcript hash is always taken from the
following sequence of handshake messages, starting at the first
ClientHello and including only those messages that were sent:
ClientHello, HelloRetryRequest, ClientHello, ServerHello,
EncryptedExtensions, server CertificateRequest, server Certificate,
server CertificateVerify, server Finished, EndOfEarlyData, client
Certificate, client CertificateVerify, client Finished.

In general, implementations can implement the transcript by keeping a
running transcript hash value based on the negotiated hash. Note,
however, that subsequent post-handshake authentications do not include
each other, just the messages through the end of the main handshake.
-->
</div>
<div class="col2">
The rules in our model which use these messages are:
`server_auth, server_auth_psk, client_auth, client_auth_cert, client_auth_post`
(along with the corresponding `recv_` rules).

We model certificates and the PKI with the `Register_pk` rule:
```
rule Register_pk:
  [ Fr(~ltkA) ]--[ GenLtk($A, ~ltkA), HonestUse(~ltkA)
  ]->
  [ !Ltk($A, ~ltkA), !Pk($A, pk(~ltkA)), Out(pk(~ltkA)) ]
```

This creates: a persistent (i.e. reusable) fact for the long term key
(containing the signing key `~ltkA`); a persistant fact for the long term
key with the publick key `pk(~ltkA)` which can be used for verification; and
finally outputs the public key to the adversary with an `Out` fact.

Note that the adversary is able to use the `Reveal_Ltk` rule to reveal the value
of `~ltkA`. This rule can be seen as either representing the adversary compromising
the long-term key, or alternatively registering the fact that `$A` is a malicious
server.

Signing is captured through the equations: `verify{sign{message, ~ltkA}pk(~ltkA)} = True`.

We assume that the authenticating party simply sends the public key `pk(~ltkA)`
to their peer, and they are able to use the PKI to authenticate that this key
belongs to `$A` by using the `!Pk(...)` fact.

For the Handshake Context, instead of a rolling hash we keep a transcript of all 
the messages, though we could easily compute the hash instead without any impact.

We compute the MAC key as specified later.
</div>
</div>

<div class="row">
###  Certificate
</div>

<div class="row">
<div class="col1">
The server MUST send a Certificate message whenever the agreed-upon
key exchange method uses certificates for authentication (this
includes all key exchange methods defined in this document except PSK).

The client MUST send a Certificate message if and only if the server has
requested client authentication via a CertificateRequest message
({{certificate-request}}). If the server requests client authentication
but no suitable certificate is available, the client
MUST send a Certificate message containing no certificates (i.e., with
the "certificate_list" field having length 0).

Structure of this message:

       struct {
           select(certificate_type){
               case RawPublicKey:
                 // From RFC 7250 ASN.1_subjectPublicKeyInfo
                 opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;

               case X509:
                 opaque cert_data<1..2^24-1>;
           };
           Extension extensions<0..2^16-1>;
       } CertificateEntry;

       struct {
           opaque certificate_request_context<0..2^8-1>;
           CertificateEntry certificate_list<0..2^24-1>;
       } Certificate;

certificate_request_context
: If this message is in response to a CertificateRequest, the
  value of certificate_request_context in that message. Otherwise
  (in the case of server authentication), this field SHALL be zero length.

certificate_list
`---snip---`

<!--
: This is a sequence (chain) of CertificateEntry structures, each
  containing a single certificate and set of extensions. The sender's
  certificate MUST come in the first CertificateEntry in the list.
  Each following certificate SHOULD directly certify one preceding it.
  Because certificate validation requires that trust anchors be distributed
  independently, a certificate that specifies a
  trust anchor MAY be omitted from the chain, provided that
  supported peers are known to possess any omitted certificates.
-->

extensions:
`---snip---`

<!--
: A set of extension values for the CertificateEntry. The "Extension"
  format is defined in {{extensions}}. Valid extensions include
  OCSP Status extensions ({{!RFC6066}} and {{!RFC6961}}) and
  SignedCertificateTimestamps ({{!RFC6962}}).  Any extension presented
  in a Certificate message must only be presented if the corresponding
  ClientHello extension was presented in the initial handshake.
  If an extension applies to the entire chain, it SHOULD be included
  in the first CertificateEntry.
{:br }

Note: Prior to TLS 1.3, "certificate_list" ordering required each certificate
to certify the one immediately preceding it,
however some implementations allowed some flexibility. Servers sometimes send
both a current and deprecated intermediate for transitional purposes, and others
are simply configured incorrectly, but these cases can nonetheless be validated
properly. For maximum compatibility, all implementations SHOULD be prepared to
handle potentially extraneous certificates and arbitrary orderings from any TLS
version, with the exception of the end-entity certificate which MUST be first.

The server's certificate list MUST always be non-empty. A client will
send an empty certificate list if it does not have an appropriate
certificate to send in response to the server's authentication
request.
-->

#### OCSP Status and SCT Extensions

`---snip---`

<!--

{{!RFC6066}} and {{!RFC6961}} provide extensions to negotiate the server
sending OCSP responses to the client. In TLS 1.2 and below, the
server sends an empty extension to indicate negotiation of this
extension and the OCSP information is carried in a CertificateStatus
message. In TLS 1.3, the server's OCSP information is carried in
an extension in the CertificateEntry containing the associated
certificate. Specifically:
The body of the "status_request" or "status_request_v2" extension
from the server MUST be a CertificateStatus structure as defined
in {{RFC6066}} and {{RFC6961}} respectively.

Similarly, {{!RFC6962}} provides a mechanism for a server to send a
Signed Certificate Timestamp (SCT) as an extension in the ServerHello.
In TLS 1.3, the server's SCT information is carried in an extension in
CertificateEntry.

-->

#### Server Certificate Selection

`---snip---`

<!--
The following rules apply to the certificates sent by the server:

- The certificate type MUST be X.509v3 {{RFC5280}}, unless explicitly negotiated
  otherwise (e.g., {{RFC5081}}).

- The server's end-entity certificate's public key (and associated
  restrictions) MUST be compatible with the selected authentication
  algorithm (currently RSA or ECDSA).

- The certificate MUST allow the key to be used for signing (i.e., the
  digitalSignature bit MUST be set if the Key Usage extension is present) with
  a signature scheme indicated in the client's "signature_algorithms" extension.

- The "server_name" and "trusted_ca_keys" extensions {{RFC6066}} are used to
  guide certificate selection. As servers MAY require the presence of the "server_name"
  extension, clients SHOULD send this extension, when applicable.

All certificates provided by the server MUST be signed by a
signature algorithm that appears in the "signature_algorithms"
extension provided by the client, if they are able to provide such
a chain (see {{signature-algorithms}}).
Certificates that are self-signed
or certificates that are expected to be trust anchors are not validated as
part of the chain and therefore MAY be signed with any algorithm.

If the server cannot produce a certificate chain that is signed only via the
indicated supported algorithms, then it SHOULD continue the handshake by sending
the client a certificate chain of its choice that may include algorithms
that are not known to be supported by the client. This fallback chain MAY
use the deprecated SHA-1 hash algorithm only if the "signature_algorithms"
extension provided by the client permits it.
If the client cannot construct an acceptable chain using the provided
certificates and decides to abort the handshake, then it MUST abort the
handshake with an "unsupported_certificate" alert.

If the server has multiple certificates, it chooses one of them based on the
above-mentioned criteria (in addition to other criteria, such as transport
layer endpoint, local configuration and preferences).
-->

#### Client Certificate Selection

`---snip---`

<!--
The following rules apply to certificates sent by the client:

- The certificate type MUST be X.509v3 {{RFC5280}}, unless explicitly negotiated
  otherwise (e.g., {{RFC5081}}).

- If the certificate_authorities list in the certificate request
  message was non-empty, one of the certificates in the certificate
  chain SHOULD be issued by one of the listed CAs.

- The certificates MUST be signed using an acceptable signature
  algorithm, as described in {{certificate-request}}.  Note that this
  relaxes the constraints on certificate-signing algorithms found in
  prior versions of TLS.

- If the certificate_extensions list in the certificate request message
  was non-empty, the end-entity certificate MUST match the extension OIDs
  recognized by the client, as described in {{certificate-request}}.

Note that, as with the server certificate, there are certificates that use
algorithm combinations that cannot be currently used with TLS.
-->
</div>
<div class="col2">

As mentioned in the previous section, we simply model server/client certificates
as a public key, which is authenticated by an abstract representation of the
PKI.

Hence the Certificate message is defined as:
```
define(<!Certificate!>, <!handshake_record('11', certificate_request_context,
 certificate)!>)
```

Where `certificate_request_context` is set to `'0'` when it is not used (i.e.
all cases other that post-handshake client auth), and certificate is set to
`pk(~ltkA)`. This is 'authenticated' using the fact `!Pk($A, pk(~ltkA))` which 
models using the PKI to verify the public key belongs to `$A`.
</div> </div>

<div class="row">
#### Receiving a Certificate Message
</div>
<div class="row">
<div class="col1">
In general, detailed certificate validation procedures are out of scope for
TLS (see {{RFC5280}}). This section provides TLS-specific requirements.

If the server supplies an empty Certificate message, the client MUST abort
the handshake with a "decode_error" alert.

If the client does not send any certificates,
the server MAY at its discretion either continue the handshake without client
authentication, or abort the handshake with a "certificate_required" alert. Also, if some
aspect of the certificate chain was unacceptable (e.g., it was not signed by a
known, trusted CA), the server MAY at its discretion either continue the
handshake (considering the client unauthenticated) or abort the handshake.

`---snip---`

<!--
Any endpoint receiving any certificate signed using any signature algorithm
using an MD5 hash MUST abort the handshake with a "bad_certificate" alert.
SHA-1 is deprecated and it is RECOMMENDED that
any endpoint receiving any certificate signed using any signature algorithm
using a SHA-1 hash abort the handshake with a "bad_certificate" alert.
All endpoints are RECOMMENDED to transition to SHA-256 or better as soon
as possible to maintain interoperability with implementations
currently in the process of phasing out SHA-1 support.

Note that a certificate containing a key for one signature algorithm
MAY be signed using a different signature algorithm (for instance,
an RSA key signed with an ECDSA key).
-->

</div>
<div class="col2">
We do not currently model the scenario in which the client is unable to provide
a certificate to authenticate.
</div>
</div>

<div class="row">
###  Certificate Verify
</div>
<div class="row">
<div class="col1">

This message is used to provide explicit proof that an endpoint
possesses the private key corresponding to its certificate
and also provides integrity for the handshake up
to this point. Servers MUST send this message when
authenticating via a certificate.
Clients MUST send this
message whenever authenticating via a certificate (i.e., when
the Certificate message is non-empty). When sent, this message MUST appear immediately
after the Certificate message and immediately prior to the Finished
message.

Structure of this message:

%%% Authentication Messages

       struct {
           SignatureScheme algorithm;
           opaque signature<0..2^16-1>;
       } CertificateVerify;

The algorithm field specifies the signature algorithm used (see
{{signature-algorithms}} for the definition of this field). The
signature is a digital signature using that algorithm. The
content that is covered under the signature is the hash output as described in
{{authentication-messages}}, namely:

       Transcript-Hash(Handshake Context, Certificate)

`---snip---`

<!--

In TLS 1.3, the digital signature process takes as input:

- A signing key
- A context string
- The actual content to be signed

The digital signature is then computed using the signing key over
the concatenation of:

- A string that consists of octet 32 (0x20) repeated 64 times
- The context string
- A single 0 byte which serves as the separator
- The content to be signed

This structure is intended to prevent an attack on previous versions
of TLS in which the ServerKeyExchange format meant that
attackers could obtain a signature of a message with a chosen, 32-byte
prefix. The initial 64 byte pad clears that prefix.

The context string for a server signature is
"TLS 1.3, server CertificateVerify"
and for a client signature is "TLS 1.3, client
CertificateVerify".

For example, if Hash(Handshake Context + Certificate) was 32 bytes of
01 (this length would make sense for SHA-256), the input to the final
signing process for a server CertificateVerify would be:

       2020202020202020202020202020202020202020202020202020202020202020
       2020202020202020202020202020202020202020202020202020202020202020
       544c5320312e332c207365727665722043657274696669636174655665726966
       79
       00
       0101010101010101010101010101010101010101010101010101010101010101

If sent by a server, the signature algorithm MUST be one offered in the
client's "signature_algorithms" extension unless no valid certificate chain can be
produced without unsupported algorithms (see {{signature-algorithms}}).

If sent by a client, the signature algorithm used in the signature
MUST be one of those present in the supported_signature_algorithms
field of the CertificateRequest message.

In addition, the signature algorithm MUST be compatible with the key
in the sender's end-entity certificate. RSA signatures MUST use an
RSASSA-PSS algorithm, regardless of whether RSASSA-PKCS1-v1_5 algorithms
appear in "signature_algorithms". SHA-1 MUST NOT be used in any signatures in
CertificateVerify. All SHA-1 signature algorithms in this specification are
defined solely for use in legacy certificates, and are not valid for
CertificateVerify signatures.
-->
</div>
<div class="col2">
We compute the (server) signature as:
```
messages = <messages, Certificate>
signature = compute_signature(~ltkS, server)
```
where `compute_signature` expands to:
```
sign{<'TLS13_server_CertificateVerify', h(messages)>}
```

Since `messages` contains the handshake transcript up until that point,
this is valid for Handshake Context. We do not attempt to add the padding prefix
specified in the specification since it would have no purpose given our 
assumption of perfect crypto.

The CertificateVerify message is simply defined as:
```
define(<!CertificateVerify!>, <!handshake_record('15', $sig_alg, signature)!>)
```

We do not currently model using different signing algorithms or their effects on
security.

The peer validates the CertificateVerify message by recomputing the signature
input, and enforcing the action `Eq(verify(signature, sig_messages, pk(~ltkS)), true)`
which makes the trace invalid if the verification fails (implying the peer
terminates the connection if receiving an invalid signature).

Note that an alternative way to model this in Tamarin would be to provide the
peer with the long-term key `~ltkA` and pattern match the signature as an
expected message. While this can (probably) be shown to be equivalent and is
potentially more efficient for Tamarin, we believe using explicit verification
is clearer.

</div> </div>

<div class="row">
###  Finished  
</div>
<div class="row">
<div class="col1">
The Finished message is the final message in the authentication
block. It is essential for providing authentication of the handshake
and of the computed keys.

Recipients of Finished messages MUST verify that the contents are
correct and if incorrect MUST terminate the connection
with a "decrypt_error" alert.

Once a side has sent its Finished message and received and
validated the Finished message from its peer, it may begin to send and
receive application data over the connection.
Early data may be sent prior to the receipt of the peer's Finished
message, per {{early-data-indication}}.

The key used to compute the finished message is computed from the
Base key defined in {{authentication-messages}} using HKDF (see
{{key-schedule}}). Specifically:

~~~
finished_key =
    HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
~~~

Structure of this message:

%%% Authentication Messages

       struct {
           opaque verify_data[Hash.length];
       } Finished;

The verify_data value is computed as follows:

       verify_data =
           HMAC(finished_key,
                Transcript-Hash(Handshake Context,
                                Certificate*, CertificateVerify*))

       * Only included if present.


`---snip---`

<!--

Where HMAC {{RFC2104}} uses the Hash algorithm for the handshake.
As noted above, the HMAC input can generally be implemented by a running
hash, i.e., just the handshake hash at this point.

In previous versions of TLS, the verify_data was always 12 octets long. In
the current version of TLS, it is the size of the HMAC output for the
Hash used for the handshake.

Note: Alerts and any other record types are not handshake messages
and are not included in the hash computations.

Any records following a 1-RTT Finished message MUST be encrypted under the
application traffic key. In particular, this includes any alerts sent by the
server in response to client Certificate and CertificateVerify messages.
-->

</div>
<div class="col2">
The Finished message is modelled as:
```
define(<!Finished!>, <!handshake_record('20', verify_data)!>)
```
where `verify_data` is computed locally (for example in `server_auth`) by:
```
messages = <messages, Certificate>
...
messages = <messages, CertificateVerify>
fin_keys = keygen(handshake_traffic_secret(server), fin_key_label())
verify_data = compute_finished(fin_keys)
```
and `messages` is originally effectively Handshake Context.

Here we use the macros `keygen`, `handshake_traffic_secret`, `fin_key_label`
and `compute_finished` to do the cryptographic processing.

These expand as:
```
fin_keys = HKDF_Expand_Label(BaseKey, finished, '0', '32')
compute_finished = hmac(fin_keys, h(messages))
```
where BaseKey is, in the example given the expansion of the server handshake traffic secret.
</div>
</div>


