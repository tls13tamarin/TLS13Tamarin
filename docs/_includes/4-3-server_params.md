<div class="row">
## Server Parameters
`---snip---`

<!--
The next two messages from the server, EncryptedExtensions and
CertificateRequest, contain encrypted information from the server
that determines the rest of the handshake.
-->
</div>

<div class="row">
###  Encrypted Extensions
</div>

<div class="row">
<div class="col1">

In all handshakes, the server MUST send the
EncryptedExtensions message immediately after the
ServerHello message. This is the first message that is encrypted
under keys derived from the server_handshake_traffic_secret.

`---snip---`

<!--
The EncryptedExtensions message contains extensions
that can be protected, i.e., any which are not needed to
establish the cryptographic context, but which are not
associated with individual certificates. The client
MUST check EncryptedExtensions for the presence of any forbidden
extensions and if any are found MUST abort the handshake with an
"illegal_parameter" alert.
-->

Structure of this message:

%%% Server Parameters Messages

       struct {
           Extension extensions<0..2^16-1>;
       } EncryptedExtensions;

extensions
: A list of extensions. For more information, see the table in {{extensions}}.
{:br }

</div>
<div class="col2">
We do not attempt to model any additional extensions, so the `EncryptedExtensions`
message is simply:
```
define(<!EncryptedExtensions!>, <!handshake_record('8', $exts)!>)
```

As far as we are concerned, the extensions is just some blob of data which
is protected under the handshake keys and included in the transcript.
</div>
</div>

<div class="row">
###  Certificate Request
</div>
<div class="row">
<div class="col1">

A server which is authenticating with a certificate MAY optionally
request a certificate from the client. This message, if sent, MUST
follow EncryptedExtensions.

Structure of this message:

%%% Server Parameters Messages

       struct {
           opaque certificate_request_context<0..2^8-1>;
           Extension extensions<2..2^16-1>;
       } CertificateRequest;

certificate_request_context
: An opaque string which identifies the certificate request and
  which will be echoed in the client's Certificate message. The
  certificate_request_context MUST be unique within the scope
  of this connection (thus preventing replay of client
  CertificateVerify messages). This field SHALL be zero length
  unless used for the post-handshake authentication exchanges
  described in {{post-handshake-authentication}}.
  When requesting post-handshake authentication, the server SHOULD
  make the context unpredictable to the client (e.g., by
  randomly generating it) in order to prevent an attacker who
  has temporary access to the client's private key from
  pre-computing valid CertificateVerify messages.

extensions
: A set of extensions describing the parameters of the
  certificate being requested. The "signature_algorithms"
  extension MUST be specified, and other extensions may optionally be
  included if defined for this message.
  Clients MUST ignore unrecognized extensions.
{:br}

`---snip---`

<!--
In prior versions of TLS, the CertificateRequest message
carried a list of signature algorithms and certificate authorities
which the server would accept. In TLS 1.3 the former is expressed
by sending the "signature_algorithms" extension. The latter is
expressed by sending the "certificate_authorities" extension
(see {{certificate-authorities}}).

Servers which are authenticating with a PSK MUST NOT send the
CertificateRequest message in the main handshake, though they
MAY send it in post-handshake authentication (see {{post-handshake-authentication}})
provided that the client has sent the "post_handshake_auth"
extension (see {{post_handshake_auth}}).


#### OID Filters

The "oid_filters" extension allows servers to provide a set of OID/value
pairs which it would like the client's certificate to match. This
extension MUST only be sent in the CertificateRequest message.

%%% Server Parameters Messages

       struct {
           opaque certificate_extension_oid<1..2^8-1>;
           opaque certificate_extension_values<0..2^16-1>;
       } OIDFilter;

       struct {
           OIDFilter filters<0..2^16-1>;
       } OIDFilterExtension;


filters
: A list of certificate extension OIDs {{RFC5280}} with their allowed
  values, represented in DER-encoded {{X690}} format. Some certificate
  extension OIDs allow multiple values (e.g., Extended Key Usage).
  If the server has included a non-empty certificate_extensions list,
  the client certificate included in the response
  MUST contain all of the specified extension
  OIDs that the client recognizes. For each extension OID recognized
  by the client, all of the specified values MUST be present in the
  client certificate (but the certificate MAY have other values as
  well). However, the client MUST ignore and skip any unrecognized
  certificate extension OIDs. If the client ignored some of the
  required certificate extension OIDs and supplied a certificate
  that does not satisfy the request, the server MAY at its discretion
  either continue the connection without client authentication, or
  abort the handshake with an "unsupported_certificate" alert.

  PKIX RFCs define a variety of certificate extension OIDs and their
  corresponding value types. Depending on the type, matching
  certificate extension values are not necessarily bitwise-equal. It
  is expected that TLS implementations will rely on their PKI
  libraries to perform certificate selection using certificate
  extension OIDs.

  This document defines matching rules for two standard certificate
  extensions defined in {{RFC5280}}:

  - The Key Usage extension in a certificate matches the request when
  all key usage bits asserted in the request are also asserted in the
  Key Usage certificate extension.

  - The Extended Key Usage extension in a certificate matches the
  request when all key purpose OIDs present in the request are also
  found in the Extended Key Usage certificate extension. The special
  anyExtendedKeyUsage OID MUST NOT be used in the request.

  Separate specifications may define matching rules for other certificate
  extensions.
{:br }
-->
</div>
<div class="col2">

The `CertificateRequest` message is optionally sent by the server, and only when
*not* in PSK mode. This choice is covered by two rules:
`certificate_request` and `skip_certificate_request`.

When `certificate_request` is used, the server sets the "bit" for `auth_req` to
`'1'`, which matches with the later rule `recv_client_auth_cert` reflecting that
the server will expect a certificate. Similarly, `skip_certificate_request` leaves
the bit as `'0'` and matches with the regular `client_auth` rule which just expects
the client `Finished` message.

We define the `CertificateRequest` message as:
```
define(<!CertificateRequest!>, <! handshake_record('13',
  certificate_request_context,
  $certificate_extensions
)!>)
```


That is, the `certificate_request_context` is a free variable which is to be
set locally. The extensions we simply leave as public variables and 
do not model any other certificate extension mechanism.

As stated in the specification, the `certificate_request_context` value is zero-
length except for in post-handshake authentication. Therefore, we set this
variable to `'0'` in both server and client rules (the latter reflecting that
the client only continues if they receive a zero value).

</div> </div>
