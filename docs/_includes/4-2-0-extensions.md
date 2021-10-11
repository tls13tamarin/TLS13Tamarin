
<div class="row">
##  Extensions  
</div>

<div class="row">
<div class="col1">
A number of TLS messages contain tag-length-value encoded extensions structures.

%%% Key Exchange Messages

       struct {
           ExtensionType extension_type;
           opaque extension_data<0..2^16-1>;
       } Extension;

       enum {
           server_name(0),                             /* RFC 6066 */
           max_fragment_length(1),                     /* RFC 6066 */
           status_request(5),                          /* RFC 6066 */
           supported_groups(10),                       /* RFC 4492, 7919 */
           signature_algorithms(13),                   /* RFC 5246 */
           use_srtp(14),                               /* RFC 5764 */
           heartbeat(15),                              /* RFC 6520 */
           application_layer_protocol_negotiation(16), /* RFC 7301 */
           signed_certificate_timestamp(18),           /* RFC 6962 */
           client_certificate_type(19),                /* RFC 7250 */
           server_certificate_type(20),                /* RFC 7250 */
           padding(21),                                /* RFC 7685 */
           key_share(40),                              /* [[this document]] */
           pre_shared_key(41),                         /* [[this document]] */
           early_data(42),                             /* [[this document]] */
           supported_versions(43),                     /* [[this document]] */
           cookie(44),                                 /* [[this document]] */
           psk_key_exchange_modes(45),                 /* [[this document]] */
           certificate_authorities(47),                /* [[this document]] */
           oid_filters(48),                            /* [[this document]] */
           post_handshake_auth(49),                    /* [[this document]] */
           (65535)
       } ExtensionType;

Here:

-  "extension_type" identifies the particular extension type.

-  "extension_data" contains information specific to the particular
  extension type.

The list of extension types is maintained by IANA as described in
{{iana-considerations}}.

</div>
<div class="col2">
Similarly, we define extensions using the macro `Extension` which simply
expands to a list, `Extension('10', client_sg) = <'10', client_sg>` for the
support groups for example.
</div>
</div>

<div class="row">
<div class="col1">

Extensions are generally structured in a request/response fashion, though
some extensions are just indications with no corresponding response. The client
sends its extension requests in the ClientHello message and the server sends
its extension responses in the ServerHello, EncryptedExtensions,
HelloRetryRequest and Certificate messages. The server sends extension requests
in the CertificateRequest message which a client MAY respond to with
a Certificate message. The server MAY also send unsolicited
extensions in the NewSessionTicket, though the client does not respond
directly to these.

`---snip---`

<!--
Implementations MUST NOT send extension responses
if the remote endpoint did not send the corresponding extension requests,
with the exception of the "cookie" extension in HelloRetryRequest.
Upon receiving such an extension, an endpoint MUST abort the handshake with an
"unsupported_extension" alert.

The table below indicates the messages where a given extension may
appear, using the following notation: CH (ClientHello), SH
(ServerHello), EE (EncryptedExtensions), CT (Certificate), CR
(CertificateRequest), NST (NewSessionTicket) and HRR
(HelloRetryRequest). If an implementation receives an extension which
it recognizes and which is not specified for the message in which it
appears it MUST abort the handshake with an "illegal_parameter" alert.

| Extension                                |   TLS 1.3   |
|:-----------------------------------------|------------:|
| server_name [RFC6066]                    |      CH, EE |
| max_fragment_length [RFC6066]            |      CH, EE |
| status_request [RFC6066]                 |  CH, CR, CT |
| supported_groups [RFC7919]               |      CH, EE |
| signature_algorithms [RFC5246]           |      CH, CR |
| use_srtp [RFC5764]                       |      CH, EE |
| heartbeat [RFC6520]                      |      CH, EE |
| application_layer_protocol_negotiation [RFC7301]|      CH, EE |
| signed_certificate_timestamp [RFC6962]   |  CH, CR, CT |
| client_certificate_type [RFC7250]        |      CH, EE |
| server_certificate_type [RFC7250]        |      CH, CT |
| padding [RFC7685]                        |          CH |
| key_share \[\[this document]]            | CH, SH, HRR |
| pre_shared_key \[\[this document]]       |      CH, SH |
| psk_key_exchange_modes \[\[this document]]|          CH |
| early_data \[\[this document]]           | CH, EE, NST |
| cookie \[\[this document]]               |     CH, HRR |
| supported_versions \[\[this document]]   |          CH |
| certificate_authorities \[\[this document]]|      CH, CR |
| oid_filters \[\[this document]]          |          CR |
| post_handshake_auth \[\[this document]]  |          CH |

When multiple extensions of different types are present, the
extensions MAY appear in any order, with the exception of
"pre_shared_key" {{pre-shared-key-extension}} which MUST be
the last extension in the ClientHello.
There MUST NOT be more than one extension of the same type in a given
extension block.

In TLS 1.3, unlike TLS 1.2, extensions are renegotiated with each
handshake even when in resumption-PSK mode. However, 0-RTT parameters are
those negotiated in the previous handshake; mismatches may require
rejecting 0-RTT (see {{early-data-indication}}).

There are subtle (and not so subtle) interactions that may occur in this
protocol between new features and existing features which may result in a
significant reduction in overall security. The following considerations should
be taken into account when designing new extensions:

- Some cases where a server does not agree to an extension are error
  conditions, and some are simply refusals to support particular features. In
  general, error alerts should be used for the former, and a field in the
  server extension response for the latter.

- Extensions should, as far as possible, be designed to prevent any attack that
  forces use (or non-use) of a particular feature by manipulation of handshake
  messages. This principle should be followed regardless of whether the feature
  is believed to cause a security problem.
  Often the fact that the extension fields are included in the inputs to the
  Finished message hashes will be sufficient, but extreme care is needed when
  the extension changes the meaning of messages sent in the handshake phase.
  Designers and implementors should be aware of the fact that until the
  handshake has been authenticated, active attackers can modify messages and
  insert, remove, or replace extensions.

-->
</div>
<div class="col2">
We model this text directly; the client and server only send a specific set
of extensions/messages. Note that actions such as "aborting the handshake"
are effectively modelled by the obvservation that no subsequent client/server
rules can be used. We do not explicitly model sending alert messages.
</div>
</div>

<div class="row">
###  Supported Versions
</div>
<div class="row">
<div class="col1">

%%% Version Extension

       struct {
           ProtocolVersion versions<2..254>;
       } SupportedVersions;

`---snip---`

<!--
The "supported_versions" extension is used by the client to indicate
which versions of TLS it supports. The extension contains a list of
supported versions in preference order, with the most preferred
version first. Implementations of this specification MUST send this
extension containing all versions of TLS which they are
prepared to negotiate (for this specification, that means minimally
0x0304, but if previous versions of TLS are supported, they MUST
be present as well).

If this extension is not present, servers which are compliant with
this specification MUST negotiate TLS 1.2 or prior as specified in
{{RFC5246}}, even if ClientHello.legacy_version is 0x0304 or later.

If this extension is present, servers MUST ignore the
ClientHello.legacy_version value and MUST use only the
"supported_versions" extension to determine client
preferences. Servers MUST only select a version of TLS present in that
extension and MUST ignore any unknown versions. Note that this
mechanism makes it possible to negotiate a version prior to TLS 1.2 if
one side supports a sparse range. Implementations of TLS 1.3 which choose
to support prior versions of TLS SHOULD support TLS 1.2.

The server MUST NOT send the "supported_versions" extension. The
server's selected version is contained in the ServerHello.version field as
in previous versions of TLS.

#### Draft Version Indicator

RFC EDITOR: PLEASE REMOVE THIS SECTION

While the eventual version indicator for the RFC version of TLS 1.3 will
be 0x0304, implementations of draft versions of this specification SHOULD
instead advertise 0x7f00 | draft_version
in ServerHello.version, and HelloRetryRequest.server_version.
For instance, draft-17 would be encoded as the 0x7f11.
This allows pre-RFC implementations to safely negotiate with each other,
even if they would otherwise be incompatible.

-->
</div>
<div class="col2">
```
define(<!SupportedVersions!>, <!Extension('43', '0x0304')!>)
```

We do not attempt to model the interaction between different specifications, nor
downgrade protection.
</div>
</div>

<div class="row">
<div class="col1">


###  Cookie

%%% Cookie Extension

       struct {
           opaque cookie<1..2^16-1>;
       } Cookie;

Cookies serve two primary purposes:

- Allowing the server to force the client to demonstrate reachability
  at their apparent network address (thus providing a measure of DoS
  protection). This is primarily useful for non-connection-oriented
  transports (see {{?RFC6347}} for an example of this).

- Allowing the server to offload state to the client, thus allowing it to send
  a HelloRetryRequest without storing any state. The server can do this by
  storing the hash of the ClientHello in the HelloRetryRequest cookie
  (protected with some suitable integrity algorithm).

When sending a HelloRetryRequest, the server MAY provide a "cookie" extension to the
client (this is an exception to the usual rule that the only extensions that
may be sent are those that appear in the ClientHello). When sending the
new ClientHello, the client MUST copy the contents of the extension received in
the HelloRetryRequest into a "cookie" extension in the new ClientHello.
Clients MUST NOT use cookies in subsequent connections.


</div>
<div class="col2">
Currently we do not make use of the `Cookie` extension for either of these 
purposes. It might be an interesting extension of this work to verify that
offloading state through the cookie is safe.
</div>
</div>

<div class="row">
###  Signature Algorithms  
</div>
<div class="row">
<div class="col1">
The client uses the "signature_algorithms" extension to indicate to the server
which signature algorithms may be used in digital signatures. Clients which
desire the server to authenticate itself via a certificate MUST send this extension.

`---snip---`

<!--
If a server
is authenticating via a certificate and the client has not sent a
"signature_algorithms" extension then the server MUST
abort the handshake with a "missing_extension" alert
(see {{mti-extensions}}).
-->

The "extension_data" field of this extension in a ClientHello contains a
SignatureSchemeList value:


%%% Signature Algorithm Extension

       enum {
       ---snip---
       } SignatureScheme;

       struct {
           SignatureScheme supported_signature_algorithms<2..2^16-2>;
       } SignatureSchemeList;

`---snip---`

<!--
Note: This enum is named "SignatureScheme" because there is already
a "SignatureAlgorithm" type in TLS 1.2, which this replaces.
We use the term "signature algorithm" throughout the text.

Each SignatureScheme value lists a single signature algorithm that the
client is willing to verify. The values are indicated in descending order
of preference. Note that a signature algorithm takes as input an
arbitrary-length message, rather than a digest. Algorithms which
traditionally act on a digest should be defined in TLS to first
hash the input with a specified hash algorithm and then proceed as usual.
The code point groups listed above have the following meanings:

RSASSA-PKCS1-v1_5 algorithms
: Indicates a signature algorithm using RSASSA-PKCS1-v1_5 {{RFC3447}}
  with the corresponding hash algorithm as defined in {{SHS}}. These values
  refer solely to signatures which appear in certificates (see
  {{server-certificate-selection}}) and are not defined for use in signed
  TLS handshake messages.

ECDSA algorithms
: Indicates a signature algorithm using ECDSA {{ECDSA}}, the corresponding
  curve as defined in ANSI X9.62 {{X962}} and FIPS 186-4 {{DSS}}, and the
  corresponding hash algorithm as defined in {{SHS}}. The signature is
  represented as a DER-encoded {{X690}} ECDSA-Sig-Value structure.

RSASSA-PSS algorithms
: Indicates a signature algorithm using RSASSA-PSS {{RFC3447}} with MGF1. The
  digest used in the mask generation function and the digest being signed are
  both the corresponding hash algorithm as defined in {{SHS}}. When used in
  signed TLS handshake messages, the length of the salt MUST be equal to the
  length of the digest output.  This codepoint is defined for use with TLS 1.2
  as well as TLS 1.3.

EdDSA algorithms
: Indicates a signature algorithm using EdDSA as defined in
  {{I-D.irtf-cfrg-eddsa}} or its successors. Note that these correspond to the
  "PureEdDSA" algorithms and not the "prehash" variants.
{:br }

rsa_pkcs1_sha1, dsa_sha1, and ecdsa_sha1 SHOULD NOT be offered. Clients
offering these values for backwards compatibility MUST list them as the lowest
priority (listed after all other algorithms in SignatureSchemeList).
TLS 1.3 servers MUST NOT offer a SHA-1
signed certificate unless no valid certificate chain can be produced without it
(see {{server-certificate-selection}}).

The signatures on certificates that are self-signed or certificates that are
trust anchors are not validated since they begin a certification path (see
{{RFC5280}}, Section 3.2).  A certificate that begins a certification
path MAY use a signature algorithm that is not advertised as being supported
in the "signature_algorithms" extension.

Note that TLS 1.2 defines this extension differently. TLS 1.3 implementations
willing to negotiate TLS 1.2 MUST behave in accordance with the requirements of
{{RFC5246}} when negotiating that version. In particular:

* TLS 1.2 ClientHellos MAY omit this extension.

* In TLS 1.2, the extension contained hash/signature pairs. The pairs are
  encoded in two octets, so SignatureScheme values have been allocated to
  align with TLS 1.2's encoding. Some legacy pairs are left unallocated. These
  algorithms are deprecated as of TLS 1.3. They MUST NOT be offered or
  negotiated by any implementation. In particular, MD5 {{SLOTH}} and SHA-224
  MUST NOT be used.

* ECDSA signature schemes align with TLS 1.2's ECDSA hash/signature pairs.
  However, the old semantics did not constrain the signing curve.  If TLS 1.2 is
  negotiated, implementations MUST be prepared to accept a signature that uses
  any curve that they advertised in the "supported_groups" extension.

* Implementations that advertise support for RSASSA-PSS (which is mandatory in
  TLS 1.3), MUST be prepared to accept a signature using that scheme even when
  TLS 1.2 is negotiated. In TLS 1.2, RSASSA-PSS is used with RSA cipher suites.
-->
</div>
<div class="col2">
Due to our assumption of "perfect crypto" much of this extension is irrelevant.
We simply model the offered list as some public knowledge parameter:
```define(<!SignatureSchemeList!>, <!Extension('13', $sig_algs)!>)```
and validate the integrity of those algorithms in the transcript.
</div>
</div>


<div class="row">
#### Certificate Authorities
</div>
<div class="row">
<div class="col1">
`--snip---`

<!--

The "certificate_authorities" extension is used to indicate the
certificate authorities which an endpoint supports and which SHOULD
be used by the receiving endpoint to guide certificate selection.

The body of the "certificate_authorities" extension consists of a
CertificateAuthoritiesExtension structure.

%%% Server Parameters Messages

       opaque DistinguishedName<1..2^16-1>;

       struct {
           DistinguishedName authorities<3..2^16-1>;
       } CertificateAuthoritiesExtension;

authorities
: A list of the distinguished names {{X501}} of acceptable
  certificate authorities, represented in DER-encoded {{X690}} format.  These
  distinguished names specify a desired distinguished name for a
  root CA or for a subordinate CA; thus, this message can be used to
  describe known roots as well as a desired authorization space.
{:br}

The client MAY send the "certificate_authorities" extension in the ClientHello
message. The server MAY send it in the CertificateRequest message.

The "trusted_ca_keys" extension, which serves a similar
purpose {{RFC6066}}, but is more complicated, is not used in TLS 1.3
(although it may appear in ClientHello messages from clients which are
offering prior versions of TLS).
-->
</div>
<div class="col2">
We do not model the certificate authorities extension.
</div>
</div>

<div class="row">
### Post-Handshake Client Authentication {#post_handshake_auth}
</div>
<div class="row">
<div class="col1">
The "post_handshake_auth" extension is used to indicate that a client is willing
to perform post-handshake authentication {{post-handshake-authentication}}. Servers
MUST not send a post-handshake CertificateRequest to clients which do not
offer this extension. Servers MUST NOT send this extension.

The "extension_data" field of the "post_handshake_auth" extension is zero
length.
</div>
<div class="col2">
We will add this in future work. As with many of our extensions, we will model
this as always being supported by the client, so the impact of adding this
will be negligible.
</div>
</div>


<div class="row">
### Negotiated Groups
</div>
<div class="row">
<div class="col1">

When sent by the client, the "supported_groups" extension indicates
the named groups which the client supports for key exchange, ordered
from most preferred to least preferred.

`--snip---`

<!--

Note: In versions of TLS prior to TLS 1.3, this extension was named
"elliptic_curves" and only contained elliptic curve groups. See {{RFC4492}} and
{{RFC7919}}. This extension was also used to negotiate
ECDSA curves. Signature algorithms are now negotiated independently (see
{{signature-algorithms}}).
-->

The "extension_data" field of this extension contains a
"NamedGroupList" value:

%%% Supported Groups Extension

       enum {
           ---snip---
       } NamedGroup;

       struct {
           NamedGroup named_group_list<2..2^16-1>;
       } NamedGroupList;

`---snip---`

<!--
Elliptic Curve Groups (ECDHE)
: Indicates support of the corresponding named curve, defined
  either in FIPS 186-4 {{DSS}} or in {{RFC7748}}.
  Values 0xFE00 through 0xFEFF are reserved for private use.

Finite Field Groups (DHE)
: Indicates support of the corresponding finite field
  group, defined in {{RFC7919}}.
  Values 0x01FC through 0x01FF are reserved for private use.
{:br }

Items in named_group_list are ordered according to the client's
preferences (most preferred choice first).
-->

</div>
<div class="col2">
We covered the logic behind the group selection in the [HelloRetryRequest](#hello-retry-request)
section. We define the extension as the list:
```
define(<!NamedGroupList!>, <!Extension('10', client_sg)!>)
```
where `client_sg` is defined locally by the client as `client_sg = <$g1, $g2>`.

That is, we only support the client sending two (distinct) groups. However, 
`$g1` and `$g2` are free to be any value, so any two client hello messages may
have no overlapping groups.
</div>
</div>

<div class="row">
<div class="col1">

As of TLS 1.3, servers are permitted to send the "supported_groups"
extension to the client. If the server has a group it prefers to the
ones in the "key_share" extension but is still willing to accept the
ClientHello, it SHOULD send "supported_groups" to update the client's
view of its preferences; this extension SHOULD contain all groups
the server supports, regardless of whether they are currently
supported by the client. Clients MUST NOT act upon any information
found in "supported_groups" prior to successful completion of the
handshake, but MAY use the information learned from a successfully
completed handshake to change what groups they use in their
"key_share" extension in subsequent connections.

</div>
<div class="col2">
We do not model this, nor do we model the client remembering which groups the
server supports.
</div>
</div>

