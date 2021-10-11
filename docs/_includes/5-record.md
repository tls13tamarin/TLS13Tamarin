<div class="row">
# Record Protocol
</div>
<div class="row">
<div class="col1">

`---snip---`
<!--
The TLS record protocol takes messages to be transmitted, fragments
the data into manageable blocks, protects the records, and transmits
the result. Received data is verified and decrypted, reassembled, and
then delivered to higher-level clients.

TLS records are typed, which allows multiple higher-level protocols to
be multiplexed over the same record layer. This document specifies
three content types: handshake, application data, and alert.
Implementations MUST NOT send record types not defined in this
document unless negotiated by some extension. If a TLS implementation
receives an unexpected record type, it MUST terminate the connection
with an "unexpected_message" alert.  New record content type values are
assigned by IANA in the TLS Content Type Registry as described in
{{iana-considerations}}.
-->
## Record Layer

`---snip---`
<!--
The TLS record layer receives uninterpreted data from higher layers in
non-empty blocks of arbitrary size.

The record layer fragments information blocks into TLSPlaintext records
carrying data in chunks of 2^14 bytes or less. Message boundaries are
not preserved in the record layer (i.e., multiple messages of the same
ContentType MAY be coalesced into a single TLSPlaintext record, or a single
message MAY be fragmented across several records).
Alert messages ({{alert-protocol}}) MUST NOT be fragmented across records.

%%% Record Layer

       enum {
           invalid_RESERVED(0),
           change_cipher_spec_RESERVED(20),
           alert(21),
           handshake(22),
           application_data(23),
           (255)
       } ContentType;

       struct {
           ContentType type;
           ProtocolVersion legacy_record_version = 0x0301;    /* TLS v1.x */
           uint16 length;
           opaque fragment[TLSPlaintext.length];
       } TLSPlaintext;

type
: The higher-level protocol used to process the enclosed fragment.

legacy_record_version
: This value MUST be set to 0x0301 for all records.
  This field is deprecated and MUST be ignored for all purposes.

length
: The length (in bytes) of the following TLSPlaintext.fragment. The
  length MUST NOT exceed 2^14. An endpoint that receives a record
  that exceeds this length MUST terminate the connection with a
  "record_overflow" alert.

fragment
: The data being transmitted. This value transparent and treated as an
  independent block to be dealt with by the higher-level protocol
  specified by the type field.
{:br }

This document describes TLS Version 1.3, which uses the version 0x0304.
This version value is historical, deriving from the use of 0x0301
for TLS 1.0 and 0x0300 for SSL 3.0. In order to maximize backwards
compatibility, the record layer version identifies as simply TLS 1.0.
Endpoints supporting other versions negotiate the version to use
by following the procedure and requirements in {{backward-compatibility}}.

Implementations MUST NOT send zero-length fragments of Handshake or
Alert types, even if those fragments contain padding. Zero-length
fragments of Application Data MAY be sent as they are potentially
useful as a traffic analysis countermeasure.

When record protection has not yet been engaged, TLSPlaintext
structures are written directly onto the wire. Once record protection
has started, TLSPlaintext records are protected and sent as
described in the following section.

## Record Payload Protection

The record protection functions translate a TLSPlaintext structure into a
TLSCiphertext. The deprotection functions reverse the process. In TLS 1.3
as opposed to previous versions of TLS, all ciphers are modeled as
"Authenticated Encryption with Additional Data" (AEAD) {{RFC5116}}.
AEAD functions provide a unified encryption and authentication
operation which turns plaintext into authenticated ciphertext and
back again. Each encrypted record consists of a plaintext header followed
by an encrypted body, which itself contains a type and optional padding.

%%% Record Layer

       struct {
           opaque content[TLSPlaintext.length];
           ContentType type;
           uint8 zeros[length_of_padding];
       } TLSInnerPlaintext;

       struct {
           ContentType opaque_type = 23; /* application_data */
           ProtocolVersion legacy_record_version = 0x0301; /* TLS v1.x */
           uint16 length;
           opaque encrypted_record[length];
       } TLSCiphertext;

content
: The cleartext of TLSPlaintext.fragment.

type
: The content type of the record.

zeros
: An arbitrary-length run of zero-valued bytes may
  appear in the cleartext after the type field.  This provides an
  opportunity for senders to pad any TLS record by a chosen amount as
  long as the total stays within record size limits.  See
  {{record-padding}} for more details.

opaque_type
: The outer opaque_type field of a TLSCiphertext record is always set to the
  value 23 (application_data) for outward compatibility with
  middleboxes accustomed to parsing previous versions of TLS.  The
  actual content type of the record is found in TLSInnerPlaintext.type after
  decryption.

legacy_record_version
: The legacy_record_version field is identical to TLSPlaintext.legacy_record_version and is always 0x0301.
  Note that the handshake protocol including the ClientHello and ServerHello messages authenticates
  the protocol version, so this value is redundant.

length
: The length (in bytes) of the following TLSCiphertext.encrypted_record, which
  is the sum of the lengths of the content and the padding, plus one
  for the inner content type. The length MUST NOT exceed 2^14 + 256.
  An endpoint that receives a record that exceeds this length MUST
  terminate the connection with a "record_overflow" alert.

encrypted_record
: The AEAD encrypted form of the serialized TLSInnerPlaintext structure.
{:br }
-->

AEAD algorithms take as input a single key, a nonce, a plaintext, and "additional
data" to be included in the authentication check, as described in Section 2.1
of {{RFC5116}}. The key is either the client_write_key or the server_write_key,
the nonce is derived from the sequence number (see {{nonce}}) and the
client_write_iv or server_write_iv, and the additional data input is empty
(zero length).  Derivation of traffic keys is defined in {{traffic-key-calculation}}.

The plaintext input to the AEAD is the the encoded TLSInnerPlaintext structure.

The AEAD output consists of the ciphertext output from the AEAD
encryption operation. The length of the plaintext is greater than the
corresponding TLSPlaintext.length due to the inclusion of TLSInnerPlaintext.type and
any padding supplied by the sender.  The length of the
AEAD output will generally be larger than the plaintext, but by an
amount that varies with the AEAD algorithm. Since the ciphers might
incorporate padding, the amount of overhead could vary with different
lengths of plaintext. Symbolically,

       AEADEncrypted =
           AEAD-Encrypt(write_key, nonce, plaintext)

In order to decrypt and verify, the cipher takes as input the key,
nonce, and the AEADEncrypted value. The output is either the plaintext
or an error indicating that the decryption failed. There is no
separate integrity check. That is:

       plaintext of encrypted_record =
           AEAD-Decrypt(peer_write_key, nonce, AEADEncrypted)

If the decryption fails, the receiver MUST terminate the connection
with a "bad_record_mac" alert.

An AEAD algorithm used in TLS 1.3 MUST NOT produce an expansion greater than
255 octets.  An endpoint that receives a record from its peer with
TLSCiphertext.length larger than 2^14 + 256 octets MUST terminate
the connection with a "record_overflow" alert.  This limit is derived from the maximum
TLSPlaintext length of 2^14 octets + 1 octet for ContentType + the
maximum AEAD expansion of 255 octets.


## Per-Record Nonce {#nonce}

A 64-bit sequence number is maintained separately for reading and writing
records.  Each sequence number is set to zero at the beginning of a connection
and whenever the key is changed.

The sequence number is incremented by one after reading or writing each record.
The first record transmitted under a particular set of traffic keys
MUST use sequence number 0.

Because the size of sequence numbers is 64-bit, they should not
wrap. If a TLS implementation would need to
wrap a sequence number, it MUST either rekey ({{key-update}}) or
terminate the connection.

The length of the per-record nonce (iv_length) is set to the larger of
8 bytes and N_MIN for the AEAD algorithm (see {{RFC5116}} Section 4). An AEAD
algorithm where N_MAX is less than 8 bytes MUST NOT be used with TLS.
The per-record nonce for the AEAD construction is formed as follows:

  1. The 64-bit record sequence number is encoded in network byte order
     and padded to the left with zeroes to iv_length.

  2. The padded sequence number is XORed with the static client_write_iv
     or server_write_iv, depending on the role.

The resulting quantity (of length iv_length) is used as the per-record
nonce.

Note: This is a different construction from that in TLS 1.2, which
specified a partially explicit nonce.


## Record Padding

`---snip---`
<!--

All encrypted TLS records can be padded to inflate the size of the
TLSCipherText.  This allows the sender to hide the size of the
traffic from an observer.

When generating a TLSCiphertext record, implementations MAY choose to
pad.  An unpadded record is just a record with a padding length of
zero.  Padding is a string of zero-valued bytes appended
to the ContentType field before encryption.  Implementations MUST set
the padding octets to all zeros before encrypting.

Application Data records may contain a zero-length TLSInnerPlaintext.content if
the sender desires.  This permits generation of plausibly-sized cover
traffic in contexts where the presence or absence of activity may be
sensitive.  Implementations MUST NOT send Handshake or Alert records
that have a zero-length TLSInnerPlaintext.content.

The padding sent is automatically verified by the record protection
mechanism; upon successful decryption of a TLSCiphertext.encrypted_record,
the receiving implementation scans the field from the end toward the
beginning until it finds a non-zero octet. This non-zero octet is the
content type of the message.
This padding scheme was selected because it allows padding of any encrypted
TLS record by an arbitrary size (from zero up to TLS record size
limits) without introducing new content types.  The design also
enforces all-zero padding octets, which allows for quick detection of
padding errors.

Implementations MUST limit their scanning to the cleartext returned
from the AEAD decryption.  If a receiving implementation does not find
a non-zero octet in the cleartext, it MUST terminate the
connection with an "unexpected_message" alert.

The presence of padding does not change the overall record size
limitations -- the full fragment plaintext may not exceed 2^14 octets.

Selecting a padding policy that suggests when and how much to pad is a
complex topic, and is beyond the scope of this specification. If the
application layer protocol atop TLS has its own padding, it may be
preferable to pad application_data TLS records within the application
layer.  Padding for encrypted handshake and alert TLS records must
still be handled at the TLS layer, though.  Later documents may define
padding selection algorithms, or define a padding policy request
mechanism through TLS extensions or some other means.
-->
## Limits on Key Usage

`---snip---`
<!--
There are cryptographic limits on the amount of plaintext which can be
safely encrypted under a given set of keys.  {{AEAD-LIMITS}} provides
an analysis of these limits under the assumption that the underlying
primitive (AES or ChaCha20) has no weaknesses. Implementations SHOULD
do a key update {{key-update}} prior to reaching these limits.

For AES-GCM, up to 2^24.5 full-size records (about 24 million)
may be encrypted on a
given connection while keeping a safety margin of approximately
2^-57 for Authenticated Encryption (AE) security. For
ChaCha20/Poly1305, the record sequence number would wrap before the
safety limit is reached.

-->
</div>
<div class="col2">
</div>
</div>
