<div class="row">
#  Cryptographic Computations
</div>
<div class="row">
<div class="col1">
The TLS handshake establishes one or more input secrets which
are combined to create the actual working keying material, as detailed
below. The key derivation process incorporates both the input secrets
and the handshake transcript. Note that because the handshake
transcript includes the random values in the Hello messages,
any given handshake will have different traffic secrets, even
if the same input secrets are used, as is the case when
the same PSK is used for multiple connections
</div>
<div class="col2">
</div>
</div>

<div class="row">
## Key Schedule
</div>
<div class="row">
<div class="col1">

The key derivation process makes use of the HKDF-Extract and HKDF-Expand
functions as defined for HKDF {{RFC5869}}, as well as the functions
defined below:

~~~~
    HKDF-Expand-Label(Secret, Label, HashValue, Length) =
         HKDF-Expand(Secret, HkdfLabel, Length)

    Where HkdfLabel is specified as:

    struct {
        uint16 length = Length;
        opaque label<7..255> = "tls13 " + Label;
        opaque hash_value<0..255> = HashValue;
    } HkdfLabel;

    Derive-Secret(Secret, Label, Messages) =
         HKDF-Expand-Label(Secret, Label,
                           Transcript-Hash(Messages), Hash.length)
~~~~

The Hash function used by Transcript-Hash and HKDF is the cipher suite hash
algorithm.
Hash.length is its output length in bytes. Messages are the concatenation of the
indicated handshake messages, including the handshake message type
and length fields, but not including record layer headers. Note that
in some cases a zero-length HashValue (indicated by "") is passed to
HKDF-Expand-Label.

Note: with common hash functions, any label longer than 12 characters
requires an additional iteration of the hash function to compute.
The labels in this specification have all been chosen to fit within
this limit.

Given a set of n InputSecrets, the final "master secret" is computed
by iteratively invoking HKDF-Extract with InputSecret_1, InputSecret_2,
etc.  The initial secret is simply a string of Hash.length zero bytes.
Concretely, for the
present version of TLS 1.3, secrets are added in the following order:

- PSK (a pre-shared key established externally or a resumption_master_secret
  value from a previous connection)
- (EC)DHE shared secret ({{ecdhe-shared-secret-calculation}})

This produces a full key derivation schedule shown in the diagram below.
In this diagram, the following formatting conventions apply:

- HKDF-Extract is drawn as taking the Salt argument from the top and the IKM argument
  from the left.
- Derive-Secret's Secret argument is indicated by the incoming
  arrow. For instance, the Early Secret is the Secret for
  generating the client_early_traffic_secret.

</div>
<div class="col2">
  Though our assumption of perfect crypto makes many of these additional steps
  unnecessary, we attempt to stay as close to the design as possible.

  ```
  // Usage: HKDF_Expand_Label(Secret, Label, HashValue)
  define(<!HKDF_Expand_Label!>, <!Expand($1, HkdfLabel($2, $3, L), L)!>)
  define(<!HKDF_Expand_Label!>, <!Expand($1, HkdfLabel($2, $3, L), L)!>)
  define(<!HkdfLabel!>, <!<$3, 'TLS13_$1', $2>!> )
  ```
  where `Expand/3` is a perfect one-way function taking three inputs.

  We leave the length variable `L` as implicit, and it is set to `'32'`
  everywhere.

  Which leaves `Derive-Secret` to be defined as:

  ```
  dnl Usage: Derive_Secret(Secret, Label, HashValue)
  define(<!Derive_Secret!>, <!HKDF_Expand_Label($1, $2, <!$3!>)!>)
  ```

  `HashValue` is defined to be `h(messages)`, where `messages` is always
  defined locally. 
</div>
</div>
<div class="row">
<div class="col1">
<br>
~~~~
                 0
                 |
                 v
   PSK ->  HKDF-Extract = Early Secret
                 |
                 +-----> Derive-Secret(.,
                 |                     "ext binder" |
                 |                     "res binder",
                 |                     "")
                 |                     = binder_key
                 |
                 +-----> Derive-Secret(., "c e traffic",
                 |                     ClientHello)
                 |                     = client_early_traffic_secret
                 |
                 +-----> Derive-Secret(., "e exp master",
                 |                     ClientHello)
                 |                     = early_exporter_master_secret
                 v
           Derive-Secret(., "derived", "")
                 |
                 v
(EC)DHE -> HKDF-Extract = Handshake Secret
                 |
                 +-----> Derive-Secret(., "c hs traffic",
                 |                     ClientHello...ServerHello)
                 |                     = client_handshake_traffic_secret
                 |
                 +-----> Derive-Secret(., "s hs traffic",
                 |                     ClientHello...ServerHello)
                 |                     = server_handshake_traffic_secret
                 v
           Derive-Secret(., "derived", "")
                 |
                 v
      0 -> HKDF-Extract = Master Secret
                 |
                 +-----> Derive-Secret(., "c ap traffic",
                 |                     ClientHello...server Finished)
                 |                     = client_application_traffic_secret_0
                 |
                 +-----> Derive-Secret(., "s ap traffic",
                 |                     ClientHello...server Finished)
                 |                     = server_application_traffic_secret_0
                 |
                 +-----> Derive-Secret(., "exp master",
                 |                     ClientHello...server Finished)
                 |                     = exporter_master_secret
                 |
                 +-----> Derive-Secret(., "res master",
                                       ClientHello...client Finished)
                                       = resumption_master_secret
~~~~

`---snip---`

<!--
The general pattern here is that the secrets shown down the left side
of the diagram are just raw entropy without context, whereas the
secrets down the right side include handshake context and therefore
can be used to derive working keys without additional context.
Note that the different
calls to Derive-Secret may take different Messages arguments,
even with the same secret. In a 0-RTT exchange, Derive-Secret is
called with four distinct transcripts; in a 1-RTT only exchange
with three distinct transcripts.

If a given secret is not available, then the 0-value consisting of
a string of Hash.length zeroes is used.  Note that this does not mean skipping
rounds, so if PSK is not in use Early Secret will still be
HKDF-Extract(0, 0). For the computation of the binder_secret, the label is "external
psk binder key" for external PSKs (those provisioned outside of TLS)
and "resumption psk binder key" for
resumption PSKs (those provisioned as the resumption master secret of
a previous handshake). The different labels prevents the substitution of one
type of PSK for the other.

There are multiple potential Early Secret values depending on
which PSK the server ultimately selects. The client will need to compute
one for each potential PSK; if no PSK is selected, it will then need to
compute the early secret corresponding to the zero PSK.
-->
</div>
<div class="col2">
Following the key schedule diagram, we obtain:
```
                '0'
                 |
                 v
   res_psk ->  Extract(res_psk, '0') = EarlySecret ( = es )
                 |
                 +-----> Derive_Secret(es,
                 |                     "extbinder" |
                 |                     "resbinder",
                 |                     '0')
                 |                     = binder_key
                 |
                 +-----> Derive_Secret(es, "clientearlytrafficsecret",
                 |                     h(messages))
                 |                     = early_traffic_secret
                 |
                 +-----> Derive_Secret(es, "earlyexportermastersecret",
                 |                     h(messages))
                 |                     = early_exporter_secret (NOT USED)
                 v
gxy -> Extract(gxy, es) = HandshakeSecret ( = hs )
                 |
                 +-----> Derive-Secret(hs, "c hs traffic",
                 |                     h(messages))
                 |                     = client_handshake_traffic_secret
                 |
                 +-----> Derive-Secret(hs, "s hs traffic",
                 |                     h(messages))
                 |                     = server_handshake_traffic_secret
                 |
                 v
      '0' -> Extract('0', hs) = MasterSecret ( = ms )
                 |
                 +-----> Derive-Secret(ms, "c ap traffic",
                 |                     ClientHello...server Finished)
                 |                     = client_application_traffic_secret_0
                 |
                 +-----> Derive-Secret(ms, "s ap traffic",
                 |                     ClientHello...server Finished)
                 |                     = server_application_traffic_secret_0
                 |
                 +-----> Derive-Secret(ms, "exp master",
                 |                     ClientHello...server Finished)
                 |                     = exporter_master_secret
                 |
                 +-----> Derive-Secret(ms, "res master",
                                       ClientHello...client Finished)
                                       = resumption_master_secret
```

Hence care must be taken that `messages` is defined to be the correct sequence of
messages.

`early_traffic_secret` is generated in `{recv_}client_hello_psk` and contains `ClientHello`.

`*_handshake_traffic_secret` is generated in `{client,server}_gen_keys` and contains
`ClientHello...ServerHello`.

`{client,server}_traffic_secret_0` is generated in `{recv_}server_auth` and contains
`ClientHello...ServerFinished`

`resumption_secret` is generated in `{recv_}client_auth{_cert}` and contains
`ClientHello...ClientFinished`.

Therefore `messages` is always defined as expected.
</div>
</div>

<div class="row">
## Updating Traffic Keys and IVs {#updating-traffic-keys}
</div>
<div class="row">
<div class="col1">
Once the handshake is complete, it is possible for either side to
update its sending traffic keys using the KeyUpdate handshake message
defined in {{key-update}}.  The next generation of traffic keys is computed by
generating client_/server_application_traffic_secret_N+1 from
client_/server_application_traffic_secret_N as described in
this section then re-deriving the traffic keys as described in
{{traffic-key-calculation}}.

The next-generation application_traffic_secret is computed as:

~~~~
    application_traffic_secret_N+1 =
        HKDF-Expand-Label(application_traffic_secret_N,
                          "traffic upd", "", Hash.length)
~~~~

Once client/server_application_traffic_secret_N+1 and its associated traffic keys have been computed,
implementations SHOULD delete client_/server_application_traffic_secret_N and its associated traffic
keys.

</div>
<div class="col2">
We generate the new traffic secret as:
```
    cats = keygen(prev_cats, app_secret_label())
    sats = keygen(prev_sats, app_secret_label())
```

where `keygen` expands as: `HKDF_Expand_Label($1, $2, '0')`. I.e. is the usual
exand macro with a zero-length hash value used and the label is
`applicationtrafficsecret`.
</div>
</div>

<div class="row">
## Traffic Key Calculation    
</div>
<div class="row">
<div class="col1">
The traffic keying material is generated from the following input values:

* A secret value
* A purpose value indicating the specific value being generated
* The length of the key

The traffic keying material is generated from an input traffic secret value using:

~~~~
    [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
    [sender]_write_iv = HKDF-Expand-Label(Secret, "iv", "", iv_length)
~~~~

[sender] denotes the sending side. The Secret value for each record type
is shown in the table below.

| Record Type | Secret |
|:------------|--------|
| 0-RTT Application | client_early_traffic_secret |
| Handshake         | [sender]_handshake_traffic_secret |
| Application Data  | [sender]_traffic_secret_N |

All the traffic keying material is recomputed whenever the
underlying Secret changes (e.g., when changing from the handshake to
application data keys or upon a key update).
</div>
<div class="col2">
Due to our use of perfect crypto, we do not bother with generating IVs.

However, we generate keys as above using the `keygen` macro. For example, for
the client keys we get:
```
// early application traffic keys
ead_keyc = keygen(early_traffic_secret(client), early_app_key_label())
// handshake keys
hs_keyc = keygen(handshake_traffic_secret(client), hs_key_label())
// application traffic keys
app_keys = keygen(sats, app_key_label())
```
</div>
</div>


<div class="row">
###  Diffie-Hellman    
</div>
<div class="row">
<div class="col1">
A conventional Diffie-Hellman computation is performed. The negotiated key (Z)
is converted to byte string by encoding in big-endian, padded with zeros up to
the size of the prime. This byte string is used as the shared secret, and is
used in the key schedule as specified above.

`---snip---`

<!--
Note that this construction differs from previous versions of TLS which remove
leading zeros.

### Elliptic Curve Diffie-Hellman

For secp256r1, secp384r1 and secp521r1, ECDH calculations (including parameter
and key generation as well as the shared secret calculation) are
performed according to {{IEEE1363}} using the ECKAS-DH1 scheme with the identity
map as key derivation function (KDF), so that the shared secret is the
x-coordinate of the ECDH shared secret elliptic curve point represented
as an octet string.  Note that this octet string (Z in IEEE 1363 terminology)
as output by FE2OSP, the Field Element to Octet String Conversion
Primitive, has constant length for any given field; leading zeros
found in this octet string MUST NOT be truncated.

(Note that this use of the identity KDF is a technicality.  The
complete picture is that ECDH is employed with a non-trivial KDF
because TLS does not directly use this secret for anything
other than for computing other secrets.)

ECDH functions are used as follows:

* The public key to put into the KeyShareEntry.key_exchange structure is the
  result of applying the ECDH function to the secret key of appropriate length
  (into scalar input) and the standard public basepoint (into u-coordinate point
  input).
* The ECDH shared secret is the result of applying ECDH function to the secret
  key (into scalar input) and the peer's public key (into u-coordinate point
  input). The output is used raw, with no processing.

For X25519 and X448, see {{RFC7748}}.
-->
</div>
<div class="col2">
None of this applies to our abstract model. We can simply use the raw value
`gxy = $g^(~x*~y)`. 
</div>
</div>

<div class="row">
### Exporters
</div>
<div class="row">
<div class="col1">    
{{!RFC5705}} defines keying material exporters for TLS in terms of
the TLS PRF. This document replaces the PRF with HKDF, thus requiring
a new construction. The exporter interface remains the same. If context is
provided, the value is computed as:

    HKDF-Expand-Label(Secret, label, Hash(context_value), key_length)

Where Secret is either the early_exporter_secret or the exporter_secret.
Implementations MUST use the exporter_secret unless explicitly specified
by the application. When adding TLS 1.3 to TLS 1.2 stacks, the exporter_secret
MUST be for the existing exporter interface.

If no context is provided, the value is computed as above but with a
zero-length context_value. Note that providing no context computes the
same value as providing an empty context. As of this document's
publication, no allocated exporter label is used with both
modes. Future specifications MUST NOT provide an empty context and no
context with the same label and SHOULD provide a context, possibly
empty, in all exporter computations.
</div>
<div class="col2">
We do not currently make use of exporters, nor try to prove any properties.
One can easily draw conclusions from our lemmas which prove secrecy properties
of the base secret (e.g. MasterSecret) and the transcript agreement lemmas.
</div>
</div>
