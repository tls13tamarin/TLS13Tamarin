
<div class="row">
## Incorrect DHE Share
</div>

<div class="row">
<div class="col1">

If the client has not provided a sufficient "key_share" extension (e.g., it
includes only DHE or ECDHE groups unacceptable to or unsupported by the
server), the server corrects the mismatch with a HelloRetryRequest and
the client needs to restart the handshake with an appropriate
"key_share" extension, as shown in Figure 2.
If no common cryptographic parameters can be negotiated,
the server MUST abort the handshake with an appropriate alert.

~~~
         Client                                               Server

         ClientHello
         + key_share             -------->
                                 <--------         HelloRetryRequest
                                                         + key_share

         ClientHello
         + key_share             -------->
                                                         ServerHello
                                                         + key_share
                                               {EncryptedExtensions}
                                               {CertificateRequest*}
                                                      {Certificate*}
                                                {CertificateVerify*}
                                                          {Finished}
                                 <--------       [Application Data*]
         {Certificate*}
         {CertificateVerify*}
         {Finished}              -------->
         [Application Data]      <------->        [Application Data]
~~~

Note: The handshake transcript includes the initial
ClientHello/HelloRetryRequest exchange; it is not reset with the new
ClientHello.

TLS also allows several optimized variants of the basic handshake, as
described in the following sections.

</div>
<div class="col2">
In Tamarin, we handle this with the `hello_retry_request` rule on
the server side, and the `recv_hello_retry_request` rule for the client.
we also have `*_psk` rules when a retry happens within a PSK handshake.

`hello_retry_request{_psk}` will return the server to state `S0`, ready to
recieve another client hello message. Note that if the server request a retry
with a PSK, the client might respond with a basic client hello message.

On the other hand, the client `recv_hello_retry_request` rule will process
the incoming retry request, and immediately returns a new client hello message.
</div>
</div>

<div class="row">
## Resumption and Pre-Shared Key (PSK)
</div>
<div class="row">
<div class="col1">

Although TLS PSKs can be established out of band,
PSKs can also be established in a previous connection and
then reused ("session resumption"). Once a handshake has completed, the server can
send the client a PSK identity that corresponds to a key derived from
the initial handshake (see {{NSTMessage}}). The client
can then use that PSK identity in future handshakes to negotiate use
of the PSK. If the server accepts it, then the security context of the
new connection is tied to the original connection and the key derived
from the initial handshake is used to bootstrap the cryptographic state
instead of a full handshake. In TLS 1.2 and
below, this functionality was provided by "session IDs" and
"session tickets" {{RFC5077}}. Both mechanisms are obsoleted in TLS
1.3.



PSKs can be used with (EC)DHE key exchange in order to provide forward
secrecy in combination with shared keys, or can be used alone, at the
cost of losing forward secrecy.

{{tls-resumption-psk}} shows a pair of handshakes in which the first establishes
a PSK and the second uses it:
~~~
       Client                                               Server

Initial Handshake:
---snip---
                                 <--------      [NewSessionTicket]
       [Application Data]        <------->      [Application Data]


Subsequent Handshake:
       ClientHello
       + key_share*
       + psk_key_exchange_modes
       + pre_shared_key          -------->
                                                       ServerHello
                                                  + pre_shared_key
                                                      + key_share*
                                             {EncryptedExtensions}
                                                        {Finished}
                                 <--------     [Application Data*]
       {Finished}                -------->
       [Application Data]        <------->      [Application Data]
~~~
{: #tls-resumption-psk title="Message flow for resumption and PSK"}

</div>
<div class="col2">
The main rules to handle PSK/resumption are covered above. In addition, out-of-band
PSKs are supported using the `out_of_band_psk` rule, which generates a 
symmetric secret to be used by two unauthenticated peers.

In future work, it would be interesting to write precise authentication
properties to understand the nature of implicit authentication for out-of-band
PSK authentication.

</div>
</div>

<div class="row">
<div class="col1">

As the server is authenticating via a PSK, it does not send a
Certificate or a CertificateVerify message. When a client offers resumption
via PSK, it SHOULD also supply a "key_share" extension to the server to
allow the server to decline resumption and fall back
to a full handshake, if needed. The server responds with a "pre_shared_key"
extension to negotiate use of PSK key establishment and can (as shown here)
respond with a "key_share" extension to do (EC)DHE key establishment, thus
providing forward secrecy.

When PSKs are provisioned out of band, the PSK identity and the KDF hash
algorithm to
be used with the PSK MUST also be provisioned.  Note: When using an
out-of-band provisioned pre-shared secret, a critical consideration is
using sufficient entropy during the key generation, as discussed in
[RFC4086]. Deriving a shared secret from a password or other
low-entropy sources is not secure. A low-entropy secret, or password,
is subject to dictionary attacks based on the PSK binder.  The
specified PSK authentication is not a strong password-based
authenticated key exchange even when used with Diffie-Hellman key
establishment.
</div>
<div class="col2">

We have the `server_auth` rule checking that `Eq(ke_mode, '0')`, which means we
are not in a PSK-based handshake, and therefore does not send certificates
(instead the `server_auth_psk` rule is used which just sends the `Finished`
message).

The client by default always sends a key share in the `client_hello_psk` rule, 
and the server can choose between `server_hello_psk` and `server_hello_psk_dhe`.

</div>
</div>

<div class="row">
## Zero-RTT Data
</div>

<div class="row">
<div class="col1">
When clients and servers share a PSK (either obtained externally or
via a previous handshake), TLS 1.3 allows clients to send data on the
first flight ("early data"). The client uses the PSK to authenticate
the server and to encrypt the early data.

`---snip---`

<!-- 
When clients use a PSK obtained externally then the following
additional information MUST be provisioned to both parties:

  * The cipher suite for use with this PSK
  * The Application-Layer Protocol Negotiation (ALPN) protocol, if any is to be used
  * The Server Name Indication (SNI), if any is to be used

As shown in {{tls-0-rtt}}, the Zero-RTT data is just added to the 1-RTT
handshake in the first flight. The rest of the handshake uses the same messages
as with a 1-RTT handshake with PSK resumption.
 -->
~~~
         Client                                               Server

         ClientHello
         + early_data
         + key_share*
         + psk_key_exchange_modes
         + pre_shared_key
         (Application Data*)     -------->
                                                         ServerHello
                                                    + pre_shared_key
                                                        + key_share*
                                               {EncryptedExtensions}
                                                       + early_data*
                                                          {Finished}
                                 <--------       [Application Data*]
         (EndOfEarlyData)
         {Finished}              -------->

         [Application Data]      <------->        [Application Data]
~~~
{: #tls-0-rtt title="Message flow for a zero round trip handshake"}

`---snip---`

<!-- IMPORTANT NOTE: The security properties for 0-RTT data are weaker than
those for other kinds of TLS data.  Specifically:

1. This data is not forward secret, as it is encrypted solely under
keys derived using the offered PSK.

2. There are no guarantees of non-replay between connections.
Unless the server takes special measures outside those provided by TLS,
the server has no guarantee that the same
0-RTT data was not transmitted on multiple 0-RTT connections
(See {{replay-time}} for more details).
This is especially relevant if the data is authenticated either
with TLS client authentication or inside the application layer
protocol. However, 0-RTT data cannot be duplicated within a connection (i.e., the server
will not process the same data twice for the same connection) and
an attacker will not be able to make 0-RTT data appear to be
1-RTT data (because it is protected with different keys.)

Protocols MUST NOT use 0-RTT data without a profile that defines its
use. That profile needs to identify which messages or interactions are
safe to use with 0-RTT. In addition, to avoid accidental misuse,
implementations SHOULD NOT enable 0-RTT unless specifically
requested. Implementations SHOULD provide special functions for 0-RTT data to ensure
that an application is always aware that it is sending or receiving
data that might be replayed.

The same warnings apply to any use of the early exporter secret.

The remainder of this document provides a detailed description of TLS.
 -->
</div>
<div class="col2">
We model the early data/0-RTT functionality through the `EarlySendStream`
and `EarlyRecvStream` facts. These are created by default for all PSK handshakes
(except those which were retries). The client/server may both optionally not use
these streams to send/recv data, so this is an over-approximation.
</div>
</div>
