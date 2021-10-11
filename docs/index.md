---
title: TLS 1.3 in Tamarin
layout: base
---

# TLS 1.3 modelled in Tamarin

This page is a work-in-progress and designed to be viewed on a screen resolution of
at least 1600px. Unforunately, if you have less than that then be prepared to scroll.

This is used to document the code, and provide a side-by-side comparison of the
specification and the model.

In order to ensure the quoted specification is up to date, this can be used in a
side-by-side diff: `cat _includes/* | diff -y - tls13-spec/draft-ietf-tls-tls13.md | less`
(a helper script has also been written: `./compare.sh`)
since the specification text should all be in order.

Note that there are a number of "snipped" sections. These are bits which we
have not modelled at all. With two notable exceptions, these are also sections
which we did not feel were worth elaborating on.

The notable omissions are the Alert and Record protocol sections, which we would
like to investigate in future work. Our modelling of the Record protocol is thus
quite coarse, and simply treats all encryption as chunks of authenticated
encryption.

<div class="row">
<div class="col1">
# TLS 1.3 Protocol Overview
<br>
`---snip---`

<!-- 
TODO: make this text visible via tooltip or similar.

The cryptographic parameters of the session state are produced by the
TLS handshake protocol, which a TLS client and server use when first
communicating to agree on a protocol version, select cryptographic
algorithms, optionally authenticate each other, and establish shared
secret keying material. Once the handshake is complete, the peers
use the established keys to protect application layer traffic.

A failure of the handshake or other protocol error triggers the
termination of the connection, optionally preceded by an alert message
({{alert-protocol}}).
 -->
</div>
<div class="col2">

# Tamarin model

</div>
</div>

{% include 2-0-protocol_overview.md %}

{% include 2-1-hs_modes.md %}

{% include 4-0-handshake_protocol.md %}

{% include 4-1-ke_messages.md %}

{% include 4-2-0-extensions.md %}

{% include 4-2-7-key_share.md %}

{% include 4-2-8-psk.md %}

{% include 4-2-9-psk.md %}

{% include 4-3-server_params.md %}

{% include 4-4-auth_messages.md %}

{% include 4-5-post_hs.md %}

{% include 7-0-crypto.md %}

<div class="row">
<div class="col1">
</div>
<div class="col2">
</div>
</div>

<div class="row">
<div class="col1">
</div>
<div class="col2">
</div>
</div>

[Back to top](#tls-13-modelled-in-tamarin)

<!-- 
# Conclusion


[example link][link-name]

[link-name]: http://example.com -->