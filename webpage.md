# Automated Analysis of TLS 1.3: 0-RTT, Resumption and Delayed Authentication
[Cas Cremers](https://www.cs.ox.ac.uk/people/cas.cremers),[Marko Horvat](https://www.cs.ox.ac.uk/people/marko.horvat), 
[Sam Scott](https://pure.royalholloway.ac.uk/portal/en/persons/sam-scott%2822345852-62ac-47be-8e56-84ac63717a5f%29.html), 
[Thyla van der Merwe](http://pure.rhul.ac.uk/portal/en/persons/thyla-van-der-merwe%289a30d837-2dd5-47ca-9db8-5f825b32023c%29.html)

## Introduction

The TLS protocol is used globally by millions of users on a daily basis,
serving as the core building block for Internet security. The various flaws identified 
in TLS 1.2 and below, be they implementation- or specification-based, have prompted 
the TLS Working Group to adopt an "analysis-before-deployment" design paradigm in 
drafting the next version of the protocol. After a development process of 
many months, the [TLS 1.3 specification](https://github.com/tlswg/tls13-spec)
is nearly complete. 

CC: I split the paragraph here since it was mixing "background" and "our
stuff", which I didn't like.

In the spirit of contributing 
towards this new design philosophy, we model the TLS 1.3 specification using 
the Tamarin prover, a tool for the automated analysis of security protocols. 
We show that [revision 10 of the specification](https://tools.ietf.org/html/draft-ietf-tls-tls13-10) meets the goals of authenticated 
key exchange for any combination of unilaterally and mutually authenticated
handshakes. 

By extending our revision 10 model to incorporate the desired delayed client
authentication mechanism, we uncovered a potential attack in which an
adversary is able to successfully impersonate a client during a
PSK-resumption handshake.  Our attack highlighted the
strict necessity of including more information in the client signature contents. The IETF TLS Working Group updated
[revision 11 of the TLS 1.3 specification draft](https://tools.ietf.org/html/draft-ietf-tls-tls13-11) based on our report.
(TODO: Replace rev 11 reference with paper when published.)

Our work provides the first supporting evidence for the security of
several complex protocol mode interactions in TLS 1.3. Our formal 
model can be extended to future releases, 
thus being of long-lasting benefit.
We give a brief overview of our methodology in the following sections.

## TLS 1.3

The new handshake modes of TLS 1.3 include a 1-RTT initial (EC)DHE mode, 
a 0-RTT mode, a (Pre-Shared Key) PSK mode and a PSK-DHE mode. 
For further details see the [TLS 1.3 specification draft](https://github.com/tlswg/tls13-spec).

THYLA: This section needs to be expanded a bit - it needs to read easily and link 
to the previous and following section.

MH: I would remove it completely. I put the links to all the relevant revs in the intro.

CC: It would be good to give a few lines to point out the ideas behind
the new modes. Maybe a paragraph in total?

## Building a model

For our analysis, we use the Tamarin prover, a 
tool for the symbolic analysis of security protocols. Tamarin
enables us to precisely specify and analyse the secrecy and
authentication properties of the various handshake modes. Furthermore,
Tamarin's multiset rewriting semantics are well-suited for modelling the
complex transition system implied by the TLS 1.3 specification; the tool
allows us to analyse the interaction of an unbounded number of concurrent
TLS sessions. 
The tool and further documentation can be
found on its 
[webpage](https://github.com/tamarin-prover/tamarin-prover). 

The first step of our analysis is to construct an abstraction of the 
handshake and record protocols which we then encode as Tamarin rules. Rules capture 
honest-party and adversary actions alike. In the case of legitimate clients and servers, 
our constructed model rules generally correspond to all processing actions
associated with respective flights of messages. Our first client rule, for instance, 
captures a client generating and sending all necessary parameters as part of the first 
flight of an (EC)DHE handshake, as well as keeping track of them in the local client state.
This rule, C_1, is visible in the client state machine diagram below. The diagram 
represents the union of all the options that a client has in different executions. 

TODO: Include client state machine diagram here, with its caption. 

Note that our model assumes perfect cryptography. That is, encryption schemes 
are IND-CCA2 secure, signatures and MACs are unforgeable, hash functions behave 
as random oracles and all parties generate truly random values. We also simplify the 
model by treating parameters that do not directly influence the security 
of the protocol as abstract parameters and we do not explicitly model the TLS alert 
protocol. Our attacker model is capable
of corrupting long-term secret keys of most protocol participants (any
but the intended peer of the attacked session), and thus supports
checking for insider and Key Compromise Impersonation (KCI) attacks.
Our Tamarin model can be found [here](TODO: Add link to model). 

THYLA: Maybe the model assumptions can be excluded. Have the diagram and then 
a link to the model. 

MH: As long as they are available somewhere, it is fine.

CC: The model assumptions are clear in the paper, I don't think they
help the reader here in any useful way; I would leave them out. Clearly
this is an ad for the paper!

## Proving Stated Goals and Security Properties

The second step of the analysis involves encoding the desired security properties as 
Tamarin lemmas. The goal of the TLS handshake protocol is 
to allow for unilateral or, optionally, mutual entity authentication of communicating
parties, as well as to establish a shared secret that is unavailable to 
eavesdroppers and adversaries who can place themselves in the middle of the 
connection. The TLS record protocol is intended to provide confidentiality 
and integrity of application data. Hence, we encode the following properties as lemmas 

- unilateral authentication of the server (mandatory),
- mutual authentication (optional) 
- confidentiality and perfect forward secrecy of session keys and
- integrity of handshake messages.

and aim to show that each property holds 
THYLA: Do we need to state that we don't explicitly prove anything about the record 
protocol?  Also, I haven't said a lot about how we construct lemmas...

CC: See lemmas below...

MH: Maybe we can just link to the sources, and paper when published.

While Tamarin can automatically construct proofs for simple protocols,
its proof-finding heuristics are not yet strong enough to automatically
generate full proofs for TLS 1.3.
In practice this meant that we augmented Tamarin's search with substantial manual effort: inspecting partial proofs and deducing appropriate hints (in the form of lemmas) to guide Tamarin's proof search.

Using this approach, we establish that revision 10 of the TLS 1.3 specification meets the goals of 
authenticated key exchange in all possible combinations of 
client, server, and adversary behaviours. Specifically, we show that the confidentiality of session 
keys holds and that these keys are forward secure with respect to the attacker model
described above. We also verify both unilateral (server) and mutual authentication.

## Attacking Client Authentication

In extending our revision 10 model to include the delayed client authentication mechanism 
as proposed in ... we found an attack which violates client authentication, as an 
adversary can can impersonate a client when communicating with a server. The 
attack is similar to the [Triple Handshake attack](https://mitls.org/pages/attacks/3SHAKE) in both structure and
resulting client misauthentication: 

Handshake 1: Alice (the victim client) starts a connection with Charlie (the man-in-the-middle),
and Charlie starts a connection with Bob (the targeted server). In both connections
a PSK is established. Alice shares PSK_1 with Charlie and Charlie shares PSK_2 
with Bob. 

TODO: Insert first poster attack section here. 

Handshake 2: Alice resumes a connection with Charlie using PSK_1. Alice generates 
a random nonce nc and this is sent to Charlie. Charlie reuses this nonce
to initiate a PSK-resumption handshake with Bob. Bob responds with a random 
nonce ns, and the server Finished message, computed using PSK_2. Charlie
reuses ns and recomputes the Finished message for Alice using PSK_1. Alice returns 
her Finished message to Charlie who recomputes the Finished message for 
Bob using PSK_2. At this point, Alice and Charlie share session keys
derived from PSK_1 and Charlie and Bob share session keys derived from 
PSK_2. 

TODO: Insert second poster attack section here. 

Handshake 3: Following resumption, Charlie attempts to make a request of Bob that 
requires client authentication. Charlie is subsequently prompted for his 
certificate and verification.  Charlie re-encrypts this request for Alice. 
To compute the verification signature, Alice uses the  session_hash value, which is 
defined as the hash of all handshake messages 
excluding the Finished messages. This session_hash value will match the one 
of Charlie and Bob and hence, Charlie can re-encrypt Alice's signature for Bob, 
who accepts Alice's certificate and verification as valid authentication for Charlie. 

MH: Someone might wonder why Alice would agree to authenticate out of the blue,
without having requested an auth-required resource. We can also say that Alice
requests such a resource (the attack is not so much about that particular resource,
which Charlie may or may not wish to access, but the impending impersonation).

TODO: Insert third poster attack section here. 

The attack is possible due to the lack of a strong binding between the client signature 
and the session for which that signature is intended. We note that revision 11 
of the TLS 1.3 specification defines the client signature based on a Handshake Context 
value that now includes the Finished message. This appears to address the attack as 
the adversary would now need to force the Finished messages to match across 
the two sessions. Although the inclusion of the Finished message in the Handshake 
Context message was suggested in [Pull Request #316](https://github.com/tlswg/tls13-spec/pull/316), the TLS Working 
Group was unaware of the strict requirement for a stronger binding between the client certificate and the
security context that emerges from combining the PSK mode with delayed client authentication.

THYLA: Perhaps this last paragraph is a bit too vague. Although, it might be okay, don't 
want to go overkill. 

MH: Added new part from paper (maybe we should also say "delayed" there in paper).

THYLA: How do we make the notation pretty in the html?

CC: Which notation do you mean? We can make pretty pictures for the
graph; or do you mean PSK_1 and Finished etc.?

## Ongoing Work 

We are currently working on a model for revision 11. 

THYLA: Maybe add a bit more here/rephrase this. 

CC: I'm not sure we need this here. It is just an (empty) promise until
we've done it.

## Downloads
Download the [technical paper] (TODO: Add paper link).
TODO: Add link to RWC slides. 

THYLA: We may need to move this to where it's immediately visible. 

CC: I would put those links at the top (as well?)

## Support 

TODO: Add grants, Mozilla etc. 
