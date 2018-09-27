# TLS 1.3 Tamarin Model

Welcome to the TLS 1.3 Tamarin model. This README contains some basic
information on navigating the source code.

In-depth modelling details can be found
at https://samscott89.github.io/TLS13_Tamarin/.

## TLS Model


The rules defining the TLS model are found in the [model](model/) folder.
[client_basic](model/client_basic.m4i) and
[server_basic](model/server_basic.m4i) contain the basic initial TLS handshake -
from client hello up to the final client finished.

[pki](model/pki.m4i) contains the rules dictating the public-key infrastructure.

[client_psk](model/client_psk.m4i) and [server_psk](model/server_psk.m4i) contain the rules for pre-shared key TLS handshakes.

[post_hs](model/post_hs.m4i) contains rules for the post-handshake
messages: new session tickets, client authentication and key updates.

[record](model/record.m4i) contains rules for sending/receiving data. These are 
written to be role-agnostic, i.e., the same rules work for both client/server.

[zero_rtt](model/zero_rtt.m4i) contains the rules for sending/receving 0RTT data, 
including the authentication message, which can take place after a client hello
message in PSK mode.

These files should be included in a theory by using the [model](model/model.m4i)
file which subsequently includes the above. The model can be temporarily simplified
for testing by removing lines from this file.

In addition to these files which contain the rules for the model, there are extra 
auxiliary files which are used to keep the model files relatively clean.

[crypto](model/crypto.m4i) contains the definitions for the cryptographic parts of
the model. For example, key deriviation definitions.

[msgs](model/msgs.m4i) contains the definitions of the TLS messages which are sent 
by the rules, e.g., ClientHello. It is important to consult these definitions
when using them in rules in order to determine what unbound variables need to be
defined in the scope of the rule.

[state](model/state.m4i) contains the definition of the client/server state - 
a large tuple representing all the information which a client or server would 
be expected to store. By re-using this definition in facts, this helps to reduce
the likelihood of introducing errors.

Finally, [header](model/header.m4i) includes some standard re-usable components.

### m4 Defines

The m4 defines aim to keep rule syntax consistent across files, and to
try to keep the mapping between TLS syntax and Tamarin modelling as clear
as possible.

There are large two types of macros which should be used in the rules:
 - Functions (written in `snake_case(... [var_n])`)
 - Definitions (written in `UpperCamelCase`)

Though a function without any arguments is equivalent to a a definition, the distinction
is that the function will generally involve some processing, or variable assignmemt.

For example, the `set_state()` macro will carry forwards state variables, `nc = prev_nc, ...`.

On the other hand, definitions simply expand out a tuple, for example `ClientHello`.

Upper snake case variables such as `SIMPLE_MODEL` are reserved for preprocessor
flags.

#### Using `set_state()`

The `set_state()` macro is used to set all variables of the {Server/Client}State
by simply carrying forwards the variables in Prev{Server/Client}State.

In some situations, we wish to pattern match one of the state variables. For
example, making sure the server is running in `psk_auth` mode when supplying a
Finished message.

This can be done by setting the `prev_*` variable *before* the `set_state()`
macro is invoked.

Similary, any state variable which will be changed on the output state can
simply be assigned *after* the `set_state()` macro.

**Important**: if a variable is to be assigned based on an incoming messages (
for example a server key share gy). This needs to be overriden after
`set_state()`, i.e., use `gy = new_gy`. Otherwise, the `set_state()` macro will
have assigned `gy = prev_gy` which is invalid.

#### Session hash convention

The TLS session hash is defined by accumulating all messages *processed* up to
that point. These hashes are used at various points to generate cryptographic
material.

For example, the server's CertificateVerify message contains a signature of the session
hash up to this point. Therefore, we must use the partial session hash which is
computed at this point.

Since each distinct message is defined as per the specs, we can easily compute
the rolling hash by simply appending to the `messages` variable:

```cpp
    messages = <messages, ServerCertificate>
    ...
    // compute signature
    ...
    messages = <messages, CertificateVerify>
    ...
    // compute finished messages
    ...
    messages = <messages, Finished>
```

This is important since `h(<a, b, c>)` is not equal to `h(<<a, b>, c>)`, and we
need to ensure that the server and client use the same convention for computing
the hash.

The `messages` variable is used implicitly in a lot of computations and should
be updated as soon as possible in every `let` block.

### Builtins and functions

The builtins we are using are:

 - hashing: provides the symbol h(), representing hash functions
 - signing: the functions `sign(data, sk) = sign{data}sk` and `verify(sig,
   data, pk)` where `verify(sign{data}sk, data, pk) = true`
 - symmetric-encryption: senc, sdec where `sdec(senc(data, key), key) = data`
 - diffie-hellman: a finite equations variant of DH to find solutions to the
   equation g^xy

Each function declaration will automatically generate an adversary rule to
allow the adversary to compute the same function, i.e., all functions
essentially act as random oracles.

#### Public key infrastructure

The public key infrastructure is modelled by an infallible entity which
generates public, private key pairs and binds them to an identity.

This is the `Register_pk` rule.

Long term keys are captured by the persistant fact `!Ltk($A, ~ltkA)`, `$A`
denoting the public identity of the actor, and ~ltkA the fresh value which
is the key itself.

The public key is `pk(~ltkA)`, where pk is from the asymmetric builtins (via
signing) and is the public key for the key `~ltkA`. The public key is bound
to `$A` in the persistant fact `!Pk($A, pk(~ltkA))`.

The adversary is also provided the public key in the `Out` fact. The
adversary can also compromise the long-term key using the `Reveal_Ltk` rule.

#### Adversarial capabilities

As per the Dolev-Yao model, the communication channel is assumed to be under the
control of the adversary and cryptography is modelled as a perfect system of
functions with different properties.

In practice, this means the adversary will always need to know/learn the keys
used in the cryptographic computation to be able to decrypt messages and forge
signatures.

It is important to note that here 'adversary' does not refer to a specific
actor, but rather to the information that could be deduced by an active
attacker interacting with the protocol. The adversary does not directly
partake in the protocol using rules, but has the necessary powers
to be able to masquerade as a legitimate party.

We define additional rules to give the adversary the ability to compromise
different components of the protocol.

The `Reveal_Ltk` rule allows the attacker to reveal the private key of the
an actor, used for signing, whereas the `Reveal_DHExp` rule allows the attacker
to reveal the Diffie-Hellman exponent of a particular actor. Note that this
could either correspond to a compromise of an actor, or a cryptographic break.

Future work includes adding the following capabilities:
 - Compromise of pre-shared keys
 - Weakening of cryptographic primitives, including modelling bad randomness
   and weak hash functions

#### Implicit vs Explicit checking

There are two possibilities when modelling cryptographic checks, for example,
checking that a signature is valid.

**Implicit** checking refers to using Tamarin's pattern matching to reduce the
set of traces to only those in which a valid signature is supplied.

To be specific, suppose `sign{m}sk` and `sk` are premises of a rule
(in this model, `sign{m}~ltkA` and `!Ltk($A, ~ltkA)`). Then the only way a
trace can exist with that particular rule is if a valid signature is supplied
as a premise. An adversary will need `~ltkA` to be able to produce such a
signature. Note that the rule does not actually use ~ltkA for any computation,
and thus this does not imply that the actor has access to the private key.

In **explicit** checking, we replace the `sign{m}~ltkA` term with a
generic term `signature`. To model the recipient checking the signature,  we
write an explicit action which says `Eq(verify(signature, m, pk(~ltkA)),True)`.
Now we only require the public key fact `!Pk($A, pk(~ltkA))` as a premise. Note
that this has the same outcome: all traces which do not have valid signatures
are excluded.

We currently use explicit checking for signatures and finished messages.
However, for encryption we use the implicit pattern matching.

#### Threads vs Actors

There are two distinct ways to refer to a party: using the thread
identifier (tid) or the identity ($A).

The tid models a single instance of the protocol. A tid is
generated precisely once, and helps the Tamarin tool to unravel state facts.
Currently, tid is set to be equal to the nonce of the party, since this is a
fresh value generated uniquely for each handshake.

The identity refers to some globally agreed upon value for the identity of the
party.

When a new thread starts, the party is assigned an identity. This binding is
strict in that a new thread with identity $A precisely represents that party
$A has started a new thread.

#### Actions

Actions serve as means to log the possible operations that an actor might 
perform given the premises. These are necessary for the constuction of lemmas 
(explained in the TLS Lemmas section below). 

##### Running and Commit

We conform to the the syntax of authentication from [Lowe 1997](http://ieeexplore.ieee.org/xpl/login.jsp?tp=&arnumber=596782&url=http%3A%2F%2Fieeexplore.ieee.org%2Fxpls%2Fabs_all.jsp%3Farnumber%3D596782).

A statement of the form `Running(A, B, role, data)` means that party A:
believes they are speaking to B; is currently running the protocol as role
`role`; and has derived the information `data`.

The statement `Commit(A, B, role, data)` has the same
meaning, but it additionally says that A has finished (some part of) the protocol
and is committing to using the information `data`.

A Running action merely logs `data` as something which
is known, whereas a Commit action signals the intention to use the value of
`data` in some future process.

For example, data might be cryptographic material such as a shared secret, or
randomness. Ideally, we would expect that for each `Running(A, B, role, data)` there
wound be a corresponding `Commit(B, A, role2, data)` to pair with it.

### Macro usage

We are currently using m4 as a preprocessor, for easy aliasing, and other
features.

#### Conventions

We use '<!' and '!>' as the macro opening and closing markers, as opposed to
the default use of primes. This ensures that we do not conflict with other
Tamarin syntax. However, the m4 comment is defined to be the same as a C block:
/* ... */
This means we can use m4 macro names in Tamarin block comments without issue.

If a macro name is directly followed by an opening bracket (no space
inbetween), the bracketed parts are considered to be parameters to the macro.
They can be addressed as $1,$2,... or as $@ for all of them.

Examples:

  define(<!SessionKey!>,<!KDF(I,R,...)!>)

  define(<!State!>,<!F_State($@)!>)


#### File extensions

The top-level files have extension '.m4' to indicate that they should be
processed by m4 and then Tamarin.

Included files have the extension '.m4i' to indicate they might use m4 macros
but are not meant to be processed by m4 directly.

## TLS Lemmas

The security properties that we aim to prove are captured in the form of lemmas.
The lemma syntax and an example of a lemma are given below.

### Syntax

The syntax for specifying security properties uses (as described in the Tamarin
install's Tutorial.spthy file):
```cpp
    All      for universal quantification, temporal variables are prefixed with #

  Ex       for existential quantification, temporal variables are prefixed with #

  ==>      for implication

  &        for conjunction
  |        for disjunction
  not      for  negation

  f @ i    for action constraints, the sort prefix for the temporal variable 'i'
           is optional

  i < j    for temporal ordering, the sort prefix for the temporal variables 'i'
           and 'j' is optional

  #i = #j  for an equality between temporal variables 'i' and 'j'
  x = y    for an equality between message variables 'x' and 'y'
  KU(x)    for indicating adversarial knowledge of 'x'
```

```cpp
lemma secret_session_keys:
"/* For all session keys `k` set up between actors and peers */
  All actor peer k #i. SessionKey(actor, peer, 'client', k)@i ==>
    /* the adversary does not know `k` */
    not Ex #j. KU(k)@j &
      /* as long as the adversary has not revealed the long-term key of the peer */
      not ((Ex #r. RevLtk(peer)@r & #r < #i) |
           /* or not revealed the Diffie-Hellman exponent of the actor */
           (Ex #r x. RevDHExp(actor, x)@r) |
           /* or not revealed the Diffie-Hellman exponent of the peer. */
           (Ex #r x. RevDHExp(peer, x)@r))"
```

### Axioms

Axioms restrict the set of considered traces. The intended goal of each axiom
is expressed in a comment associated with each axiom.
