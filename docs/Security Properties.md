Security Properties
===================

An (informal) overview of the security properties we are aiming to prove. For
more details, see either the documentation in paper/, or for a technical
specification of these properties see src/.

Secrecy properties
------------------

a) Basic secrecy property: If *client* generates a session key, it is secret
   under the assumption that the adversary has not revealed the long term key
   of the server.
 - This assumption covers either long term key compromise, or the degenerate
   case where the adversary IS the server.

b) Weaker secrecy property. If *server* generates a session key, and there
   exists a client instance which generated the same key, then the adversary
   does not know the key.
 - Without client auth, is this the best you can hope for? In practice this is
   probably sufficient for most servers, particularly when authentication is
   performed at the application layer.
 - Switching roles also covers you in anon modes, and out of band
   authentication modes.

c) Basic secrecy - mutual auth. If *server* generates a key, and the server
   has receieved some authentication from the client, and the long term key of
   the client is secret, then the adversary does not know the key.
 - But still no authentication is proven.

Authentication properties
-------------------------

a) Lowe's hierarchy of authentication. (We expect the strongest notion - full
   agreement - to hold).

b) If A authenticates B, and B subsequently performs PSK/session resumption
   with A, does A inductively authenticate B?

AKE
---

If A has generated a key with B, then B has also generated the same key with
A.
 - This should follow as a combination of basic secrecy (between A and B) and
   authentication of parties.
 - Additionally, we get key confirmation through agrement of
   transcripts/session hashes, and recentness through agreement of nonces.