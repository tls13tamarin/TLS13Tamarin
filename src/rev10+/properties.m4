changequote(<!,!>)dnl
changecom(<!/*!>,<!*/!>)dnl
dnl 
define(<!St_init!>,<!F_St_$1_$2_init(shift(shift($@)))!>)dnl
define(<!St_loop!>,<!St_$1_loop(shift($@))!>)dnl
define(<!St_init_KC!>,<!F_St_$1_$2_init_KC(shift(shift($@)))!>)dnl
define(<!St_init_PSK!>,<!F_St_$1_$2_init_PSK(shift(shift($@)))!>)dnl
dnl define(<!ClientPSK!>,<!L_ClientPSK($@)!>)dnl
dnl

theory TLS_13_properties
begin

include(tls13.m4i)
include(invariants.m4i)
include(helpers.m4i)

include(axioms.m4i)
include(secrets.m4i)
include(secret_helpers.m4i)
include(psk_helpers.m4i)


lemma_tid_invariant

lemma_pk_origin
lemma_ltk_invariant
lemma_ku_keys
lemma_forge_server_sig
lemma_forge_server_fin
lemma_psk_invariant
lemma_psk_auth
lemma_psk_helper
lemma_authenticated_psk
lemma_injectivity

lemma_es_basic
lemma_ss_basic
lemma_es_mutual
lemma_ss_mutual

/* Security Properties as Lemmas */
/*
  Confidentiality of session keys
  (with forward secrecy)
*/
lemma secret_session_keys:
  "All actor peer role k #i.
      SessionKey(actor, peer, role, <k, 'authenticated'>)@i & 
      not ((Ex #r. RevLtk(peer)@r & #r < #i) | (Ex #r. RevLtk(actor)@r & #r < #i)) 
    ==> not Ex #j. KU(k)@j"

/*
  Confidentiality of early data keys
*/
lemma secret_early_data_keys:
  "All actor peer k #i.
      EarlyDataKey(actor, peer, 'client', k)@i &
      not ((Ex #r. RevLtk(peer)@r))
    ==> not Ex #j. KU(k)@j" 

/*
  Unilateral (entity) authentication
*/
lemma entity_authentication [reuse]:
  "All actor peer nonces #i. 
      CommitNonces(actor, peer, 'client', nonces)@i & 
      not (Ex #r. RevLtk(peer)@r)
    ==> (Ex #j peer2. RunningNonces(peer, peer2, 'server', nonces)@j & #j < #i)"

/*
  Integrity of handshake messages
*/
lemma transcript_agreement [reuse]:
  "All actor peer transcript #i.
      CommitTranscript(actor, peer, 'client', transcript)@i & 
      not ((Ex #r. RevLtk(peer)@r))
    ==> (Ex #j peer2. RunningTranscript(peer, peer2, 'server', transcript)@j & #j < #i)"

/*
  Mutual (entity) authentication
*/
lemma mutual_entity_authentication [reuse, use_induction]:
  "All actor peer nonces #i. 
      CommitNonces(actor, peer, 'server', nonces)@i & 
      not ((Ex #r. RevLtk(peer)@r) | (Ex #r. RevLtk(actor)@r))
    ==> (Ex #j. RunningNonces(peer, actor, 'client', nonces)@j & #j < #i)"

/*
  Integrity of handshake messages
*/
lemma mutual_transcript_agreement [reuse]:
  "All actor peer transcript #i.
      CommitTranscript(actor, peer, 'server', transcript)@i & 
      not ((Ex #r. RevLtk(peer)@r) | (Ex #r. RevLtk(actor)@r))
    ==> (Ex #j. RunningTranscript(peer, actor, 'client', transcript)@j & #j < #i)"

end

// vim: ft=spthy 
