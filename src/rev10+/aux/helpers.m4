changequote(<!,!>)dnl
changecom(<!/*!>,<!*/!>)dnl
dnl 
define(<!St_init!>,<!St_$1_$2_init(shift(shift($@)))!>)dnl
define(<!St_loop!>,<!F_St_$1_loop(shift($@))!>)dnl
define(<!St_init_KC!>,<!F_St_$1_$2_init_KC(shift(shift($@)))!>)dnl
define(<!St_init_PSK!>,<!F_St_$1_$2_init_PSK(shift(shift($@)))!>)dnl
define(<!ClientPSK!>,<!L_ClientPSK($@)!>)dnl
define(<!RunningTranscript!>,<!F_RunningTranscript($@)!>)dnl
dnl 
/*
    These helper lemmas have been constructed in 
    the process of proving secrets.m4.

    STATUS: Proves automatically using given heuristics.
*/
theory TLS_13_helpers
begin

include(tls13.m4i)
include(aux/invariants.m4i)
include(fresh_secret.m4i)
include(helpers.m4i)
include(dh_chal.m4i)

include(axioms.m4i)

/* Lemmas pulled in from aux/invariants.m4i and 
   proved in invariants.m4 
*/
lemma_tid_invariant
lemma_one_start_per_tid
lemma_data_misuse
lemma_nonce_misuse
lemma_fresh_secret
lemma_ltk_invariant
lemma_pk_origin
lemma_fresh_psk
lemma_psk_invariant
/* end invariants */

/*  Lemma: key_deriv
    Proof: automatic, heuristic S

    A collection of basic lemmas to
    unwrap secrets from knowledge of 
    keys.

    Very straightforward proofs.
*/
lemma_key_deriv

/*  Lemma: psk_basic
    Proof: automatic, heuristic S

    A lemma to provide a useful inductive step 
    for PSK modes:

    If an adversary knows a PSK (i.e. the resumption
    secret), then they must have compromised some pair
    of secrets (static/ephemeral) to derive the
    PSK.

    The proof is large due to many case distinctions, 
    but quite simple, and relies on the psk_invariant
    lemma.

*/
lemma_psk_basic

/*  Lemmas: forge_{server,client}_sig
    Proofs: automatic, heuristic S

    Knowing a signature either implies there was a legitimate
    party who signed a particular hash, or the adversary
    knows the long-term key.

    This simply unravels the signature to deduce this fact.
    As such, the proof is easy.
*/
lemma_forge_server_sig
lemma_forge_client_sig

/*  Lemma: forge_server_fin
    Proof: automatic, heuristic S

    Similar to above, but with finished messages instead
    of signatures.
*/
lemma_forge_server_fin

/*  This lemma is particularly tricky
and is proved (manually) in dh_chal.m4.
*/
lemma_dh_chal 

/*  Lemmas: ku_keys
    Proofs: automatic, heuristic S

    Same idea as key_deriv.
*/
lemma_ku_keys

end