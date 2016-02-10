changequote(<!,!>)dnl
changecom(<!/*!>,<!*/!>)dnl
dnl
define(<!St_init!>,<!F_St_$1_$2_init(shift(shift($@)))!>)dnl
define(<!St_loop!>,<!F_St_$1_loop(shift($@))!>)dnl
define(<!St_init_KC!>,<!F_St_$1_$2_init_KC(shift(shift($@)))!>)dnl
define(<!St_init_PSK!>,<!F_St_$1_$2_init_PSK(shift(shift($@)))!>)dnl
dnl define(<!ServerConfig!>,<!L_ServerConfig($@)!>)dnl
define(<!ClientPSK!>,<!L_ClientPSK($@)!>)dnl
dnl define(<!KnownConfig!>,<!L_KnownConfig($@)!>)dnl
dnl
dnl
/*
    This file contains a few 'invariant' properties
    of the TLS 1.3 model.

    Each of these prove simple statements about the origin
    of actions, as well as bindings and separations.

    These are commonly used across all other theory files.

    STATUS: Proves automatically using given heuristics.
*/
theory TLS_13_invariants
begin

include(tls13.m4i)
include(invariants.m4i)

include(axioms.m4i)

/*  Lemma tid_invariant
    Proof: automatic, heuristic S

    Proves easily by to induction.
*/
lemma_tid_invariant

/*  Lemma: one_start_per_tid
    Proof: automatic, heuristic C

    Simple proof, fresh tid
    always generated at start action.
*/  
lemma_one_start_per_tid

/*  Lemma: data_misuse
    Proof: automatic, heuristic ssc

    Quickly finds contradicting uses of
    fresh values.
*/
lemma_data_misuse

/*  Lemma: nonce_misues
    Proof: automatic, heuristic ssc

    Same as data_misuse.
*/
lemma_nonce_misuse

/*  Lemma: psk_invariant
    Proof: automatic, heuristic s

    Simple state unfolding.
*/
lemma_psk_invariant

/*  Lemma: psk_id_origin
    Proof: automatic, heuristic ssc

    Immediate proof by unwrapping the
    new session ticket value.
    
*/
lemma_psk_id_origin

/*  Lemma: ltk_invariant
    Proof: automatic, heuristic S

    Easily finds proof.

*/
lemma_ltk_invariant

/*  Lemma: pk_origin
    Proof: automatic, heuristic s

    Simple state unfolding.
*/
lemma_pk_origin

/*  Lemma: fresh_psk
    Proof: automatic, heuristic s

    Straightforward.
*/
lemma_fresh_psk

/*  Lemma: static_dh_invariant
    Proof: automatic, heuristic s

    Straightforward.
*/
lemma_static_dh_invariant

/*  Lemma: server_config_origin
    Proof: automatic, heuristic S

    Straightforward with induction.

*/
lemma_server_config_origin

/*  Lemma: session_origin
    Proof: automatic, heuristic S

    Many states to unfold, but generally 
    a straightforward induction proof.

*/
lemma_session_origin

end