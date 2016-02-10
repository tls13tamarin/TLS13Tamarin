changequote(<!,!>)dnl
changecom(<!/*!>,<!*/!>)dnl
dnl 
define(<!St_init!>,<!F_St_$1_$2_init(shift(shift($@)))!>)dnl
define(<!St_init_KC!>,<!F_St_$1_$2_init_KC(shift(shift($@)))!>)dnl
define(<!St_init_PSK!>,<!F_St_$1_$2_init_PSK(shift(shift($@)))!>)dnl
define(<!St_loop!>,<!L_St_$1_loop(shift($@))!>)dnl
define(<!ClientPSK!>, <!L_ClientPSK($@)!>)dnl
define(<!KnownConfig!>, <!L_KnownConfig($@)!>)dnl
dnl
/*
    An experimental file to try and prove the server
    analog of the psk_auth lemma

    STATUS: Unproven.
*/
theory TLS_13_psk_helpers
begin

include(tls13.m4i)
include(invariants.m4i)
include(fresh_secret.m4i)
include(helpers.m4i)
include(dh_chal.m4i)
include(secret_helpers.m4i)
include(psk_helpers.m4i)

include(axioms.m4i)

/* Invariant lemmas from aux/invariants.m4i */
lemma_tid_invariant
lemma_one_start_per_tid
lemma_fresh_secret
lemma_ltk_invariant
lemma_pk_origin
lemma_fresh_psk
lemma_psk_basic
lemma_psk_invariant
dnl lemma_session_origin
/* end */

/*  Lemma psk_helper
    Proof: automatic, heuristic c.

    A very useful lemma to help resolve the 
    scenario where two people share an unauthenticated
    PSK. Here, we show that both parties agree on
    the identity of the server (since the client always
    authenticates the server).

    The proof goes through nicely in order of goals.
*/
lemma_psk_helper

lemma_key_deriv
lemma_ku_keys

/*  Lemma authenticated_psk
    Proof: automatic, heuristic SSSSSSc.

    A simple proof to show that an authenticated
    PSK came from a previously authenticated session.

    The only trick is needed to make the 6th step
    resolve AuthStatus to be 'authenticated'.
*/
lemma_authenticated_psk
end