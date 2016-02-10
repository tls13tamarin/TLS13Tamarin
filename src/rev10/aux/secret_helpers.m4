changequote(<!,!>)dnl
changecom(<!/*!>,<!*/!>)dnl
dnl 
define(<!St_init!>,<!St_$1_$2_init(shift(shift($@)))!>)dnl
define(<!St_init_KC!>,<!St_$1_$2_init_KC(shift(shift($@)))!>)dnl
define(<!St_init_PSK!>,<!St_$1_$2_init_PSK(shift(shift($@)))!>)dnl
define(<!St_C_1_init!>,<!L_St_C_1_init($@)!>)dnl
dnl define(<!St_C_1_init_PSK!>,<!St_C_1_init_PSK($@)!>)dnl
define(<!St_C_1_init_KC!>,<!L_St_C_1_init_KC($@)!>)dnl
define(<!St_loop!>,<!L_St_$1_loop(shift($@))!>)dnl
dnl define(<!ClientPSK!>, <!ClientPSK($@)!>)dnl
dnl 
/*
    An extra set of helper lemmas to supplement helpers.m4

    These are particularly tricky lemmas specifically used
    to help prove {ss,es}_basic lemmas.

    STATUS: Proves automatically using given heuristics.
*/
theory TLS_13_secret_helpers
begin

include(tls13.m4i)
include(invariants.m4i)
include(fresh_secret.m4i)
include(helpers.m4i)
include(dh_chal.m4i)
include(secret_helpers.m4i)

include(axioms.m4i)

/* Invariant lemmas from aux/invariants.m4i 
    proved in invariants.m4 */
lemma_tid_invariant
lemma_one_start_per_tid
lemma_fresh_secret
lemma_ltk_invariant
lemma_pk_origin
lemma_fresh_psk
lemma_psk_basic
lemma_psk_invariant
dnl lemma_session_origin
lemma_static_dh_invariant
/* end invariants */

/*  Lemma: psk_auth
    Proof: automatic, heuristic S

    This is a key lemma to establish an 
    'inductive' property on authenticated PSKs
    for the client. This relies on the fact that
    in any trace, the client will have at some
    point authenticated the server, or the keys
    were established out of band.

    Long proof due to many states to unfold.
    Proof goes through mostly relying on
    the psk_invariant/psk_basic property.

*/
lemma_psk_auth

/* Helper lemmas from aux/helpers.m4i */
lemma_forge_server_sig
lemma_forge_client_sig
lemma_key_deriv
lemma_ku_keys
/* end helpers */

lemma_dh_chal // proved in dh_chal.m4

/*  Lemma: kc_origin
    Proof: automatic, heuristic S
    
    A complicated proof to prove the authenticity
    of KnownConfig DH exponents. Either the adversary
    needs to forge everything (using the Ltk), or there
    does indeed exist a legitmate DH exponent for the
    KnownConfig.

    The proof is long, and relies heavily on the forge_server_sig
    lemma, as well as invariant properties.
*/
lemma_kc_origin


/* More invariant/helper lemmas */
lemma_forge_server_fin
lemma_data_misuse
lemma_nonce_misuse
/* end */


/*  Lemma: psk_dhe_es_basic
    Proof: automatic, heuristic S

    PSK_DHE uses a DH value, 'authenticated' using
    the server finished message, as opposed to a 
    signature. Therefore, it doesn't quite fit into
    the usual proof method. Hence it is factored out
    into a separate lemma, which can be easily included
    later.

    The proof is fairly straightforward, relying on 
    dh_chal for the DH assumption, forge_server_fin for
    the integrity of the exponents, and psk_auth for
    inductive reasoning.

*/
lemma_psk_dhe_es_basic


end