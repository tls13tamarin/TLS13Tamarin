changequote(<!,!>)dnl
changecom(<!/*!>,<!*/!>)dnl
dnl 
define(<!St_init!>,<!St_$1_$2_init(shift(shift($@)))!>)dnl
define(<!St_loop!>,<!L_St_$1_loop(shift($@))!>)dnl
define(<!St_init_KC!>,<!F_St_$1_$2_init_KC(shift(shift($@)))!>)dnl
define(<!St_init_PSK!>,<!F_St_$1_$2_init_PSK(shift(shift($@)))!>)dnl
define(<!ClientPSK!>, <!L_ClientPSK($@)!>)dnl
dnl
/*
    These are (probably) the most significant of the
    lemmas to prove. With these, many desirable properties
    follow in quite a straightforward way.

    STATUS: Needs work. Some automatic proofs, and some not
    proven at all.
*/
theory TLS_13_attack_secrets
begin

include(at_most_of.m4i)

include(tls13.m4i)
include(aux/invariants.m4i)
include(fresh_secret.m4i)
include(helpers.m4i)
include(dh_chal.m4i)
include(secrets.m4i)
include(secret_helpers.m4i)
include(psk_helpers.m4i)

include(axioms.m4i)

at_most_of(1, S1, 1)
at_most_of(1, C1, 1)
at_most_of(0, C1_Retry, 1)
at_most_of(0, S1_Retry, 0)
at_most_of(1, C1_PSK, 1)
at_most_of(0, C1_KC, 1)
at_most_of(1, S1_PSK, 1)
at_most_of(0, S1_PSK_DHE, 1)
at_most_of(0, S1_KC, 1)
at_most_of(0, C2_Auth, 1)
at_most_of(0, C_Send, 1)
at_most_of(0, C_Recv, 1)
at_most_of(0, S_Send, 1)
at_most_of(0, S_Recv, 1)
at_most_of(0, S2_Auth, 1)
at_most_of(0, S2_RecvAuth, 1)
at_most_of(0, S1_KC_RecvAuth, 1)
at_most_of(3, Register_pk, 2)

/* AUXILIARY LEMMAS */

/* Invariant lemmas from aux/invariants.m4i 
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
lemma_static_dh_invariant
lemma_psk_invariant
lemma_server_config_origin
lemma_session_origin
/* end invariants */

lemma_es_mutual
lemma_ss_mutual

end