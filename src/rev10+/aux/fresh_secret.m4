changequote(<!,!>)dnl
changecom(<!/*!>,<!*/!>)dnl
dnl 
define(<!St_init!>,<!L_St_$1_$2_init(shift(shift($@)))!>)dnl
define(<!St_loop!>,<!L_St_$1_loop(shift($@))!>)dnl
define(<!St_init_KC!>,<!L_St_$1_$2_init_KC(shift(shift($@)))!>)dnl
define(<!St_init_PSK!>,<!L_St_$1_$2_init_PSK(shift(shift($@)))!>)dnl
define(<!L_St_init_S_0_PSK!>,<!F_St_init_S_0_PSK($@)!>)
define(<!KnownConfig!>,<!L_KnownConfig($@)!>)dnl
define(<!ClientPSK!>,<!L_ClientPSK($@)!>)dnl
define(<!ServerPSK!>,<!L_ServerPSK($@)!>)dnl
dnl 
/*
    This captures the single, but important, lemma of
    fresh secrets. It relates to the adversary learning
    DH exponents.

    STATUS: Proves automatically using 'Knows' trick, 
    or is easy to manually prove otherwise.
*/
theory TLS_13_check_fresh_secret
begin

include(tls13.m4i)

rule Aux_Knows:
[ In(~x) ] --[ Knows(~x) ]-> [ ]

include(invariants.m4i)
include(fresh_secret.m4i)

include(axioms.m4i)

lemma_tid_invariant
lemma_data_misuse
lemma_psk_id_origin
lemma_psk_invariant


/*  Lemma: fresh_secret
    Proof: automatic*, heuristic s

    This proof goes through easily
    when KU is replaced by a Knows action.

    The Knows rule is a trivial addition as seen
    above.

    Without this trick, the proof is still easy, 
    but currently must be manually done.
*/
pushdef(<!KU!>,<!Knows($@)!>)
lemma_fresh_secret
popdef(<!KU!>)

end

