changequote(<!,!>)dnl
changecom(<!/*!>,<!*/!>)dnl
dnl 
define(<!St_init!>,<!St_$1_$2_init(shift(shift($@)))!>)dnl
define(<!St_loop!>,<!St_$1_loop(shift($@))!>)dnl
define(<!St_init_KC!>,<!St_$1_$2_init_KC(shift(shift($@)))!>)dnl
define(<!St_init_PSK!>,<!St_$1_$2_init_PSK(shift(shift($@)))!>)dnl
define(<!ClientPSK!>,<!L_ClientPSK($@)!>)dnl
define(<!RunningTranscript!>,<!F_RunningTranscript($@)!>)dnl
dnl 
theory TLS_13_DH_Chal
begin

include(tls13.m4i)
include(aux/invariants.m4i)
include(fresh_secret.m4i)
include(helpers.m4i)
include(dh_chal.m4i)

include(axioms.m4i)

/* AUXILIARY LEMMAS */

lemma_tid_invariant
lemma_one_start_per_tid
lemma_fresh_secret


lemma_dh_chal // needs manual proof

end