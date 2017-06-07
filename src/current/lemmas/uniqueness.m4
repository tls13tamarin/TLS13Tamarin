changequote(<!,!>)dnl
changecom(<!/*!>,<!*/!>)dnl
dnl
pushdef(<!F_State_S4!>, <!L_State_S4($@)!>)dnl
pushdef(<!F_State_C4!>, <!L_State_C4($@)!>)dnl
define(<!State!>,<!F_State_$1(shift($@))!>)dnl
dnl
theory TLS13_uniqueness
begin

include(header.m4i)
include(model.m4i)
include(all_lemmas.m4i)


uniq(C0)
uniq(C1)
uniq(C1_retry)
uniq(S1)
uniq(S1_PSK)
uniq(S1_PSK_DHE)
uniq(C1_PSK)
uniq(C1_PSK_DHE)
uniq(S2a)
uniq(S2b)
uniq(S2c)
uniq(S2c_req)
uniq(S2d)
uniq(S2d_PSK)
uniq(C2a)
uniq(C2b)
uniq(C2c)
uniq(C2c_req)
uniq(C2d)
uniq(C2d_PSK)
uniq(C3)
uniq(C3_cert)
uniq(S3)
uniq(S3_cert)

one_of(S1, S1_PSK_DHE)
one_of(S1_PSK, S1_PSK_DHE)
one_of(S1_PSK, S1)
one_of(C1, C1_PSK_DHE)
one_of(C1_PSK, C1_PSK_DHE)
one_of(C1_PSK, C1)
one_of(S3, S3_cert)
one_of(C3, C3_cert)
one_of(S2d, S2d_PSK)
one_of(C2d, C2d_PSK)


end


popdef(<!F_State_S4!>)
popdef(<!F_State_C4!>)

// vim: ft=spthy 
