changequote(<!,!>)dnl
changecom(<!/*!>,<!*/!>)dnl
dnl
define(<!St_init!>,<!F_St_$1_$2_init(shift(shift($@)))!>)dnl
define(<!St_loop!>,<!F_St_$1_loop(shift($@))!>)dnl
define(<!St_init_KC!>,<!F_St_$1_$2_init_KC(shift(shift($@)))!>)dnl
define(<!St_init_PSK!>,<!F_St_$1_$2_init_PSK(shift(shift($@)))!>)dnl
define(<!ServerConfig!>,<!F_ServerConfig($@)!>)dnl
dnl
define(<!In!>,<!MessageIn($*)!>)dnl
define(<!Out!>,<!MessageOut($*)!>)dnl
dnl
theory TLS_13_reachability_tests
begin

include(tls13.m4i)
include(at_most_of.m4i)

include(axioms.m4i)

axiom one_actor_per_role: "All actor actor2 nc nc2 role #i #j. Start(nc, actor, role)@i & Start(nc2, actor2, role)@j ==> actor = actor2"

/*
  Weird trick needed to speed up pre-processing time for
  Tamarin. has no action, so is hidden in the graph view anyway.
*/
rule in_out:
[MessageOut(m)]-->[MessageIn(m)]

at_most_of(1, S1, 1)
at_most_of(1, C1, 1)
at_most_of(1, C1_Retry, 0)
at_most_of(1, S1_Retry, 0)
at_most_of(1, C1_PSK, 1)
at_most_of(1, C1_PSK_DHE, 1)
at_most_of(1, C1_KC, 1)

/* Basic reachability tests.
 * Make sure all rules are reachable.
 */

lemma exists_c1:
  exists-trace
    "Ex tid #i. C1(tid)@i"

lemma exists_S1:
  exists-trace
    "Ex tid #i. S1(tid)@i"

lemma exists_c2:
  exists-trace
    "Ex tid #i. C2(tid)@i"

lemma exists_s2:
  exists-trace
    "Ex tid #i. S2(tid)@i"

lemma exists_c3:
  exists-trace
    "Ex tid #i. C3(tid)@i"

lemma exists_s3:
  exists-trace
    "Ex tid #i. S3(tid)@i"

lemma exists_c3_nst:
  exists-trace
    "Ex tid #i. C3_NST(tid)@i"

lemma exists_s3_nst:
  exists-trace
    "Ex tid #i. S3_NST(tid)@i"

lemma exists_c_send:
  exists-trace
    "Ex tid #i. C_Send(tid)@i"

lemma exists_s_send:
  exists-trace
    "Ex tid #i. S_Send(tid)@i"

lemma exists_c_recv:
  exists-trace
    "Ex tid #i. C_Recv(tid)@i"

lemma exists_s_recv:
  exists-trace
    "Ex tid #i. S_Recv(tid)@i"

lemma exists_c1_psk:
  exists-trace
    "Ex tid #i. C1_PSK(tid)@i"

lemma exists_s1_psk:
  exists-trace
    "Ex tid #i. S1_PSK(tid)@i"

lemma exists_c2_psk:
  exists-trace
    "Ex tid #i. C2_PSK(tid)@i"

lemma exists_s1_psk_dhe:
  exists-trace
    "Ex tid #i. S1_PSK_DHE(tid)@i"

lemma exists_c2_psk_dhe:
  exists-trace
    "Ex tid #i. C2_PSK_DHE(tid)@i"

lemma exists_s1_authreq:
  exists-trace
    "Ex tid #i. S1_AuthReq(tid)@i"

lemma exists_s1_noauth:
  exists-trace
    "Ex tid #i. S1_NoAuth(tid)@i"

lemma exists_c2_noauth:
  exists-trace
    "Ex tid #i. C2_NoAuth(tid)@i"

lemma exists_c2_auth:
  exists-trace
    "Ex tid #i. C2_Auth(tid)@i"

lemma exists_s2_recvauth:
  exists-trace
    "Ex tid #i. S2_RecvAuth(tid)@i"

lemma exists_c1_kc_auth:
  exists-trace
    "Ex tid #i. C1_KC_Auth(tid)@i"

lemma exists_s1_kc_recvauth:
  exists-trace
    "Ex tid #i. S1_KC_RecvAuth(tid)@i"

lemma exists_s1_psk_auth:
  exists-trace
    "Ex tid #i. S1_PSK_Auth(tid)@i"

lemma exists_s1_psk_noauth:
  exists-trace
    "Ex tid #i. S1_PSK_NoAuth(tid)@i"

lemma exists_c1_kc:
  exists-trace
    "Ex tid #i. C1_KC(tid)@i"

lemma exists_s1_kc:
  exists-trace
    "Ex tid #i. S1_KC(tid)@i"

lemma exists_c2_kc:
  exists-trace
    "Ex tid #i. C2_KC(tid)@i"

end

// vim: ft=spthy 
