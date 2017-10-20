changequote(<!,!>)
changecom(<!/*!>,<!*/!>)
define(<!State!>,<!F_State_$1(shift($@))!>)dnl
define(<!ClientCertReq!>,<!L_ClientCertReq($@)!>)dnl
define(<!ServerCertReq!>,<!L_ServerCertReq($@)!>)dnl
define(<!CachePSK!>, <!L_CachePSK($@)!>)dnl


theory TLS_13_dh_injectivity
begin

include(header.m4i)
include(model.m4i)
include(all_lemmas.m4i)

uniq(C0)
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

lemma_tid_invariant/* [use_induction, reuse]:
  "All tid actor role #i. Instance(tid, actor, role)@i==>
      (Ex #j. Start(tid, actor, role)@j & (#j < #i))"
*/

lemma_one_start_per_tid/* [reuse]:
  "All tid actor actor2 role role2 #i #j. Start(tid, actor, role)@i & Start(tid, actor2, role2)@j ==>#i=#j"
*/

lemma_dh_exp_invariant/*  [use_induction, reuse]:
  "All tid actor x #i. RevDHExp(tid, actor, x)@i ==>
    Ex #j. DH(tid, actor, x)@j & #j < i"
*/

lemma_one_dh_per_x/*  [reuse]:
  "All tid tid2 x actor actor2 #i #j.
    DH(tid, actor, x)@i & DH(tid2, actor2, x)@j ==> #i = #j"
*/

lemma_rev_dh_ordering/*  [reuse, use_induction]:
  "All tid actor x #j.
    DeleteDH(tid, actor, x)@j==>
      ((Ex #i. DH(tid, actor, x) @ i & i < j) &
       (All #r. RevDHExp(tid, actor, x) @ r  ==>  r < j))"
*/

lemma_rev_dh_before_hs/*  [reuse]:
  "All tid actor role hs x #i #j.
    running(HS, actor, role, hs)@j &
    RevDHExp(tid, actor, x)@i ==>
    #i < #j"
*/

end
