changequote(<!,!>)
changecom(<!/*!>,<!*/!>)
pushdef(<!F_State_S4!>, <!L_State_S4($@)!>)dnl
pushdef(<!F_State_C4!>, <!L_State_C4($@)!>)dnl
define(<!State!>,<!F_State_$1(shift($@))!>)dnl
define(<!ClientCertReq!>,<!L_ClientCertReq($@)!>)dnl
define(<!ServerCertReq!>,<!L_ServerCertReq($@)!>)dnl
define(<!CachePSK!>, <!F_CachePSK($@)!>)dnl


theory TLS_13_auth_helpers
begin

include(header.m4i)
include(model.m4i)
include(all_lemmas.m4i)

uniq(C0)
uniq(C1_retry)
uniq(S1)
uniq(C1)
uniq(C2d)
uniq(C2d_PSK)
uniq(S2d)
uniq(S2d_PSK)
uniq(C3)
uniq(C3_cert)
uniq(S3)
uniq(S3_cert)

one_of(S3, S3_cert)
one_of(C3, C3_cert)
one_of(S2d, S2d_PSK)
one_of(C2d, C2d_PSK)


lemma_tid_invariant/* [use_induction, reuse]:
  "All tid actor role #i. Instance(tid, actor, role)@i==>
      (Ex #j. Start(tid, actor, role)@j & (#j < #i))"
*/

lemma_one_start_per_tid/* [use_induction, reuse]:
  "All tid actor actor2 role role2 #i #j. Start(tid, actor, role)@i & Start(tid, actor2, role2)@j ==>#i=#j"
*/

lemma_matching_nonces/* [reuse]:
  "All tid tid2 actor actor2 role  nonces #i #j. 
    running(Nonces, actor, role, nonces)@i & 
    running2(Nonces, actor2, role, nonces)@j ==>
    tid = tid2 & actor = actor2"
*/

lemma_consistent_nonces/* [reuse]:
  "All tid actor role nonces #i. 
    commit(Nonces, actor, role, nonces)@i ==>
      Ex #j. running(Nonces, actor, role, nonces)@j"
*/

lemma_invariant_nonces/*[reuse]:
  "All tid actor actor2 role role2 nonces nonces2 #i #j.
    running(Nonces, actor, role, nonces)@i & 
    running(Nonces, actor2, role2, nonces2)@j ==> #i = #j"
*/

lemma_matching_rms_nonces/* [reuse]:
  "All nonces tid tid2 actor actor2 peer peer2 rms messages #i #j. 
    running(RMS, actor, 'client', peer, rms, messages)@i &
    running2(RMS, actor2, 'server', peer2, rms, messages)@j &
    commit2(Nonces, actor2, 'server', nonces)@j ==>
      Ex #a.
        commit(Nonces, actor, 'client', nonces)@a & 
        #a < #i"
*/

end

popdef(<!F_State_S4!>)
popdef(<!F_State_C4!>)
