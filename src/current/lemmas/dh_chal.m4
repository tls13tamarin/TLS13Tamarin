changequote(<!,!>)
changecom(<!/*!>,<!*/!>)
define(<!State!>,<!F_State_$1(shift($@))!>)
define(<!ClientCertReq!>,<!L_ClientCertReq($@)!>)
define(<!ServerCertReq!>,<!L_ServerCertReq($@)!>)
define(<!CachePSK!>, <!F_CachePSK($@)!>)
define(<!ClientPSK!>, <!L_ClientPSK($@)!>)
define(<!ServerPSK!>, <!L_ServerPSK($@)!>)


theory TLS_13_dh_chal
begin

include(header.m4i)
include(model.m4i)
include(all_lemmas.m4i)

uniq(C0)
uniq(C1_retry)
uniq(S1)
uniq(C1)

lemma_cert_req_origin
/*  "All certificate_request_context certificate_extensions keys #i.
    KU(senc{handshake_record('13', certificate_request_context, certificate_extensions)}keys)@i ==> 
      (Ex #j. KU(certificate_request_context)@j & #j < #i) |
      (Ex #j tid actor role. running(CertReqCtxt, actor, role, certificate_request_context)@j & #j < #i)"
*/

lemma_nst_source/* [typing]:
  "All ticket ticket_age_add tkt_lt tkt_exts app_key #i.
    KU(senc{handshake_record('4', tkt_lt, ticket_age_add, ticket, tkt_exts)}app_key)@i ==>
      (Ex #j #k. KU(ticket)@j & KU(ticket_age_add)@k & #j < #i & #k < #i) |
      (Ex tid S #j. running_server(NST, ticket, ticket_age_add)@j & #j < #i)"
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


lemma_dh_chal_dual/* [reuse]:
  "All tid tid2 actor actor2 g x y gx gy gxy #i #j #r.
      DHChal(g, x, y, gx, gy, gxy)@i & Instance(tid, actor, 'client')@i &
      DHChal(g, x, y, gx, gy, gxy)@j & Instance(tid2, actor2, 'server')@j &
      KU(gxy)@r 
      ==> 
      (Ex #p. (RevDHExp(tid, actor,  x)@p & #p < #r)) | 
      (Ex #q. (RevDHExp(tid2, actor2, y)@q & #q < #r))"
// "All g x y gx gy gxy #i #r. DHChal(g, x, y, gx, gy, gxy)@i & KU(gxy)@r ==> (Ex #j. KU(x)@j & #j < #r) | (Ex #j. KU(y)@j & #j < #r)"
*/

end
