changequote(<!,!>)
changecom(<!/*!>,<!*/!>)
define(<!State!>,<!F_State_$1(shift($@))!>)dnl
define(<!ClientCertReq!>,<!L_ClientCertReq($@)!>)dnl
define(<!ServerCertReq!>,<!L_ServerCertReq($@)!>)dnl
define(<!CachePSK!>, <!F_CachePSK($@)!>)dnl

define(<!SecretPSK!>, <!F_SecretPSK($@)!>)dnl


theory TLS_13_invariants
begin

include(header.m4i)
include(model.m4i)
include(all_lemmas.m4i)

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

lemma_one_start_per_tid/* [reuse]:
  "All tid actor actor2 role role2 #i #j. Start(tid, actor, role)@i & Start(tid, actor2, role2)@j ==>#i=#j"
*/

lemma_cert_req_origin/* [typing]:
  "All certificate_request_context certificate_extensions keys #i.
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

end