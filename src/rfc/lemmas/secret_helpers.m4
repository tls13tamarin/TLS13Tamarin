changequote(<!,!>)
changecom(<!/*!>,<!*/!>)
define(<!State!>,<!F_State_$1(shift($@))!>)dnl
define(<!ClientCertReq!>,<!L_ClientCertReq($@)!>)dnl
define(<!ServerCertReq!>,<!L_ServerCertReq($@)!>)dnl
define(<!CachePSK!>, <!F_CachePSK($@)!>)dnl

define(<!SecretPSK!>, <!F_SecretPSK($@)!>)dnl


theory TLS_13_secret_helpers
begin

include(header.m4i)
include(model.m4i)
include(all_lemmas.m4i)

uniq(C2d)
/* uniq(C2d_PSK) */
uniq(S2d)
/* uniq(S2d_PSK) */
uniq(C3)
uniq(C3_cert)
uniq(S3)
uniq(S3_cert)

one_of(S3, S3_cert)
one_of(C3, C3_cert)
/* one_of(S2d, S2d_PSK) */
/* one_of(C2d, C2d_PSK) */

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

/*
lemma_nst_source [typing]:
  "All ticket ticket_age_add tkt_lt tkt_exts app_key #i.
    KU(senc{handshake_record('4', tkt_lt, ticket_age_add, ticket, tkt_exts)}app_key)@i ==>
      (Ex #j #k. KU(ticket)@j & KU(ticket_age_add)@k & #j < #i & #k < #i) |
      (Ex tid S #j. running_server(NST, ticket, ticket_age_add)@j & #j < #i)"
*/

lemma_ku_extract/* [reuse, use_induction]:
  "All a b #i. KU(Extract(a, b))@i ==> Ex #j #k. KU(a)@j & KU(b)@k & #j < #i & #k < #i"
*/

lemma_ku_expand/* [reuse, use_induction]:
  "All secret label len #i. KU(Expand(secret, label, len))@i ==>
    (Ex #j. KU(secret)@j & #j < #i) |
    (not (Ex #k. KU(secret)@k & #k < #i) &
    (Ex actor #l. RevealPSK(actor, Expand(secret, label, len))@l & #l < #i))"
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

lemma_ku_hs/* [reuse]:
  "All tid actor role es hs res_psk gxy #i #j.
    running(HS, actor, role, hs)@i &
    hs = HandshakeSecret &
    es = EarlySecret &
    KU(hs)@j ==>
      Ex #k #l. KU(gxy)@k & KU(res_psk)@l & #k < #j & #l < #j"
*/

lemma_dh_exp_invariant/*  [use_induction, reuse]:
  "All tid actor x #i. RevDHExp(tid, actor, x)@i ==>
    Ex #j. DH(tid, actor, x)@j & #j < i"
*/

lemma_ku_ltk/* [reuse]:
  "All actor ltkA #i #j.
    GenLtk(actor, ltkA)@i & KU(ltkA)@j ==>
      Ex #k. RevLtk(actor)@k & #k < #j"
*/

lemma_ku_ss/* [reuse]:
  "All actor ssA #i #j.
    GenSS(actor, ssA)@i & KU(ssA)@j ==>
      Ex #k. RevSS(actor)@k & #k < #j"
*/

/*
lemma_ku_fresh_psk [reuse]:
  "All ticket res_psk #i #k.
      FreshPSK(ticket,res_psk)@i & KU(res_psk)@k ==>
        Ex actor #j.
          RevealPSK(actor, res_psk)@j & #j < #k"
*/

lemma_hsms_derive/* [reuse]:
  "All tid actor role hs ms ss #i.
    running(HSMS, actor, role, hs, ms, ss)@i ==>
      ms = MasterSecretWithSemiStatic"
*/

// For any running(PostHS...) either the auth_status was set in the main HS and
// unchanged (along with the RMS), or there was post-hs auth, which means the
// peer's auth_status is 'auth', the actor is a server*/
/*
lemma_posths_rms [reuse, use_induction]:
  "All tid actor role hs rms peer auth_status messages #i.
    running(PostHS, actor, role, hs, rms, peer, auth_status, messages)@i ==>
      Ex aas pas ms #j.
                running(RMS, actor, role, peer, rms, messages)@j &
                ms = MasterSecretWithSemiStatic & rms = resumption_master_secret() & #j < #i &
                auth_status = <aas, pas> &
      (
        (Ex aas2 #k. commit(Identity, actor, role, peer, <aas2, pas>)@k & #k < #i) |
        (Ex aas2 #k. commit(IdentityPost, actor, role, peer, <aas2, pas>)@k &
                role = 'server' & pas = 'auth' & (#k < #i | #k = #i)
        )
      )"
*/

// A weakened version of the above lemma when needing to avoid the looping
// issue of the commit(IdentityPost, ...) bit.
// Can use [hide_lemma=posths_rms] to only use this version.
/*
lemma_posths_rms_weak [reuse, use_induction]:
  "All tid actor role hs rms peer auth_status messages #i.
    running(PostHS, actor, role, hs, rms, peer, auth_status, messages)@i ==>
      Ex aas pas ms #j.
                running(RMS, actor, role, peer, rms, messages)@j &
                ms = MasterSecretWithSemiStatic & rms = resumption_master_secret() & #j < #i &
                auth_status = <aas, pas>"
*/



lemma_matching_transcripts_posths/* [reuse]:
  "All tid tid2 actor peer actor2 peer2 role role2 rms rms2 messages #i #j.
    running(RMS, actor, role, peer2, rms, messages)@i &
    running2(RMS, peer, role2, actor2, rms2, messages)@j & not (role = role2) ==>
     rms = rms2"
*/

lemma_matching_rms_posths/* [reuse]:
  "All tid tid2 actor peer actor2 peer2 role role2 rms messages messages2 #i #j.
    running(RMS, actor, role, peer2, rms, messages)@i &
    running2(RMS, peer, role2, actor2, rms, messages2)@j & not (role = role2) ==>
     messages = messages2"
*/

lemma_matching_rms_actors/* [reuse]:
  "All tid tid2 actor peer actor2 peer2 role rms messages messages2 #i #j.
    running(RMS, actor, role, peer, rms, messages)@i &
    running2(RMS, actor2, role, peer2, rms, messages2)@j ==>
     actor = actor2 & tid = tid2"
*/

lemma_rev_dh_before_hs/*  [reuse]:
  "All tid actor role hs x #i #j.
    running(HS, actor, role, hs)@j &
    RevDHExp(tid, actor, x)@i ==>
    #i < #j"
*/

lemma_matching_sessions/* [reuse, use_induction, hide_lemma=posths_rms]:
  "All tid tid2 actor actor2 role role2 peer peer2 rms messages #i #j #k.
    running(RMS, actor, role, peer2, rms, messages)@i &
    running2(RMS, peer, role2, actor2, rms, messages)@j &
    not (role = role2) &
    KU(rms)@k ==>
      (Ex tid3 x #r. RevDHExp(tid3, actor, x)@r & #r < #i) |
      (Ex tid4 y #r. RevDHExp(tid4, peer, y)@r & #r < #j) |
      (Ex rms2 #r. RevealPSK(actor, rms2)@r & #r < #k) |
      (Ex rms2 #r. RevealPSK(peer, rms2)@r & #r < #k)"
*/

lemma_sig_origin/* [reuse]:
  "All certificate certificate_request_context signature verify_data hs_key ss_key sig_messages ssA  #i.
        KU(senc{Certificate, CertificateVerify, Finished}hs_key)@i & (signature = hmac(ss_key,sig_messages)) & DeriveFromSS(ssA, ss_key)@i ==>
      (Ex #j. KU(ssA)@j & #j < i) | (Ex #k. UseSS(ssA, signature)@k & #k < #i)"
*/

/*
lemma_post_master_secret [reuse, hide_lemma=posths_rms]:
  "All tid actor peer role hs rms aas messages #i #k.
    running(PostHS, actor, role, hs, rms, peer, <aas, 'auth'>, messages)@i &
    commit(HS, actor, role, hs)@i &
    commit(IdentityPost, actor, role, peer, <aas, 'auth'>)@i &
    KU(rms)@k ==>
      (Ex #r. RevLtk(peer)@r & #r < #i) |
      (Ex tid3 x #r. RevDHExp(tid3, peer, x)@r & #r < #i) |
      (Ex tid4 y #r. RevDHExp(tid4, actor, y)@r & #r < #i) |
      (Ex rms2 #r. RevealPSK(actor, rms2)@r & #r < #k) |
      (Ex rms2 #r. RevealPSK(peer, rms2)@r & #r < #k)"
*/

/*
lemma_invariant_post_hs [reuse, use_induction, hide_lemma=posths_rms]:
  "All tid actor peer peer2 role hs hs2 rms rms2 as as2 msgs msgs2 #i #j.
    running(PostHS, actor, role, hs, rms, peer, as, msgs)@i &
    running(PostHS, actor, role, hs2, rms2, peer2, as2, msgs2)@j ==>
      peer = peer2 & rms = rms2 & msgs = msgs2 & hs = hs2"
*/


/*
  Strategy:
  Intutition is that if two matching RMS then at some point a cert was hashed
  into the handshake.

  To prove this, if RRMS and CommitIdentity(,... 'auth')
  and RRMS2 is matching,
  then there either there exists UseLtk and UsePk for the same person,
  or RevLtk of peer.

  This will have to prove inductively over both RRMS (similar to matching sessions)
  in fact, can probably roll it in to matching_sessions?


*/


lemma_auth_psk/* [reuse, use_induction, hide_lemma=posths_rms_weak]:
  "All tid tid2 actor actor2 role role2 peer peer2 rms messages aas #i #j #k.
    running(RMS, actor, role, peer2, rms, messages)@i &
    running2(RMS, peer, role2, actor2, rms, messages)@j &
    commit(Identity, actor, role, <peer, <aas, 'auth'>>)@k &
    not (role = role2)
     ==>
      peer2 = peer |
      Ex #r. RevLtk(peer2)@r & #r < #k"
*/

lemma_rev_dh_ordering/*  [reuse, use_induction]:
  "All tid actor x #j.
    DeleteDH(tid, actor, x)@j==>
      ((Ex #i. DH(tid, actor, x) @ i & i < j) &
       (All #r. RevDHExp(tid, actor, x) @ r  ==>  r < j))"
*/

lemma_matching_hsms/* [reuse]:
  "All tid actor role hs hs2 ms #i #j.
    commit(HS, actor, role, hs2)@i &
    running(HSMS, actor, role, hs, ms)@j ==>
      hs = hs2"
*/

lemma_handshake_secret/* [reuse, use_induction, hide_lemma=posths_rms_weak]:
  "All tid actor peer role hs aas #i #k.
    commit(HS, actor, role, hs)@i &
    commit(Identity, actor, role, peer, <aas, 'auth'>)@i &
    KU(hs)@k ==>
        (Ex #r. RevLtk(peer)@r & #r < #i) |
        (Ex tid3 x #r. RevDHExp(tid3, peer, x)@r & #r < #i) |
        (Ex tid4 y #r. RevDHExp(tid4, actor, y)@r & #r < #i) |
        (Ex rms #r. RevealPSK(actor, rms)@r & #r < #k) |
        (Ex rms #r. RevealPSK(peer, rms)@r & #r < #k)"
*/

lemma_pfs_handshake_secret/* [reuse, hide_lemma=posths_rms_weak]:
  "All tid actor peer role hs aas psk_ke_mode #i #k.
    commit(HS, actor, role, hs)@i &
    running(Mode, actor, role, psk_ke_mode)@i &
    commit(Identity, actor, role, peer, <aas, 'auth'>)@i &
    KU(hs)@k &
    (not psk_ke_mode = psk_ke) ==>
        (Ex #r. RevLtk(peer)@r & #r < #i) |
        (Ex tid3 x #r. RevDHExp(tid3, peer, x)@r & #r < #i) |
        (Ex tid4 y #r. RevDHExp(tid4, actor, y)@r & #r < #i) |
        (Ex rms #r. RevealPSK(actor, rms)@r & #r < #i) |
        (Ex rms #r. RevealPSK(peer, rms)@r & #r < #i)"
*/

end
