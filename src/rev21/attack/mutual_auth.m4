changequote(<!,!>)dnl
changecom(<!/*!>,<!*/!>)dnl
dnl
define(<!State!>,<!State_$1(shift($@))!>)dnl
dnl
define(<!In!>,<!F_MessageIn($*)!>)dnl
define(<!Out!>,<!MessageOut($*)!>)dnl
dnl

theory Mutual_Authentication_Agreement 
begin

include(header.m4i)
dnl include(model.m4i)
include(actions.m4i)
include(crypto.m4i)
include(msgs.m4i)
include(state.m4i)

include(pki.m4i)
include(client_basic.m4i)
include(server_basic.m4i)
dnl include(psk.m4i)
include(record.m4i)
dnl include(zero_rtt.m4i)
include(post_hs.m4i)
dnl include(adversary.m4i)

rule in_out:
[MessageOut(m)]-->[F_MessageIn(m)]

define(<!create_lemma!>, <!
lemma one_$1_per_tid [reuse]:
    "All tid #i #j. $1(tid)@i & $1(tid)@j ==> #i = #j"
!>)

create_lemma(C2d)
create_lemma(S2d)
create_lemma(C3)
create_lemma(C3_cert)
create_lemma(S3)
create_lemma(S3_cert)

lemma s3_vs_s3_cert [reuse]:
  "All tid #i #j. S3(tid)@i & S3_cert(tid)@j ==> F"

lemma c3_vs_c3_cert [reuse]:
  "All tid #i #j. C3(tid)@i & C3_cert(tid)@j ==> F"


lemma server_agree_auth [reuse]:
  "All tid tid2 actor peer auth_status_client auth_status_server data #i #j.
      SendData(tid, actor, peer, <'auth', auth_status_server>, data)@i &
      RecvData(tid2, peer, actor, <auth_status_server, auth_status_client>, data)@j
      ==> Ex #k. commit2(Identity, peer, 'server',  actor, <auth_status_server, 'auth'>)@k &
     #k < #j"

lemma client_agree_auth [reuse]:
  "All tid actor peer auth_status_client auth_status_server data #i.
      RecvData(tid, actor, peer, <auth_status_client, auth_status_server>, data)@i 
      ==> Ex tid2 #j. commit2(Identity, peer, 'server', actor, <auth_status_server, auth_status_client>)@j &
      #j < #i" 

end
