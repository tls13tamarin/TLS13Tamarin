#define MUTUALAUTH
#define AKC
#define PFS

#define St_init(X,Y,...) F_St_##X##_##Y##_init(__VA_ARGS__) 
#define St_resume(X,Y,...) St_##X##_##Y##_resume(__VA_ARGS__) 
#define St_loop(X,Y,...) St_##X##_##Y##_loop(__VA_ARGS__) 

#define In(...) AuthenticMessage(__VA_ARGS__)
#define Out(...) AuthenticMessage(__VA_ARGS__)

theory TLS_Handshake_send_appdata_possible
begin

#include "TLS-13-resum.h"

//axiom NEq_check_succeed: "not (Ex x #i. NEq(x,x) @ i)"
//axiom no_server_instance: "not(Ex tid #r. Start(tid, 'server', 'init')@r)"
//axiom no_retry: "not (Ex tid role #r. Start(tid, role, 'retry')@r)" 
//axiom no_resume: "not (Ex tid role #r. Start(tid, role, 'resume')@r)"
axiom one_send_per_tid: "All tid actor peer appdata key actor2 peer2 appdata2 key2 #r #s. Send(tid,actor,peer,appdata,key)@r&Send(tid,actor2,peer2,appdata2,key2)@s==>#r=#s"
axiom one_recv_per_tid: "All tid actor peer appdata key actor2 peer2 appdata2 key2 #r #s. Recv(tid,actor,peer,appdata,key)@r&Recv(tid,actor2,peer2,appdata2,key2)@s==>#r=#s"
axiom one_resume_per_role: "All tid tid2 role #r #s. Start(tid, role, 'resume')@r&Start(tid2, role, 'resume')@s==>#r=#s"
axiom one_retry_per_role: "All tid tid2 role #r #s. Start(tid, role, 'retry')@r&Start(tid2, role, 'retry')@s==>#r=#s"
axiom one_instance_per_role: "All tid tid2 role #r #s. Start(tid, role, 'init')@r&Start(tid2, role,'init')@s==>#r=#s"

lemma send_appdata_possible:
  exists-trace
   "Ex tid tid2 actor peer appdata key #i #j #k #l #m.
     Retry('server')@i &
     Start(tid2, 'client', 'retry')@j &
     Start(tid2, 'client', 'resume')@k &
     Send(tid2, actor, peer, appdata, key)@l &
     Recv(tid, actor, peer, appdata, key)@m 
     & #i<#j & #j<#k & #k<#l & #l<#m"

end
