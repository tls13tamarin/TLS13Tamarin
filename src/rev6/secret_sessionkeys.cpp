#define MUTUALAUTH
#define AKC
#define PFS

#define St_init(X,Y,...) St_##X##_##Y##_init(__VA_ARGS__) 
#define St_resume(X,Y,...) St_##X##_##Y##_resume(__VA_ARGS__) 
#define St_loop(X,Y,...) St_##X##_##Y##_loop(__VA_ARGS__) 

//#define In(...) AuthenticMessage(__VA_ARGS__)
//#define Out(...) AuthenticMessage(__VA_ARGS__)

theory TLS_Handshake_secret_sessionkeys
begin

#include "TLS-13-resum.h"
//#include "lemmas.h"

//axiom NEq_check_succeed: "not (Ex x #i. NEq(x,x) @ i)"
//axiom no_server_instance: "not(Ex tid #r. Start(tid, 'server', 'init')@r)"
//axiom no_resume: "not (Ex tid role #r. Start(tid, role, 'resume')@r)"
//axiom no_retry: "not (Ex tid role #r. Start(tid, role, 'retry')@r)" 

//axiom one_send_per_tid: "All tid actor peer appdata key actor2 peer2 appdata2 key2 #r #s. Send(tid,actor,peer,appdata,key)@r&Send(tid,actor2,peer2,appdata2,key2)@s==>#r=#s"
//axiom one_recv_per_tid: "All tid actor peer appdata key actor2 peer2 appdata2 key2 #r #s. Recv(tid,actor,peer,appdata,key)@r&Recv(tid,actor2,peer2,appdata2,key2)@s==>#r=#s"
//axiom one_resume_per_tid: "All tid role role2 #r #s. Start(tid, role, 'resume')@r&Start(tid, role2, 'resume')@s==>#r=#s"

//axiom one_resume_per_role: "All tid tid2 role #r #s. Start(tid, role, 'resume')@r&Start(tid2, role, 'resume')@s==>#r=#s"
//axiom one_retry_per_role: "All role #r #s. Start(role, 'retry')@r&Start(role, 'retry')@s==>#r=#s"
//axiom one_instance_per_role: "All tid tid2 role #r #s. Start(tid,role, 'init')@r&Start(tid2,role,'init')@s==>#r=#s"
//axiom at_most_two_tids: "All tid tid2 tid3 mode role role2 role3 #i #j #k. Start(tid,role,mode)@i&Start(tid2,role2,mode)@j&Start(tid3,role3,mode)@k==>#k=#i|#k=#j" 

/*lemma init_before_retry_for_client [use_induction,reuse]:
  "All tid #i. Start(tid,'client','retry')@i==>
      Ex #j. Start(tid,'client','init')@j & #j<#i"
*/
lemma tid_invariant [use_induction,reuse]:
  "All tid sid role #i. Tid(tid,sid,role)@i==>
      (Ex #j. InitTid(tid,sid,role)@j & #j<#i)"

lemma one_inittid_per_tid [use_induction,reuse]:
  "All tid sid sid2 role role2 #i #j. InitTid(tid,sid,role)@i & InitTid(tid,sid2,role2)@j ==>#i=#j"

//lemma init_unique_per_tid [use_induction,reuse]:
//  "All tid role role2 #i #j. Start(tid,role,'init')@i & Start(tid,role2,'init')@j==>#i=#j"

lemma nc_invariant_for_client [use_induction,reuse]:
  "All tid nc #i. Nc(tid,nc)@i ==> Ex #j. GenNc(tid,nc)@j & #j<#i" 

lemma fresh_secret [use_induction,reuse]:
   "All tid fresh #i #j.
         DH(tid,fresh) @ i
         & KU(fresh) @ j==>
         (Ex #r. RevDHExp(tid)@r)"

/*lemma y [use_induction,reuse]:
  "All tid role #i. Role(tid,role)@i==> Ex #j. Finished(tid,role)@j"

lemma x [use_induction,reuse]:
  "All tid role role2 #i #j. Role(tid,role)@i & Role(tid,role2)@j==>role=role2"
*/

lemma pms_invariant [use_induction,reuse]:
  "All tid actor peer pms #i. LoopPMS(tid,actor,peer,pms)@i==>
          (Ex #j. PMS(tid,actor,peer,pms)@j & #j<#i)"

lemma inittid_before_loop [use_induction,reuse]:
  "All tid sid role #i. Loop(tid,sid,role)@i==>Ex #j. InitTid(tid,sid,role)@j & #j<#i" 

lemma pms_secret [reuse]:
  "All tid actor peer pms #i #j #k. PMS(tid,actor,peer,pms)@i & KU(pms)@j & SecretPMS(tid)@k==>
//#r<#i, not #r<#j because attacker needs key for signing, not pms
         (Ex #r. RevLtk(peer)@r & #r<#i)
         |(Ex #r. RevDHExp(tid)@r)
         |(Ex tid2 #r #s. RevDHExp(tid2) @ r &
          Partner(tid2,tid,peer,actor) @ s)"

/*lemma rms_secret [use_induction,reuse]:
  "All tid actor peer pms rms #i #j. LoopPMS(tid,actor,peer,pms,rms)@i & KU(rms)@j==>
         (Ex #r. RevLtk(peer)@r & #r<#i)
         |(Ex #r. RevDHExp(tid)@r)
         |(Ex tid2 #r #s. RevDHExp(tid2) @ r &
          Partner(tid2,tid,peer,actor) @ s)"

lemma pms_auth [use_induction,reuse]:
  "All tid tid2 pms actor peer sid nc pc ns ps #i. CommitPMS(tid,tid2,pms,actor,peer,sid,nc,pc,ns,ps)@i==>
         (Ex #j. RunningPMS(tid2,tid,pms,peer,actor,sid,nc,pc,ns,ps)@j
          & #j<#i)
         |(Ex #r. RevLtk(peer)@r & #r<#i)
         |(Ex #r. RevDHExp(tid)@r)
         |(Ex tid2 #r #s. RevDHExp(tid2) @ r &
          Partner(tid2,tid,peer,actor) @ s)"
*/

/*lemma unique_finished_per_tidrole [use_induction,reuse]:
   "All tid role #i #j. Finished(tid,role)@i & Finished(tid,role)@j==>#i=#j"
*/

lemma secret_sessionkeys [use_induction]:
   "All tid actor peer pms key #i #j.
          SessionKey(tid, actor, peer, pms, key) @ i
        & KU(key) @ j
        ==>
#ifdef PFS
       	(Ex #r. RevLtk(peer)@r & #r<#i)
	#ifndef AKC
        |(Ex #r. RevLtk(actor)@r & #r<#i)
        #endif
#elif defined(wPFS)
        (Ex #r. RevLtk(peer) @ r & #r<#i)
        |((Ex #r. RevLtk(peer) @ r & #r>#i) & 
          not (Ex tid2 role2 #s. Partner(tid2,tid,peer,actor)@s & 
               Finished(tid2,role2)))
        #ifndef AKC
	(Ex #r. RevLtk(actor) @ r & #r<#i)
        |((Ex #r. RevLtk(actor) @ r & #r>#i) & 
          not (Ex tid2 role2 #s. Partner(tid2,tid,peer,actor)@s & 
               Finished(tid2,role2)))
	#endif
#else
      	(Ex #r. RevLtk(peer)@r)
	#ifndef AKC
        |(Ex #r. RevLtk(actor)@r)
	#endif
#endif
        |(Ex #r. RevDHExp(tid)@r)
        |(Ex tid2 #r #s. RevDHExp(tid2) @ r &
          Partner(tid2,tid,peer,actor) @ s)"


end

