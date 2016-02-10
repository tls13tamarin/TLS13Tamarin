/* TLS 1.3 modelled after draft-ietf-tls-tls13-07
   (07 July 2015; expires 8 January 2016) */

#define L '256'

//Definition of C1 (client's handshake message)

#define ClientHello C, nc, sid, pc
#define ClientKeyShare X
#define MSGS1 ClientHello, ClientKeyShare

#ifdef MUTUALAUTH
#define ClientCertificate C, pk(ltkC)
#define HASH1 MSGS1, ClientCertificate 
#define ClientCertificateVerify sign{h('client_certificate_verify', HASH1)}ltkC
#define HASH2 HASH1, ClientCertificateVerify
#define ENC1 ClientCertificate,ClientCertificateVerify,earlydata
#else
#define HASH2 MSGS1
#define ENC1 earlydata
#endif

#define xSS HKDF('0',ss,'extractedSS',L)
#define xES HKDF('0',es,'extractedES',L)
#define MS HKDF(xSS,xES,'master_secret',L)
#define EDKEY HKDFExpand(xSS,'early_data_key_expansion',h(h(MSGS1)),L)
#define C1 MSGS1, senc{ENC1}EDKEY

//Definition of S0 (server handshake message 0)

#define HelloRetryRequest S, ps 

//Definition of S1

#define ServerHello S, ns, sid, ps
#define ServerKeyShare Y
#define MSGS2 ServerHello,ServerKeyShare 


#define ServerEncryptedExtensions $encext
#define ServerConfiguration ltkS
#define ServerCertificate S, pk(ltkS)
#define ServerCertificateRequest $certreq
#define MSGS3 ServerEncryptedExtensions, ServerConfiguration, ServerCertificate, ServerCertificateRequest 
#define FHASH1 MSGS1, MSGS2, MSGS3
#define FServerCertificateVerify sign{h('server_certificate_verify', FHASH1)}ltkS
#define FHASH2 FHASH1, FServerCertificateVerify
#define FFS HKDFExpand(xSS,'finished_secret',h(h(FHASH2)),L)
#define FServerFinished hmac(FFS, 'server_finished', h(h(FHASH2)))
#define FENC1 ServerEncryptedExtensions, ServerCertificate, ServerCertificateRequest, FServerCertificateVerify, FServerFinished
#define FHKEYC HKDFExpand1(xES, 'handshake_key_expansion', h(h(FHASH2)),L)
#define FHKEYS HKDFExpand2(xES, 'handshake_key_expansion', h(h(FHASH2)),L)
#define FS1 ServerHello, ServerKeyShare, senc{FENC1}FHKEYS


#define HASHFINS MSGS1, ENC1, MSGS2
#define FS HKDFExpand(xSS,'finished_secret',h(h(HASHFINS)),L)
#define RS HKDFExpand(MS, 'resumption_master_secret',h(h(HASHFINS)),L)
#define ES HKDFExpand(MS, 'exporter_master_secret',h(h(HASHFINS)),L)
#define ServerFinished hmac(FS, 'server_finished', h(h(HASHFINS)))

//in 0-rtt, HASH3 coincides with HASHFINS
#define HASH3 MSGS1,ENC1,MSGS2
#define HKEYC HKDFExpand1(xES, 'handshake_key_expansion', h(h(HASH3)),L)
#define HKEYS HKDFExpand2(xES, 'handshake_key_expansion', h(h(HASH3)),L)
#define S1 MSGS2, senc{ServerFinished}HKEYS


//Definition of C2
//in 0-rtt, input to server and client finished seems to be defined
//as the same, but there is the following confusing statement:
//   The input to the client and server Finished messages may not be the
//   same because the server's Finished does not include the client's
//   Certificate and CertificateVerify message.

#ifdef MUTUALAUTH
#define ClientCertificate C, pk(ltkC)
#define FClientCertificateVerify sign{h('client_certificate_verify', FHASH2, FServerFinished, ClientCertificate)}ltkC
#define FHASH3 FHASH2, ClientCertificate, FClientCertificateVerify 
#define FHASH4 FHASH2, FServerFinished, ClientCertificate, FClientCertificateVerify
#define FClientFinished hmac(FFS, 'client_finished', h(h(FHASH4)))
#define FC2 ClientCertificate, FClientCertificateVerify, FClientFinished
#else
#define FClientFinished hmac(FFS, 'client_finished', h(h(FHASH2, FServerFinished)))
#define FC2 FClientFinished
#endif

#define HelloRetryRequest S, ps 

#define ClientFinished hmac(FS, 'client_finished', h(h(HASHFINS)))
#define C2 senc{ClientFinished}HKEYC

/*#define HMSres PRF(pms, 'handshake_master_secret', h(C1, ServerHello))
#define MSres PRF(HMSres, 'extended_master_secret', h(C1, ServerHello))
#define RMSres PRF(HMSres, 'resumption_premaster_secret', h(C1, ServerHello))
#define HKEYCres PRFfirst48(HMSres, 'key_expansion', ns, nc)
#define HKEYSres PRFsecond48(HMSres, 'key_expansion', ns, nc)
#define ServerFinishedres PRF(HMSres, 'server_finished', h(C1, ServerHello))
#define S1res ServerHello, senc{ServerFinishedres}HKEYSres
#define C2res PRF(HMSres, 'client_finished', h(C1, ServerHello, ServerFinishedres))
*/

#define KEYC HKDFExpand1(MS, 'application_data_key_expansion', h(h(HASHFINS)),L)
#define KEYS HKDFExpand2(MS, 'application_data_key_expansion', h(h(HASHFINS)),L)
#define IVC HKDFExpand3(MS, 'application_data_key_expansion', h(h(HASHFINS)),L)
#define IVS HKDFExpand4(MS, 'application_data_key_expansion', h(h(HASHFINS)),L)

#define FKEYC HKDFExpand1(MS, 'application_data_key_expansion', h(h(FHASH2)),L)
#define FKEYS HKDFExpand2(MS, 'application_data_key_expansion', h(h(FHASH2)),L)
#define FIVC HKDFExpand3(MS, 'application_data_key_expansion', h(h(FHASH2)),L)
#define FIVS HKDFExpand4(MS, 'application_data_key_expansion', h(h(FHASH2)),L)

/*#define KEYCres PRFfirst48(MSres, 'key_expansion', ns, nc)
#define KEYSres PRFsecond48(MSres, 'key_expansion', ns, nc)
#define IVCres PRFthird48(MSres, 'key_expansion', ns, nc)
#define IVSres PRFfourth48(MSres, 'key_expansion', ns, nc)
*/

#define C_APPDATA $paramsc, ~nexpc, senc{~plainc, $padc}keyc, mac(keyc, $paramsc, ivc, ~nexpc, senc{~plainc, $padc}keyc)
#define S_APPDATA $paramss, ~nexps, senc{~plains, $pads}keys, mac(keys, $paramss, ivs, ~nexps, senc{~plains, $pads}keys)

builtins: diffie-hellman, hashing, symmetric-encryption,  signing

section{* TLS 1.3 *}

/*
 * Protocol:	TLS 1.3 Handshake and Record Protocols, Proposal A, rev. 7
 * Modeler: 	Cas Cremers, Marko Horvat
 * Year: 	2015
 * Source:      http://tlswg.github.io/tls13-spec/	
 *
 * Status: 	certainly NOT working
 */

// Hash declarations

functions: HKDF/1, HKDFExpand/1, HKDFExpand1/1, HKDFExpand2/1, HKDFExpand3/1, HKDFExpand4/1, hmac/1, mac/1

// Public key infrastructure

rule Register_pk:
  [ Fr(~ltkA) ]
  -->
  [ !Ltk($A, ~ltkA), !Pk($A, pk(~ltkA)), Out(pk(~ltkA)) ]

rule Reveal_Ltk:
  [ !Ltk($A, ~ltkA) ] --[ RevLtk($A) ]-> [ Out(~ltkA) ]

rule Reveal_DHExp:
  [ DHExp(~tid,~x) ] --[ RevDHExp(~tid) ]-> [ Out(~x) ] 

// Protocol specification

rule C_1:
let
    tid = ~nc
    C   = $C
    nc  = ~nc
    sid = ~sid
    pc  = $pc
    X   = 'g'^~x
in
    [ Fr(nc)
    , Fr(sid)
    , Fr(~x)
    ]
  --[ Start(tid, 'client','init')
    , DH(tid, ~x)
    , InitSid(tid,sid)
    , GenNc(tid,nc)
    , InitTid(tid,sid,'client')
    ]->
    [ Out(<MSGS1>)
    , DHExp(tid, ~x)
    , St_init(C,1, tid, C, nc, sid, pc, ~x)
    ]

rule C_1_0rtt:
let
    tid = ~nc
    S   = $S
    C   = $C
    nc  = ~nc
    sid = ~sid
    pc  = $pc
    X   = 'g'^~x
    ss  = 'g'^~x^~ltkS
    earlydata = ~earlydata
    ltkC = ~ltkC
    ltkS = ~ltkS
in
    [ Fr(nc)
    , Fr(sid)
    , Fr(~x)
    , Fr(~earlydata)
    , !Ltk(S,ltkS)
#ifdef MUTUALAUTH
    , !Ltk(C, ltkC)
#endif
    ]
  --[ Start(tid, 'client','init')
    , DH(tid, ~x)
    , GenSid(tid,sid)
    ]->
    [ Out(<C1>)
    , Fresh(tid, ~x)
    , St_init_0rtt(C,1, tid, ss, S, C, nc, sid, pc, ~x)
    ]

rule C_1_retry:
let
    X = 'g'^~x2
    nc = ~nc
    sid = ~sid
//added typing for resume
    C = $C
    pc  = $pc
in
    [ Fr(~x2)
    , In(<HelloRetryRequest>)
    , St_init(C,1, ~tid, C, nc, sid, pc, ~x) ]
  --[
      Start(~tid, 'client','retry') 
    , DH(~tid,~x2)
    , Nc(~tid,nc)
    , Retry('client')
    , Tid(~tid,sid,'client')
    ]->
    [ Out(<MSGS1>)
    , DHExp(~tid, ~x2)
    , St_init(C,1, ~tid, C, nc, sid, pc, ~x2) ]

/*
rule C_1_resume:
let
    nc  = ~nc
    X   = 'g'^~x
//added typing for resume
    C = $C
    S = $S
    ns = ~ns
    pc = $pc
    ps = $ps
    sid = ~sid
in
    [ Fr(nc)
    , Fr(~x)
    , St_loop(C,0, ~tid, S, C, sid, ps, pc, pms, ncOld, ns, XOld, Y, ivc, ivs, keyc, keys)
    ]
  --[ Start(~tid, 'client','resume')
    , DH(~tid, ~x)
    , Sid(~tid,sid)
    ]->
    [ Out(<C1>)
    , Fresh(~tid, ~x)
    , St_resume(C,1, ~tid, S, C, sid, ps, pc, pms, nc, ns, X, Y)
    ]
*/

rule S_1:
let
    tid = ~ns
//  tid2= nc
    S  = $S
    ns = ~ns
    ps = $ps
    Y  = 'g'^~y
    es = X^~y
    ss  = X^~ltkS
    ltkS = ~ltkS
//added typing for resume
    C = $C
    nc = ~nc
    pc = $pc
    sid = ~sid
    tid2 = ~nc
in
    [ In(<MSGS1>)
    , Fr(ns)
    , Fr(~y)
    , !Ltk(S, ltkS)
    ]
  --[ Start(tid, 'server','init')
    , Partner(tid, tid2, S, C)
    , DH(tid, ~y)
    , RunningSecrets(tid,tid2,es,ss,S,C,sid,nc,pc,ns,ps)
    , InitTid(tid,sid,'server')
    ]->
    [ Out(<FS1>)
    , DHExp(tid, ~y)
    , St_init(S,1, tid, S, C, sid, nc, pc, ns, ps, es, ss )
    ]

rule S_1_0rtt:
let
    tid = ~ns
//  tid2= nc
    S  = $S
    ns = ~ns
    ps = $ps
    Y  = 'g'^~y
    es = X^~y
    ss  = X^~ltkS
    ltkS = ~ltkS
//added typing for resume
    C = $C
    nc = ~nc
    pc = $pc
    sid = ~sid
    tid2 = ~nc
    earlydata = ~earlydata
in
    [ In(<C1>)
    , Fr(ns)
    , Fr(~y)
    , !Ltk(S, ltkS)
    ]
  --[ Start(tid, 'server','init')
    , Partner(tid, tid2, S, C)
    , DH(tid, ~y)
    , RunningES(tid,tid2,es,ss,S,C,sid,nc,pc,ns,ps)
    //, Running(C, S, <'client', MS>) //S DOES NOT YET COMPUTE MS!
    ]->
    [ Out(<S1>)
    , DHExp(tid, ~y)
    , St_init_0rtt(S,1, tid, S, C, sid, nc, pc, ns, ps, es, ss)
    ]

rule S_1_retry:
let
    S  = $S
    ps = $ps
//added typing for resume
    C = $C
    nc = ~nc
    pc = $pc
    sid = ~sid
in
    [ In(<MSGS1>)
    ]
  --[ Retry('server')
    ]->
    [ Out(<HelloRetryRequest>)
    ]

/*
rule S_1_resume:
let
    ns = ~ns
//added typing for resume
    C = $C
    S = $S
    nc = ~nc
    pc = $pc
    ps = $ps
    sid = ~sid
in
    [ In(<C1>)
    , Fr(ns)
    , St_loop(S,0, ~tid, S, C, sid, ps, pc, pms, ncOld, nsOld, XOld, Y, ivc, ivs, keyc, keys)
    ]
  --[ Start(~tid, 'server','resume')
#ifdef MUTUALAUTH
    , Sid(~tid,sid)
#endif
    ]->
    [ Out(<S1res>)
    , St_resume(S,1, ~tid, S, C, sid, ps, pc, pms, nc, ns, X, Y)
    ]
*/

rule C_2:
  let
//  tid2 = ns
    X   = 'g'^~x
    es = Y^~x
    ss = 'g'^~x^~ltkS
    nc = ~nc
    sid = ~sid
    ltkC = ~ltkC
    ltkS = ~ltkS
//added typing for resume
    C = $C
    S = $S
    ns = ~ns
    pc = $pc
    ps = $ps
    tid2= ~ns
  in
    [ In(<FS1>)
    , !Ltk(S, ltkS)
#ifdef MUTUALAUTH
    , !Ltk(C, ltkC)
#endif
    , St_init(C,1, ~tid, C, nc, sid, pc, ~x)
    ]
  --[ Running(~tid, S, C, <'server', MS>)
    , SessionKey( ~tid, C, S, FKEYC )
    , SessionKey( ~tid, C, S, FKEYS )
    , Finished(~tid,'client')
    , Partner(~tid, tid2, C, S)
    , Secrets(~tid,C,S,es,ss)
    , Secret(~tid)
    , Tid(~tid,sid,'client')
    , RunningSecrets(~tid,tid2,es,ss,C,S,sid,nc,pc,ns,ps)
    , CommitSecrets(~tid,tid2,es,ss,C,S,sid,nc,pc,ns,ps)
    ]->
    [ Out(senc{FC2}FHKEYC)
    , St_loop(C,0, ~tid, S, C, sid, ps, pc, nc, ns, X, Y, FIVC, FIVS, FKEYC, FKEYS)
    ]

rule C_2_0rtt:
  let
//  tid2 = ns
    X   = 'g'^~x
    es = Y^~x
    ss = 'g'^~x^~ltkS
    nc = ~nc
    sid = ~sid
    ltkC = ~ltkC
    ltkS = ~ltkS
//added typing for resume
    C = $C
    S = $S
    ns = ~ns
    pc = $pc
    ps = $ps
    tid2= ~ns
  in
    [ In(<S1>)
    , !Ltk(S, ltkS)
#ifdef MUTUALAUTH
    , !Ltk(C, ltkC)
#endif
    , St_init_0rtt(C,1, ss, ~tid, S, C, nc, sid, pc, ~x)
    ]
  --[ Running(~tid, S, C, <'server', MS>)
    , SessionKey( ~tid, C, S, KEYC )
    , SessionKey( ~tid, C, S, KEYS )
    , Finished(~tid,'client')
    , Partner(~tid, tid2, C, S)
    , Secrets(~tid,C,S,es,ss)
    , RunningSecrets(~tid,tid2,es,ss,C,S,sid,nc,pc,ns,ps)
    , CommitSecrets(~tid,tid2,es,ss,C,S,sid,nc,pc,ns,ps)
    //, Commit(C, S, <'client', MS>) FALSE---NO CAUSALLY PRECEDING RUNNING!
    ]->
    [ Out(<C2>)
    , LoopSecrets(~tid,C,S,es,ss)
    , St_loop(C,0, ~tid, S, C, sid, ps, pc, nc, ns, X, Y, IVC, IVS, KEYC, KEYS)
    ]

/*
rule C_2_resume:
let
    nc = ~nc
    sid = ~sid
//added typing for resume
    C = $C
    S = $S
    ns = ~ns
    pc = $pc
    ps = $ps
in
    [ In(<S1res>)
    , St_resume(C,1, ~tid, S, C, sid, ps, pc, pms, nc, nsOld, X, Y)
    , LoopPMS(~tid,C,S,pmsOld,pms)
    ]
  --[ SessionKey( ~tid, C, S, KEYCres )
    , SessionKey( ~tid, C, S, KEYSres )
    , LoopPMS(~tid,C,S,pmsOld,pms)
    , Sid(~tid,sid)
    ]->
    [ Out(senc{C2res}HKEYCres)
    , St_loop(C,0, ~tid, S, C, sid, ps, pc, RMSres, nc, ns, X, Y, IVCres, IVSres, KEYCres, KEYSres)
    , LoopPMS(~tid,C,S,pmsOld,RMSres)
    ]
*/

rule S_2:
let
    ns = ~ns
    ltkC = ~ltkC
    ltkS = ~ltkS
//added typing for resume
    C = $C
    S = $S
    nc = ~nc
    pc = $pc
    ps = $ps
    sid = ~sid
    tid2 = ~nc
in
    [ In(senc{FC2}HKEYC)
#ifdef MUTUALAUTH
    , !Ltk(C, ltkC)
#endif
    , !Ltk(S, ltkS)
    , St_init(S,1, ~tid, S, C, sid, nc, pc, ns, ps, es, ss)
    ]
  --[ Finished(~tid,'server')
    , Tid(~tid,sid,'server')
    , Secrets(~tid,S,C,es,ss)
#ifdef MUTUALAUTH
    , Secret(~tid)
    , SessionKey(~tid, S, C, KEYC )
    , SessionKey(~tid, S, C, KEYS )
    , Commit(~tid, S, C, <'server', MS>)
    , CommitSecrets(~tid,tid2,es,ss,S,C,sid,nc,pc,ns,ps)
#endif
    ]->
    [ St_loop(S,0, ~tid, S, C, sid, ps, pc, nc, ns, X, Y, FIVC, FIVS, FKEYC, FKEYS)
#ifdef PSK
    , Out(<senc{NewSessionTicket}FKEYS>)
#endif
    ]

rule S_2_0rtt:
let
    ns = ~ns
    ltkC = ~ltkC
    ltkS = ~ltkS
//added typing for resume
    C = $C
    S = $S
    nc = ~nc
    pc = $pc
    ps = $ps
    sid = ~sid
    tid2 = ~nc
in
    [ In(<C2>)
#ifdef MUTUALAUTH
    , !Ltk(C, ltkC)
#endif
    , !Ltk(S, ltkS)
    , St_init_0rtt(S,1, ~tid, S, C, sid, nc, pc, ns, ps, es, ss)
    ]
  --[ Finished(~tid,'server')
#ifdef MUTUALAUTH
    , SessionKey(~tid, S, C, KEYC )
    , SessionKey(~tid, S, C, KEYS )
    , Commit(~tid, S, C, <'server', MS>)
    , CommitSecrets(~tid,tid2,es,ss,S,C,sid,nc,pc,ns,ps)
    , Sid(~tid,sid)
    , Secrets(~tid,S,C,es,ss)
#endif
    ]->
    [ St_loop(S,0, ~tid, S, C, sid, ps, pc, nc, ns, X, Y, IVC, IVS, KEYC, KEYS)
#ifdef MUTUALAUTH
    , LoopSecrets(~tid,S,C,es,ss)
#endif
    ]

/*
rule S_2_resume:
let
    ns = ~ns
//added typing for resume
    C = $C
    S = $S
    nc = ~nc
    pc = $pc
    ps = $ps
    sid = ~sid
in
    [ In(senc{C2res}HKEYCres)
    , St_resume(S,1, ~tid, S, C, sid, ps, pc, pms, nc, ns, X, Y)
#ifdef MUTUALAUTH
    , LoopPMS(~tid,S,C,pmsOld,pms)
#endif
    ]
  --[
#ifdef MUTUALAUTH
      SessionKey(~tid, S, C, KEYCres )
    , SessionKey(~tid, S, C, KEYSres )
    , LoopPMS(~tid,S,C,pmsOld,pms)
    , Sid(~tid,sid)
#endif
    ]->
    [ St_loop(S,0, ~tid, S, C, sid, ps, pc, RMSres, nc, ns, X, Y, IVCres, IVSres, KEYCres, KEYSres)
#ifdef MUTUALAUTH
    , LoopPMS(~tid,S,C,pmsOld,RMSres)
#endif
    ]
*/

#ifdef PSK
rule C_3:
  let
//  tid2 = ns
    X   = 'g'^~x
    es = Y^~x
    ss = 'g'^~x^~ltkS
    nc = ~nc
    sid = ~sid
    ltkC = ~ltkC
    ltkS = ~ltkS
//added typing for resume
    C = $C
    S = $S
    ns = ~ns
    pc = $pc
    ps = $ps
    tid2= ~ns
  in
    [ St_loop(C,0, ~tid, S, C, sid, ps, pc, nc, ns, X, Y, ivc, ivs, fkeys, fkeys)
    , In(<senc{NewSessionTicket}fkeys>) ]
    --[]->
    [ St_loop(C,0, ~tid, S, C, sid, ps, pc, nc, ns, X, Y, ivc, ivs, fkeys, fkeys) ]
#endif


rule C_send_appdata:
let
//added typing for resume
    C = $C
    S = $S
    nc = ~nc
    ns = ~ns
    pc = $pc
    ps = $ps
    sid = ~sid
in
    [ St_loop(C,0, ~tid, S, C, sid, ps, pc, nc, ns, X, Y, ivc, ivs, keyc, keys)
    , !Ltk(S, ltkS)
    , Fr(~nexpc)
    , Fr(~plainc) ]
    --[
      Send(~tid,C,S,~plainc,keyc)
    , Sid(~tid,sid)
    ]->
    [ Out(<C_APPDATA>) 
    , St_loop(C,0, ~tid, S, C, sid, ps, pc, nc, ns, X, Y, ivc, ivs, keyc, keys)
    ]

rule S_send_appdata:
let
//added typing for resume
    C = $C
    S = $S
    nc = ~nc
    ns = ~ns
    pc = $pc
    ps = $ps
    sid = ~sid
in
    [ St_loop(S,0, ~tid, S, C, sid, ps, pc, nc, ns, X, Y, ivc, ivs, keyc, keys)
    , !Ltk(S, ltkS)
    , Fr(~nexps)
    , Fr(~plains) ]
    --[
      Send(~tid,S,C,~plains,keys) 
#ifdef MUTUALAUTH
    , Sid(~tid,sid)
#endif
    ]->
    [ Out(<S_APPDATA>) 
    , St_loop(S,0, ~tid, S, C, sid, ps, pc, nc, ns, X, Y, ivc, ivs, keyc, keys)
    ]
 
rule C_recv_appdata:
let
//added typing for resume
    C = $C
    S = $S
    nc = ~nc
    ns = ~ns
    pc = $pc
    ps = $ps
    sid = ~sid
in
    [ St_loop(C,0, ~tid, S, C, sid, ps, pc, nc, ns, X, Y, ivc, ivs, keyc, keys)
    , !Ltk(S, ltkS)
    , In(<S_APPDATA>) ]
    --[
      Recv(~tid,S,C,~plains,keys)
    , Sid(~tid,sid)
    ]->
    [
    St_loop(C,0, ~tid, S, C, sid, ps, pc, nc, ns, X, Y, ivc, ivs, keyc, keys)
    ]

rule S_recv_appdata:
let
//added typing for resume
    C = $C
    S = $S
    nc = ~nc
    ns = ~ns
    pc = $pc
    ps = $ps
    sid = ~sid
in
    [ St_loop(S,0, ~tid, S, C, sid, ps, pc, nc, ns, X, Y, ivc, ivs, keyc, keys)
    , !Ltk(S, ltkS)
    , In(<C_APPDATA>) ]
    --[
      Recv(~tid,C,S,~plainc,keyc)
#ifdef MUTUALAUTH
    , Sid(~tid,sid)
#endif
    ]->
    [
    St_loop(S,0, ~tid, S, C, sid, ps, pc, nc, ns, X, Y, ivc, ivs, keyc, keys)
    ]

