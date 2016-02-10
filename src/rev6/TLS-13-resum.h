/* TLS 1.3 modelled after draft-ietf-tls-tls13-06
   (24 May 2015; expires 25 November 2015) */

#define ClientHello C, nc, sid, pc
#define ClientKeyShare X
#define C1 ClientHello, ClientKeyShare
#define ServerHello S, ns, sid, ps
#define ServerKeyShare Y
#define ServerEncryptedExtensions $encext 
#define ServerCertificate S, pk(ltkS)
#define ServerCertificateRequest $certreq
#define HASH1 C1, ServerHello, ServerKeyShare, ServerEncryptedExtensions, ServerCertificate, ServerCertificateRequest
#define ServerCertificateVerify sign{h('server_certificate_verify', HASH1)}ltkS
#define HMS PRF(pms, 'handshake_master_secret', h(C1, ServerHello, ServerKeyShare))
#define HASH2 HASH1, ServerCertificateVerify
#define ServerFinished PRF(HMS, 'server_finished', h(HASH2))
#define HKEYC PRFfirst48(HMS, 'key_expansion', ns, nc)
#define HKEYS PRFsecond48(HMS, 'key_expansion', ns, nc)
#define ENC1 ServerEncryptedExtensions, ServerCertificate, ServerCertificateRequest, ServerCertificateVerify, ServerFinished
#define S1 ServerHello, ServerKeyShare, senc{ENC1}HKEYS
#define HMSres PRF(pms, 'handshake_master_secret', h(C1, ServerHello))
#define MSres PRF(HMSres, 'extended_master_secret', h(C1, ServerHello))
#define RMSres PRF(HMSres, 'resumption_premaster_secret', h(C1, ServerHello))
#define HKEYCres PRFfirst48(HMSres, 'key_expansion', ns, nc)
#define HKEYSres PRFsecond48(HMSres, 'key_expansion', ns, nc)
#define ServerFinishedres PRF(HMSres, 'server_finished', h(C1, ServerHello))
#define S1res ServerHello, senc{ServerFinishedres}HKEYSres
#define C2res PRF(HMSres, 'client_finished', h(C1, ServerHello, ServerFinishedres))

#ifdef MUTUALAUTH
#define ClientCertificate C, pk(ltkC)
#define ClientCertificateVerify sign{h('client_certificate_verify', HASH2, ServerFinished, ClientCertificate)}ltkC
#define HASH3 HASH2, ClientCertificate, ClientCertificateVerify 
#define MS PRF(HMS, 'extended_master_secret', h(HASH3))
#define RMS PRF(HMS, 'resumption_premaster_secret', h(HASH3))
#define HASH4 HASH2, ServerFinished, ClientCertificate, ClientCertificateVerify
#define ClientFinished PRF(HMS, 'client_finished', h(HASH4))
#define C2 ClientCertificate, ClientCertificateVerify, ClientFinished
#else
#define MS PRF(HMS, 'extended_master_secret', h(HASH2))
#define RMS PRF(HMS, 'resumption_premaster_secret', h(HASH2))
#define ClientFinished PRF(HMS, 'client_finished', h(HASH2, ServerFinished))
#define C2 ClientFinished
#endif

#define KEYC PRFfirst48(MS, 'key_expansion', ns, nc)
#define KEYS PRFsecond48(MS, 'key_expansion', ns, nc)
#define IVC PRFthird48(MS, 'key_expansion', ns, nc)
#define IVS PRFfourth48(MS, 'key_expansion', ns, nc)
#define KEYCres PRFfirst48(MSres, 'key_expansion', ns, nc)
#define KEYSres PRFsecond48(MSres, 'key_expansion', ns, nc)
#define IVCres PRFthird48(MSres, 'key_expansion', ns, nc)
#define IVSres PRFfourth48(MSres, 'key_expansion', ns, nc)
#define HelloRetryRequest S, ps 
#define C_APPDATA $paramsc, ~nexpc, senc{~plainc, $padc}keyc, mac(keyc, $paramsc, ivc, ~nexpc, senc{~plainc, $padc}keyc)
#define S_APPDATA $paramss, ~nexps, senc{~plains, $pads}keys, mac(keys, $paramss, ivs, ~nexps, senc{~plains, $pads}keys)

builtins: diffie-hellman, hashing, symmetric-encryption,  signing

section{* TLS 1.3 *}

/*
 * Protocol:	TLS 1.3 Handshake and Record Protocols, Proposal A, rev. 6
 * Modeler: 	Cas Cremers, Marko Horvat
 * Year: 	2015
 * Source:      http://tlswg.github.io/tls13-spec/	
 *
 * Status: 	working
 */

// Hash declarations

functions: PRF/1, PRFfirst48/1, PRFsecond48/1, PRFthird48/1, PRFfourth48/1, mac/1

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
    [ Out(<C1>)
    , DHExp(tid, ~x)
    , St_init(C,1, tid, C, nc, sid, pc, ~x)
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
    [ Out(<C1>)
    , DHExp(~tid, ~x2)
    , St_init(C,1, ~tid, C, nc, sid, pc, ~x2) ]

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
    , St_loop(C,0, ~tid, S, C, sid, ps, pc, pms, rms, ncOld, ns, XOld, Y, ivc, ivs, keyc, keys)
    ]
  --[ Start(~tid, 'client','resume')
    , DH(~tid, ~x)
    , LoopPMS(~tid,C,S,pms)
    , Tid(~tid,sid,'client')
    ]->
    [ Out(<C1>)
    , DHExp(~tid, ~x)
    , St_resume(C,1, ~tid, S, C, sid, ps, pc, pms, rms, nc, ns, X, Y)
    ]

rule S_1:
let
    tid = ~ns
//  tid2= nc
    S  = $S
    ns = ~ns
    ps = $ps
    Y  = 'g'^~y
    pms = X^~y
    ltkS = ~ltkS
//added typing for resume
    C = $C
    nc = ~nc
    pc = $pc
    sid = ~sid
    tid2 = ~nc
in
    [ In(<C1>)
    , Fr(ns)
    , Fr(~y)
    , !Ltk(S, ltkS)
    ]
  --[ Start(tid, 'server','init')
    , Partner(tid, tid2, S, C)
    , DH(tid, ~y)
    , RunningPMS(tid,tid2,pms,S,C,sid,nc,pc,ns,ps)
    , InitTid(tid,sid,'server')
    ]->
    [ Out(<S1>)
    , DHExp(tid, ~y)
    , St_init(S,1, tid, S, C, sid, nc, pc, ns, ps, pms )
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
    [ In(<C1>)
    ]
  --[ Retry('server')
    ]->
    [ Out(<HelloRetryRequest>)
    ]

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
    , St_loop(S,0, ~tid, S, C, sid, ps, pc, pms, rms, ncOld, nsOld, XOld, Y, ivc, ivs, keyc, keys)
    ]
  --[ Start(~tid, 'server','resume')
    , Tid(~tid,sid,'server')
    , Loop(~tid,sid,'server')
    ]->
    [ Out(<S1res>)
    , St_resume(S,1, ~tid, S, C, sid, ps, pc, pms, rms, nc, ns, X, Y)
    ]

rule C_2:
  let
//  tid2 = ns
    X   = 'g'^~x
    pms = Y^~x
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
    , St_init(C,1, ~tid, C, nc, sid, pc, ~x)
    ]
  --[ Running(~tid, S, C, <'server', MS>)
    , SessionKey( ~tid, C, S, pms, KEYC )
    , SessionKey( ~tid, C, S, pms, KEYS )
    , Finished(~tid,'client')
    , Partner(~tid, tid2, C, S)
    , PMS(~tid,C,S,pms)
    , SecretPMS(~tid)
    , Tid(~tid,sid,'client')
    , RunningPMS(~tid,tid2,pms,C,S,sid,nc,pc,ns,ps)
    , CommitPMS(~tid,tid2,pms,C,S,sid,nc,pc,ns,ps)
    ]->
    [ Out(senc{C2}HKEYC)
    , St_loop(C,0, ~tid, S, C, sid, ps, pc, pms, RMS, nc, ns, X, Y, IVC, IVS, KEYC, KEYS)
    ]

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
    , St_resume(C,1, ~tid, S, C, sid, ps, pc, pms, rms, nc, nsOld, X, Y)
    ]
  --[ SessionKey( ~tid, C, S, pms, KEYCres )
    , SessionKey( ~tid, C, S, pms, KEYSres )
    , Loop(~tid,sid,'client')
    , LoopPMS(~tid,C,S,pms)
    , Tid(~tid,sid,'client')
    ]->
    [ Out(senc{C2res}HKEYCres)
    , St_loop(C,0, ~tid, S, C, sid, ps, pc, pms, RMSres, nc, ns, X, Y, IVCres, IVSres, KEYCres, KEYSres)
    ]

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
    [ In(senc{C2}HKEYC)
#ifdef MUTUALAUTH
    , !Ltk(C, ltkC)
#endif
    , !Ltk(S, ltkS)
    , St_init(S,1, ~tid, S, C, sid, nc, pc, ns, ps, pms)
    ]
  --[ Finished(~tid,'server')
    , Tid(~tid,sid,'server')
    , PMS(~tid,S,C,pms)
#ifdef MUTUALAUTH
    , SecretPMS(~tid)
    , SessionKey(~tid, S, C, pms, KEYC )
    , SessionKey(~tid, S, C, pms, KEYS )
    , Commit(~tid, S, C, <'server', MS>)
    , CommitPMS(~tid,tid2,pms,S,C,sid,nc,pc,ns,ps)
#endif
    ]->
    [ St_loop(S,0, ~tid, S, C, sid, ps, pc, pms, RMS, nc, ns, X, Y, IVC, IVS, KEYC, KEYS)
    ]

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
    , St_resume(S,1, ~tid, S, C, sid, ps, pc, pms, rms, nc, ns, X, Y)
    ]
  --[
      LoopPMS(~tid,S,C,pms)
    , Tid(~tid,sid,'server')
    , Loop(~tid,sid,'server')
#ifdef MUTUALAUTH
    , SessionKey(~tid, S, C, pms, KEYCres )
    , SessionKey(~tid, S, C, pms, KEYSres )
#endif
    ]->
    [ St_loop(S,0, ~tid, S, C, sid, ps, pc, pms, RMSres, nc, ns, X, Y, IVCres, IVSres, KEYCres, KEYSres)
    ]

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
    [ St_loop(C,0, ~tid, S, C, sid, ps, pc, pms, rms, nc, ns, X, Y, ivc, ivs, keyc, keys)
    , !Ltk(S, ltkS)
    , Fr(~nexpc)
    , Fr(~plainc) ]
    --[
      Send(~tid,C,S,~plainc,keyc)
    , Tid(~tid,sid,'client')
    , Loop(~tid,sid,'client')
    , LoopPMS(~tid,C,S,pms)
    ]->
    [ Out(<C_APPDATA>) 
    , St_loop(C,0, ~tid, S, C, sid, ps, pc, pms, rms, nc, ns, X, Y, ivc, ivs, keyc, keys)
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
    [ St_loop(S,0, ~tid, S, C, sid, ps, pc, pms, rms, nc, ns, X, Y, ivc, ivs, keyc, keys)
    , !Ltk(S, ltkS)
    , Fr(~nexps)
    , Fr(~plains) ]
    --[
      Send(~tid,S,C,~plains,keys) 
    , Loop(~tid,sid,'server')
    , LoopPMS(~tid,S,C,pms)
    , Tid(~tid,sid,'server')
    ]->
    [ Out(<S_APPDATA>) 
    , St_loop(S,0, ~tid, S, C, sid, ps, pc, pms, rms, nc, ns, X, Y, ivc, ivs, keyc, keys)
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
    [ St_loop(C,0, ~tid, S, C, sid, ps, pc, pms, rms, nc, ns, X, Y, ivc, ivs, keyc, keys)
    , !Ltk(S, ltkS)
    , In(<S_APPDATA>) ]
    --[
      Recv(~tid,S,C,~plains,keys)
    , Tid(~tid,sid,'client')
    , Loop(~tid,sid,'client')
    , LoopPMS(~tid,C,S,pms)
    ]->
    [
    St_loop(C,0, ~tid, S, C, sid, ps, pc, pms, rms, nc, ns, X, Y, ivc, ivs, keyc, keys)
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
    [ St_loop(S,0, ~tid, S, C, sid, ps, pc, pms, rms, nc, ns, X, Y, ivc, ivs, keyc, keys)
    , !Ltk(S, ltkS)
    , In(<C_APPDATA>) ]
    --[
      Recv(~tid,C,S,~plainc,keyc)
    , Loop(~tid,sid,'server')
    , LoopPMS(~tid,S,C,pms)
    , Tid(~tid,sid,'server')
    ]->
    [
    St_loop(S,0, ~tid, S, C, sid, ps, pc, pms, rms, nc, ns, X, Y, ivc, ivs, keyc, keys)
    ]

