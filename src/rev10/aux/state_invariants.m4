changequote(<!,!>)dnl
changecom(<!/*!>,<!*/!>)dnl
dnl
define(<!St_init!>,<!F_St_$1_$2_init(shift(shift($@)))!>)dnl
define(<!St_loop!>,<!L_St_$1_loop(shift($@))!>)dnl
define(<!St_init_KC!>,<!F_St_$1_$2_init_KC(shift(shift($@)))!>)dnl
define(<!St_init_PSK!>,<!F_St_$1_$2_init_PSK(shift(shift($@)))!>)dnl
define(<!ServerConfig!>,<!L_ServerConfig($@)!>)dnl
define(<!ClientPSK!>,<!L_ClientPSK($@)!>)dnl
define(<!KnownConfig!>,<!L_KnownConfig($@)!>)dnl
dnl
dnl
/*
    State invariants are an extension of the
    invariants.m4 file, containing a few extra
    lemmas which require a different set of heuristics.

    The lemmas themselves are contained in invariants.m4i.

    STATUS: Proves automatically using given heuristics.
*/
theory TLS_13_state_invariants
begin

include(tls13.m4i)
include(invariants.m4i)

include(axioms.m4i)

/*
    Proved in invariants.m4
*/
lemma_tid_invariant
lemma_one_start_per_tid

/*  Lemmas: C1_before_Retry,
        Retry_before_C2,
        C2_uniq

    Proofs: automatic, heuristic S

    These three lemmas help prove the injectivity
    of the C1 -> C1_Retry -> C2 loop.

    The proof is straightforward.
*/
lemma_injectivity

/*  Lemma: finished_invariant
    Proof: automatic, slow, heuristic csccSSSS....

    This is a meaty lemma to prove. It says that each tid
    only has a single FinishedHandshake action.

    The 'cscc' at the start ensures that both 
    FinishedHandshake actions are resolved. From there, 
    the proof continues by state unfolding.

    This also depends on the fact that each tid can only 
    have one C2 (proved above).

    There are many states, so this is quite slow.
*/
lemma_finished_invariant

end