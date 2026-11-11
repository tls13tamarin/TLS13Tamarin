DEPS= $(wildcard *.m4i) $(wildcard ../model/*.m4i) $(wildcard includes/*.m4i)
M4= $(patsubst %.m4,%.spthy,$(wildcard *.m4))
PIPE=--quit-on-warning 2>error.log 1>>success.log
TAMARIN ?= tamarin-prover
TAMARIN_FLAGS ?=
TAM=time $(TAMARIN) $(TAMARIN_FLAGS)
FLAGS :=-DPDK -DBASIC

ifdef SPLIT_KEM
	FLAGS := ${FLAGS} -DSPLIT_KEM
endif

all: $(M4)

clean:
	$(RM) $(M4) *.proof output.log

%.spthy: %.m4 $(DEPS)
	m4 -E -Q $(FLAGS) -I ../ -I../model -I . $< > $@
	# Strip extra new lines introduced by M4 macros
	perl -0777pi -e 's/\n{3,}/\n\n/g' $@
	# Replace "prev_" with "p_" to save space...
	perl -0777pi -e 's/prev_/p_/g' $@
	$(TAMARIN) $(TAMARIN_FLAGS) +RTS -N4 -RTS --derivcheck-timeout=0 --quit-on-warning $@ > /dev/null


%.proof: %.spthy
	$(TAM) --quit-on-warning $< --prove --output=$@ 2> output.log
	@grep -qv falsified output.log

quick-proofs: sources.proof invariants.proof uniqueness.proof kem_chal.proof auth_helpers.proof

all-proofs: quick-proofs secret_helpers.proof

proofs_: $(M4) $(wildcard oracles/*)
	rm -f error.log
	rm -rf success.log
	bash -c "$(TAM) sources.spthy --prove --output=../proofs/sources.spthy $(PIPE)"
	bash -c "$(TAM) invariants.spthy --prove --output=../proofs/invariants.spthy $(PIPE)"
	bash -c "$(TAM) uniqueness.spthy --prove --output=../proofs/uniqueness.spthy $(PIPE)"
	bash -c "$(TAM) kem_chal.spthy --prove --output=../proofs/kem_chal.spthy $(PIPE)"
	bash -c "$(TAM) auth_helpers.spthy --prove --output=../proofs/auth_helpers.spthy $(PIPE)"

	bash -c "$(TAM) secret_helpers.spthy --prove=tid* --prove=ku* --prove=hsms* --prove=sig_origin* --prove=posths_rms* --heuristic=S --output=../proofs/secret_helpers.1.spthy $(PIPE)"
	bash -c "$(TAM) secret_helpers.spthy --prove=matching_rms_posths* --prove=matching_transcripts_posths* --prove=matching_rms_actors* --bound=8 --heuristic=CCCiiiiiiii --output=../proofs/secret_helpers.2.spthy $(PIPE)"
	bash -c "$(TAM) secret_helpers.spthy --prove=matching_sessions* --heuristic=CCCCCissssssssssssssssssssssss --output=../proofs/secret_helpers.3.spthy $(PIPE)"
	# To prove manually:
	#   - post_master_secret (quick)
	#   - invariant_post_hs (quick: solve for RunningRMS then CommitIdentity)
	#   - handshake_secret (the big one)

	#bash -c "$(TAM) lemma.spthy --prove=secret_session_keys* --output=../proofs/lemmas.1.spthy $(PIPE)"
	#bash -c "$(TAM) lemma.spthy --prove=unique_session_keys --heuristic=c --output=../proofs/lemmas.2.spthy --bound=10 $(PIPE)"


	# To prove manually:
	#   - entity_authentication
	#   - mutual_entity authentication
	#   - transcript_agreement
	#   - mutual_transcript_agreement
	#   - session_key_agreement


.PHONY: clean proofs

