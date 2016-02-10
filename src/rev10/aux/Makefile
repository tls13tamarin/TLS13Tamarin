DEPS= $(wildcard *.m4i)
M4= $(patsubst %.m4,%.spthy,$(wildcard *.m4))

all: $(M4)

clean:
	rm -f $(M4)

%.spthy: %.m4 $(DEPS)
	m4 $(FLAGS) -I ../ -I../model -I . $< > $@

proofs:
	# Prove awkward invariants with custom heuristic 'ssc' - two smart steps, one conservative
	tamarin-prover invariants.spthy --heuristic=ssccc --prove={nonce_misuse,data_misuse,psk_id_origin} --output=../proofs/TLS_13_invariants.spthy $(PIPE_OUPUT)
ifneq ($(NO_PAUSE), 1)
	@echo "Awkward invariant proofs finished, press enter to continue."
	@read blah
endif

	# Prove with conservative heuristic
	tamarin-prover ../proofs/TLS_13_invariants.spthy --heuristic=C --prove=one_start_per_tid --output=../proofs/TLS_13_invariants.spthy.tmp $(PIPE_OUPUT)
	mv ../proofs/TLS_13_invariants.spthy.tmp ../proofs/TLS_13_invariants.spthy
	
	# Smart heuristic, loop breakers allowed
	tamarin-prover ../proofs/TLS_13_invariants.spthy --heuristic=S --prove={tid_invariant,ltk_invariant,server_config} --output=../proofs/TLS_13_invariants.spthy.tmp $(PIPE_OUPUT)
	mv ../proofs/TLS_13_invariants.spthy.tmp ../proofs/TLS_13_invariants.spthy
	
	# Smart heuristic, loop breakers delayed (default)
	tamarin-prover ../proofs/TLS_13_invariants.spthy --prove --output=../proofs/TLS_13_invariants.spthy.tmp $(PIPE_OUPUT)
	mv ../proofs/TLS_13_invariants.spthy.tmp ../proofs/TLS_13_invariants.spthy

	# Extra state invariants
	tamarin-prover state_invariants.spthy --prove={C1_before,Retry_before,C2,finished_invariant} --heuristic=csccSSSSSSSSSSSSSSSSSS --output=../proofs/TLS_13_state_invariants.spthy.tmp $(PIPE_OUPUT)
	mv ../proofs/TLS_13_state_invariants.spthy.tmp ../proofs/TLS_13_state_invariants.spthy

ifneq ($(NO_PAUSE),1)
	@echo "Invariants finished, press enter to continue."
	@read blah
endif

	# Prove fresh secrets
	tamarin-prover --prove=fresh_secret fresh_secret.spthy --output=../proofs/TLS_13_fresh_secret.spthy $(PIPE_OUPUT)
ifneq ($(NO_PAUSE),1)
	@echo "Fresh secret finished, press enter to continue."
	@read blah
endif

	# Prove helpers
	tamarin-prover helpers.spthy --prove={key_deriv,psk_basic,forge,ku} --heuristic=S --output=../proofs/TLS_13_helpers.spthy $(PIPE_OUPUT)
	
	# Prove extra helpers for secret lemmas
	tamarin-prover secret_helpers.spthy --prove={psk_auth,psk_dhe,kc_origin} --heuristic=S --output=../proofs/TLS_13_secret_helpers.spthy $(PIPE_OUPUT)
ifneq ($(NO_PAUSE),1)
	@echo "Helper lemmas finished, press enter to continue."
	@read blah
endif

	# Prove extra helpers for psk awkwardness
	tamarin-prover psk_helpers.spthy --prove=authenticated_psk --heuristic=SSSSSSc --output=../proofs/TLS_13_psk_helpers.spthy $(PIPE_OUPUT)
	tamarin-prover ../proofs/TLS_13_psk_helpers.spthy --prove=psk_helper --heuristic=c --output=../proofs/TLS_13_psk_helpers.spthy.tmp $(PIPE_OUPUT)
	mv ../proofs/TLS_13_psk_helpers.spthy.tmp ../proofs/TLS_13_psk_helpers.spthy
ifneq ($(NO_PAUSE),1)
	@echo "PSK helper lemmas finished, press enter to continue."
	@read blah
endif

	##### SECRET LEMMAS CURRENTLY NOT AUTO-PROVABLE ############
	tamarin-prover ../proofs/proof-mutual_secrets.spthy $(PIPE_OUTPUT)
	# Proving ss_basic lemma with loop breaker allowed
	# tamarin-prover secrets.spthy --prove=ss_basic --heuristic=S --output=../proofs/TLS_13_secrets-partial.spthy $(PIPE_OUPUT)

ifneq ($(NO_PAUSE),1)
	@echo "Secrets lemmas finished, press enter to continue."
	@read blah
endif

.PHONY: proofs clean
