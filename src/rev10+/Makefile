DEPS= $(wildcard *.m4i)
M4= $(patsubst %.m4,%.spthy,$(wildcard *.m4))

# Enables mutual authentication mode
# export FLAGS=-D MUTUAL_AUTH

# Disables the pause step after each proof file is completed
export NO_PAUSE=1

# Suppresses output of Tamarin while proving
export PIPE_OUPUT=2>/dev/null

all:
	$(MAKE) -C aux
	$(MAKE) -C tests
	$(MAKE) -C attack
	$(MAKE) $(M4)

clean:
	$(MAKE) clean -C aux
	$(MAKE) clean -C tests
	$(MAKE) clean -C attack
	rm -f $(M4)

%.spthy: %.m4 $(DEPS)
	m4 $(FLAGS) -I aux/ -I . -I model/  $< > $@

proofs:
	$(MAKE) proofs -C aux
	
	# Work needed in auxiliary files. Don't attempt to prove properties for now.
	#tamarin-prover --prove=unique properties.spthy --heuristic=SccSSSSSSSSSSSSS --output=proofs/proof-properties.spthy $(PIPE_OUPUT)
	tamarin-prover proofs/proof-properties.spthy $(PIPE_OUPUT)
attack:
	tamarin-prover attack/attack-secrets.spthy
.PHONY: proofs clean
