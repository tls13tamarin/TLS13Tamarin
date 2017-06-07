DEPS= $(wildcard *.m4i)
M4= $(patsubst %.m4,%.spthy,$(wildcard *.m4))

# Enables simpler model
# export FLAGS=-D SIMPLE_MODEL
export FLAGS=-D COMPACT_LABELS

# Disables the pause step after each proof file is completed
# export NO_PAUSE=1

# Suppresses output of Tamarin while proving
# export PIPE_OUPUT=2>/dev/null

all:
	$(MAKE) clean
	$(MAKE) -C lemmas
	$(MAKE) -C tests
	$(MAKE) -C attack
	$(MAKE) $(M4)

clean:
	$(MAKE) clean -C lemmas
	$(MAKE) clean -C tests
	$(MAKE) clean -C attack
	rm -f $(M4)

%.spthy: %.m4 $(DEPS)
	m4 $(FLAGS) -I lemmas/ -I . -I model/  $< > $@

test:
	# Warning: this may take a while to run, consuming a lot of resources.
	$(MAKE) test -C tests

proofs:
	$(MAKE) all
	$(MAKE) proofs -C lemmas

.PHONY: proofs clean test
