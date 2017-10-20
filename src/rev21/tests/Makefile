DEPS= $(wildcard *.m4i)
M4= $(patsubst %.m4,%.spthy,$(wildcard *.m4))

# MAKE_RULES=C1 S0a S1 S1a S1b S1c  C2 C2a C2b C2c C2d S2 Send Recv S_NST C_NST C1_PSK S0a_PSK S1_PSK S1_PSK_DHE C2_PSK C2_PSK_DHE S1c_PSK C2c_PSK\
 C_ZeroRTT_Auth S_RecvZeroRTTAuth C_EndZeroRTT C_SendZeroRTT S_RecvZeroRTT S_RecvEndZeroRTT
TEST_RULES=C0 S0 C1 S1 S1_retry C2d S2 C3 S3 C1_PSK C0_PSK S0_PSK S1_PSK_DHE S1_PSK C2d_PSK 
MAKE_RULES=$(TEST_RULES)

all:
	$(foreach rule, $(MAKE_RULES), \
	m4 -Q $(FLAGS) -I ../ -I../model -I . -D RULE=$(rule) reachability.m4 > $(rule).spthy;\
	perl -0777pi -e 's/\n{3,}/\n\n/g' $(rule).spthy ; \
	)

test:
	$(foreach rule, $(TEST_RULES), tamarin-prover --heuristic=S --prove=exists_ $(rule).spthy -o=$(rule).spthy 2>/dev/null +RTS -N16 -H75G -M150G -RTS ; )
clean:
	rm -f *.spthy

.PHONY: clean test all
