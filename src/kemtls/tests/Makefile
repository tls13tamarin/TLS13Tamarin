TAMARIN ?= tamarin-prover
TAMARIN_FLAGS ?=
DEPS= $(wildcard *.m4i)
M4= $(patsubst %.m4,%.spthy,$(wildcard *.m4))
ifndef NOBASIC
	FLAGS := ${FLAGS} -DBASIC
endif
ifdef PSK
	FLAGS := ${FLAGS} -DPSK
endif
ifdef POST_HS
	FLAGS := ${FLAGS} -DPOST_HS
endif
ifdef PDK
	FLAGS := ${FLAGS} -DPDK
endif
ifdef SPLIT_KEM
	FLAGS := ${FLAGS} -DSPLIT_KEM
endif

# MAKE_RULES=C1 S0a S1 S1a S1b S1c  C2 C2a C2b C2c C2d S2 Send Recv S_NST C_NST C1_PSK S0a_PSK S1_PSK S1_PSK_DHE C2_PSK C2_PSK_DHE S1c_PSK C2c_PSK\
 C_ZeroRTT_Auth S_RecvZeroRTTAuth C_EndZeroRTT C_SendZeroRTT S_RecvZeroRTT S_RecvEndZeroRTT
TEST_RULES := C0 \
	C1_retry \
	S1 \
	C1 \
	S2a \
	S2b \
	S2c \
	S2c_req \
	S2d \
	C2a \
	C2b \
	C2c \
	C2c_req \
	C2d \
	S2e \
	C3_skip_cert \
	C3_cert \
	C3a \
	C3b \
	S3 \
	S3_cert \
	S3a \
	S3fin \
	Send \
	Recv
ifdef POST_HS
TEST_RULES := $(TEST_RULES) \
	S4_req \
	C4_req \
	S4_cert \
	C4_cert \
	C4_update_req \
	C4_update_recv \
	C4_update_fin \
	S4_update_req \
	S4_update_recv \
	S4_update_fin \
	S4_NST \
	C4_NST
endif
ifdef PSK
TEST_RULES := $(TEST_RULES) \
	C0_PSK \
	S0_PSK \
	S1_PSK \
	S1_PSK_DHE \
	C1_PSK \
	C1_retry_PSK \
	C1_PSK_DHE \
	S2d_PSK \
	C2d_PSK \
	C_EndZeroRTT \
	S_RecvEndZeroRTT \
	C_SendZeroRTT \
	S_RecvZeroRTT \
	# C_ZeroRTT_Auth \
	# S_RecvZeroRTTAuth
endif
ifdef PDK
TEST_RULES := $(TEST_RULES) \
	C0_PDK \
	C1_PDK_cert \
	C1_PDK_skip_cert \
	C1a_PDK \
	C2a_PDK \
	C2b_PDK \
	C2c_PDK \
	C2c_PDK_skip_ct \
	C2d_PDK \
	C3_PDK \
	S0_PDK \
	S1_PDK_cert \
	S1_PDK_no_cert \
	S2a_PDK \
	S2b_PDK \
	S2c_PDK_no_cert \
	S2c_PDK_cert \
	S2d_PDK \
	S3_PDK
endif

MAKE_RULES=$(TEST_RULES)

RULE_FILES= $(foreach rule,$(TEST_RULES),$(rule).spthy) sanity-check.spthy
PROOF_FILES= $(foreach rule,$(TEST_RULES),$(rule).proof) sanity-check.proof

all: $(RULE_FILES)

test: $(PROOF_FILES)

all.spthy: reachability.m4 ../model/*.m4* ../*.m4
	m4 -Q $(FLAGS) -DALL -I ../ -I../model -I . reachability.m4 > $@
	@perl -0777pi -e 's/\n{3,}/\n\n/g' $@

sanity-check.spthy: sanity-check.m4 ../model/*.m4* ../*.m4
	m4 -Q $(FLAGS) -I ../ -I../model -I . sanity-check.m4 > $@
	@perl -0777pi -e 's/\n{3,}/\n\n/g' $@

%.spthy: reachability.m4 ../model/*.m4* ../*.m4
	m4 -Q $(FLAGS) -I ../ -I../model -I . -D RULE=$* reachability.m4 > $@
	@perl -0777pi -e 's/\n{3,}/\n\n/g' $@

%.proof: %.spthy
	$(TAMARIN) $(TAMARIN_FLAGS) --quit-on-warning --heuristic=S --prove=exists_* $< --output=$@.wip 2> $*-output.log | tee $*-stdout.log
	@grep -q verified $*-stdout.log
	rm $*-stdout.log
	mv $@.wip $@

clean:
	rm -f *.spthy *.proof *.log *.wip

.PHONY: clean test all
