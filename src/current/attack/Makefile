DEPS= $(wildcard *.m4i)
M4= $(patsubst %.m4,%.spthy,$(wildcard *.m4))

all: $(M4)


%.spthy: %.m4 $(DEPS)
	m4 -Q $(FLAGS) -I ../ -I../model -I . $< > $@
	# Strip extra new lines introduced by M4 macros
	perl -0777pi -e 's/\n{3,}/\n\n/g' $@
	# Replace "prev_" with "p_" to save space...
	#perl -0777pi -e 's/prev_/p_/g' $@


clean:
	rm -f $(M4)

.PHONY: clean test all
