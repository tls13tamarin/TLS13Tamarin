DEPS= $(wildcard *.m4i)
M4= $(patsubst %.m4,%.spthy,$(wildcard *.m4))

all: $(M4)

clean:
	rm -f $(M4)

%.spthy: %.m4 $(DEPS)
	m4 $(FLAGS) -I ../ -I../model -I../aux -I . $< > $@

.PHONY: clean
