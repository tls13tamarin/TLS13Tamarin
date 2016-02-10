all:	$(patsubst %.cpp,%.spthy,$(wildcard *.cpp))

clean:
	rm *.spthy

%.spthy: %.cpp TLS-13-resum.h
	cpp -P $< > $@

