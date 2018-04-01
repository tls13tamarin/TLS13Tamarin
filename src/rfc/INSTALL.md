# Install Guide:

First step is to install the tamarin-prover. Instructions can be found
[here](https://github.com/tamarin-prover/tamarin-
prover/blob/develop/INSTALL.md).

Prerequisites include installing stack, Haskell (ghc), maude, and GraphViz.

Additionally, ensure that m4 is installed for the macros and preprocessing.

There are three commands specified in the Makefile:

 - `make` runs the preprocessing and outputs \*.spthy files which can be used
   by Tamarin
 - `make clean` deletes aforementioned files
 - `make proofs` runs the Tamarin prover on all lemmas which can be automatically proven

If tamarin-prover is in the PATH, the theory files can then be loaded into
Tamarin's GUI by running

  tamarin-prover interactive .

in the folder containing the theory file (mind the period!).

The theories can then be opened in the Tamarin GUI by visiting

  http://localhost:3001

Additional useful options for running Tamarin are:

 - `--port=num` for running multiple instances of Tamarin
 - `--heuristic[=(s|S|c|C)+]` to choose which heuristic to launch Tamarin with (see
   the Tamarin manual for more details)
 - `--prove[=LEMMAS]` to try to automatically prove listed lemma files. Will
   match multiple lemmas such as {lemma1,lemma2} and matches by prefix.
