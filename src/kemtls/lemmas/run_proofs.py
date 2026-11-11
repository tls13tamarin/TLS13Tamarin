from datetime import datetime
from math import log10
import subprocess
import re
import os
import platform
import shlex
from typing import Iterable, Optional, Tuple

#: Fetch lemmas from incomplete output
LEMMA_REGEX: re.Pattern = re.compile(r"^\s*(?P<lemma>[a-zA-Z0-9_]+) \((all-traces|exists-trace)\): analysis incomplete \(1 steps\)\s*$")

#: Parse out steps
STEPS_REGEX: str = r"^\s*{lemma} \((all-traces|exists-trace)\): verified \((?P<steps>\d+) steps\)\s*$"

if platform.uname().system == "Darwin":
    unit = "K"
else:
    unit = "M"

TIMEFMT: str = f"""%J
%U user  %S system  %P cpu  %*E total
avg shared (code):         %X KB
avg unshared (data/stack): %D KB
total (sum):               %K KB
max memory:                %M {unit}B
"""
del unit


PAGE_SIZE: str = os.sysconf("SC_PAGE_SIZE")


def run_tamarin(model: str, prove: Optional[str] = None) -> Tuple[str, str]:
    cmd = ["time", os.environ.get("TAMARIN", "tamarin-prover"),
           *shlex.split(os.environ.get("TAMARIN_FLAGS", "")), model]
    if prove is not None:
        modelname = model.removesuffix(".spthy")
        cmd.append(f"--prove={prove}")
        cmd.append(f"--output=proofs/{modelname}_{prove}.spthy")
    env = os.environ.copy()
    env["TIMEFMT"] = TIMEFMT
    result = subprocess.run(
        ["/bin/zsh", "-c", shlex.join(cmd)],
        capture_output=True,
        text=True,
        env=env,
    )
    timeoutput = '\n'.join(result.stderr.splitlines()[-(1+len(TIMEFMT.splitlines())):])
    return result.stdout, timeoutput


def get_lemmas(model: str) -> Iterable[str]:
    """Parse out the lemmas from the output of Tamarin"""
    output, _ = run_tamarin(model)
    lines = output.splitlines()

    for line in lines:
        if m := LEMMA_REGEX.match(line):
            yield m.group("lemma")


def get_steps(tamarin_output: str, lemma) -> Optional[str]:
    pattern = STEPS_REGEX.format(lemma=lemma)
    if match := re.search(pattern, tamarin_output, re.MULTILINE):
        return match.group("steps")


def write_output(model: str, lemma: str, output: str):
    modelname = model.removesuffix(".spthy")
    with open(f"proofs/{modelname}_{lemma}.out", "w") as fh:
        fh.write(output)


def write_statistics(model: str, lemma: str, steps: str, runtime: str, timeoutput: str):
    modelname = model.removesuffix(".spthy")
    with open(f"proofs/{modelname}_{lemma}.stats", "w") as fh:
        fh.write(f"Runtime: {runtime}\n")
        fh.write(f"Steps:   {steps}\n")
        fh.write(timeoutput)


def prove_lemmas(model: str, lemmas: Iterable[str]):
    lemmas = list(lemmas)
    max_lemma_length = max(len(lemma) for lemma in lemmas)
    for idx, lemma in enumerate(lemmas):
        start_time = datetime.now()
        stridx = str(idx+1).rjust(len(str(len(lemmas))))
        lemma_name = lemma.ljust(max_lemma_length)
        print(f"[{stridx}/{len(lemmas)}] Proving {lemma_name} at {start_time.time()}...", end="", flush=True)
        output, timeoutput = run_tamarin(model, lemma)
        duration = datetime.now() - start_time
        steps = get_steps(output, lemma)
        write_output(model, lemma, output)
        write_statistics(model, lemma, steps, duration, timeoutput)
        if steps is None:
            print(output)
            print(f"Proving {lemma} failed after {duration}!?")
            break
        print(f"\tCompleted in {steps: >6} steps in {duration}")


if __name__ == "__main__":
    import sys
    import itertools
    if len(sys.argv) not in (2, 3):
        print(f"Usage: {sys.argv[0]} model.spthy [start_lemma]")
        sys.exit(1)
    model = sys.argv[1]
    lemmas = get_lemmas(model)

    if len(sys.argv) == 3:
        opt_start_lemma = sys.argv[2]
        lemmas = list(lemmas)
        while len(lemmas) > 0:
            if lemmas[0] != opt_start_lemma:
                print(f"Skipping {lemmas[0]}")
                lemmas.pop(0)
            else:
                break
        assert len(lemmas) > 0, "Dropped all lemmas"

    start_time = datetime.now()
    prove_lemmas(model, lemmas)
    duration = datetime.now() - start_time
    print(f"\n\nAll done in {duration}")
