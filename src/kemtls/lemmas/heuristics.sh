#!/bin/zsh

if ! [ $# = 3 ]; then
    echo "Usage: $0 model.spthy timelimit lemma"
    exit 1
fi

model=$1
timelimit=$2
lemma=$3

heuristics=("c" "i" "s" "C" "I" "S" "cs" "is" "ci")

for heuristic in ${heuristics}; do
    echo -n "$(date) Trying heuristic '${heuristic}' "
    output=$(mktemp)
    timeout --signal=KILL --kill-after "1m" --foreground "${timelimit}" "${TAMARIN:-tamarin-prover}" ${=TAMARIN_FLAGS} "${model}" --prove="${lemma}" --heuristic="${heuristic}" 2>/dev/null > "${output}"
    if [ $? = 124 ]; then
        echo "Timed out after ${timelimit} and was killed"
    else 
        result=$(grep -o "verified ([0-9]\+ steps)" "${output}")
        echo "Success! ${result}"
    fi
    rm "${output}"
done
