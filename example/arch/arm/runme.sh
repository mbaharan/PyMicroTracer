#!/bin/sh

#main.py trace_mcf.db 1 8,9 ./res/ mcf -b 32 -s h
#1 -> trace file namce
#2 -> coverage
#3 -> result folder
#4 -> application name

traceFile="hello_trace.db"
coverage="100"
resultFolder="./res/"
applicationName="hello"



declare -a arrPolicy=("32" "64" "128" "256")

str=""

for policy in "${arrPolicy[@]}"
do
	echo "back end size: $policy"
	../../../main.py $traceFile $coverage 5,14 $resultFolder $applicationName -b $policy -s h
done
