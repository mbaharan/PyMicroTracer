#!/bin/sh

#main.py trace_mcf.db 1 8,9 ./res/ mcf -b 32 -s h
#1 -> trace file namce
#2 -> coverage
#3 -> result folder
#4 -> application name

traceFile="loop_trace.db"
coverage="100"
resultFolder="./res/"
applicationName="loop"

../../../main.py $traceFile $coverage 3,5 $resultFolder $applicationName -b 5,6 -s o,h -d

