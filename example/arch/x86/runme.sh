#!/bin/sh

#main.py trace_mcf.db 1 8,9 ./res/ mcf -b 32 -s h
#1 -> trace file namce
#2 -> coverage
#3 -> result folder
#4 -> application name

traceFile="hello_world.db"
coverage="100"
resultFolder="./res/"
applicationName="hello"

../../../main.py $traceFile $coverage 3,5 $resultFolder $applicationName -s o,h,s -p

