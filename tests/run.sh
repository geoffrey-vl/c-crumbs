#!/bin/sh
set -e
for c in $*; do
	gcc -Wall -Werror -ansi -pedantic -std=c11 -O2 $c
	./a.out
	#g++ -Wall -Werror -O2 $c
	#./a.out
done
