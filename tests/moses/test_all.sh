#!/bin/bash
FILES=$( find ./plugin_dev -regextype egrep -regex '.*(\.inc|\.nasl)' )
for i in $FILES
do
  printf "\n%s\n" $i >> xxx 2>&1
  python3 ./tests/moses/tester.py -f $i >> xxx 2>&1
done
