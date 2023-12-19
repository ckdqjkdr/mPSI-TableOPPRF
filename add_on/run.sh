#! /bin/bash

SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
 bin="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
 SOURCE="$(readlink "$SOURCE")"
 [[ $SOURCE != /*  ]] && SOURCE="$bin/$SOURCE"
done
bin="$( cd -P "$( dirname "$SOURCE" )" && pwd )"

cd $bin

for i in `seq 2 -1 0`;
do
	../bin/add_on -p $i -i "test_data/input"$i".txt" -o "test_data/output"$i".txt" & 
	echo "Running $i..." &
done

