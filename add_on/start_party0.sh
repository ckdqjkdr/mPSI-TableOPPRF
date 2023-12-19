#! /bin/bash

SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
 bin="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
 SOURCE="$(readlink "$SOURCE")"
 [[ $SOURCE != /*  ]] && SOURCE="$bin/$SOURCE"
done
bin="$( cd -P "$( dirname "$SOURCE" )" && pwd )"

cd $bin


../bin/add_on -p 0 -i "test_data/input0.txt" -o "test_data/output0.txt" & 
echo "Running $i..." &


