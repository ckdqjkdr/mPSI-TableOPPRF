#! /bin/bash

SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
 bin="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
 SOURCE="$(readlink "$SOURCE")"
 [[ $SOURCE != /*  ]] && SOURCE="$bin/$SOURCE"
done
bin="$( cd -P "$( dirname "$SOURCE" )" && pwd )"

cd $bin


../bin/add_on -p 2 -i "test_data/input2.txt" -o "test_data/output2.txt"
echo "Running $i..." &


