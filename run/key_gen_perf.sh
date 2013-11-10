# Key generation performance measurement for SARP
# Nov 10, 2013
# daveti@cs.uoregon.edu
# http://davejingtian.org

#!/bin/sh

# Create the log file
touch time_perf.log

# Create the loop
i=1
while [ $i -le 100 ]
do
	./sarp -g -o perf_$i >> time_perf.log
	i=`expr $i + 1`
done

# Create final perf file
touch time.perf

# Process the log file
grep crypto* time* | cut -d [ -f2 | cut -d ] -f1 > time.perf

# Clear the key files
rm -rf perf*

# Done
echo "key_gen_perf.sh done"
