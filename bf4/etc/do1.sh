#!/bin/sh

# this is needed a single time
#make cptemplate

# python3 ../sigcomm-2020/cleanup_v1.py simple_nat.p4
# p4c-analysis ./simple_nat-integrated.p4 > simple_nat.log

# python3 ../sigcomm-2020/cleanup_v1.py running.p4 
# p4c-analysis ./running-integrated.p4 > running.log

# python3 ../sigcomm-2020/cleanup_v1.py basic.p4
# p4c-analysis ./basic-integrated.p4 > basic.log

if [ "$#" -eq 0 ]; then
  echo "0 args"
  export basename='example1'
else
  export basename=$1
fi

rm -rf /home/ecl7037/code/p4-programs-survey/bf4/etc/$basename.log /home/ecl7037/code/p4-programs-survey/bf4/etc/$basename.err
cd /home/ecl7037/code/bf4/build/
python3 /home/ecl7037/code/bf4/sigcomm-2020/cleanup_v1.py /home/ecl7037/code/p4-programs-survey/bf4/etc/$basename.p4 >> /home/ecl7037/code/p4-programs-survey/bf4/etc/$basename.log 2>>/home/ecl7037/code/p4-programs-survey/bf4/etc/$basename.err
p4c-analysis ./$basename-integrated.p4 >> /home/ecl7037/code/p4-programs-survey/bf4/etc/$basename.log 2>>/home/ecl7037/code/p4-programs-survey/bf4/etc/$basename.err
