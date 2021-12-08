#!/bin/sh

# this is needed a single time
#make cptemplate

python3 ../sigcomm-2020/cleanup_v1.py simple_nat.p4
p4c-analysis ./simple_nat-integrated.p4 > simple_nat.log

python3 ../sigcomm-2020/cleanup_v1.py running.p4 
p4c-analysis ./running-integrated.p4 > running.log

python3 ../sigcomm-2020/cleanup_v1.py basic.p4
p4c-analysis ./basic-integrated.p4 > basic.log

