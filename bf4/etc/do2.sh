#!/bin/bash

export BUILD_DIR='build'
export PCAP_DIR='pcaps'
export LOG_DIR='logs'
export basename='example1'

mkdir -p $BUILD_DIR $PCAP_DIR $LOG_DIR
export P4C='p4c-bm2-ss'
# P4C_ARGS += --p4runtime-files $(BUILD_DIR)/$(basename $@).p4.p4info.txt
export P4C_ARGS='--p4runtime-files $BUILD_DIR/$basename.p4.p4info.txt'
# $P4C --p4v 16 $P4C_ARGS -o $BUILD_DIR/$@ $<
$P4C --p4v 16 $P4C_ARGS -o $BUILD_DIR $1
