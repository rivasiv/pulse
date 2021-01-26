#!/bin/bash
echo "before"
cat /proc/meminfo | grep -i hugepages_[TF]
rm -rf /dev/hugepages/ &> /dev/null
echo "after"
cat /proc/meminfo | grep -i hugepages_[TF]
