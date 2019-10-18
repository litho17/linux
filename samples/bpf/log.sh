#!/bin/sh

sudo cp /sys/kernel/debug/tracing/trace_pipe ~/Desktop/logs/$1
chmod 644 ~/Desktop/logs/$1
