#!/usr/bin/env bash
awk '{print $1}' /tmp/gen2q.strace | sort | uniq -c | sort -rn | head -20
