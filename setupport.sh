#!/bin/bash
iptables -t filter -I OUTPUT -p tcp --sport 37624 --tcp-flags RST RST -j DROP
