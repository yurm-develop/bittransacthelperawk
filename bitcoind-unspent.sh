#!/bin/sh

# Helper script to form unspent outputs list

# Copyright (c) 2014 yurm@bitcointalk.org
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

bitcoind listunspent | sed -n '
/"txid" *:/          {s/^ *"txid" *: *"\([^"]\+\)".*$/\1/;      h};
/"vout" *:/          {s/^ *"vout" *: *\([^,]\+\),$/\1/;         H};
/"address" *:/       {s/^ *"address" *: *"\([^"]\+\)".*$/\1/;   H};
/"account" *:/       {s/^ *"account" *: *\("[^"]\+"\).*$/\1/;   H};
/"amount" *:/        {s/^ *"amount" *: *\([^,]\+\),$/\1/;       H};
/"confirmations" *:/ {s/^ *"confirmations" *: *\([^,]\+\)$/\1/; H; x; s/\n/\t/g; p}
' | sed 's/^\([[:xdigit:]]\+\)\t\([[:digit:]]\+\)\t\([[:alnum:]]\+\)\t\("[^"]\+"\)\t\([[:digit:]\.]\+\)\t\([[:digit:]]\+\)/i\t\1 \2\t-\t\5\t-\t\3\t\6\t\4/' | sort -k 9
