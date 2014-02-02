#!/bin/awk -f

# Copyright (c) 2014 yurm@bitcointalk.org
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Error/warning functions

# Generate error
# @ec: error code
# @str: error message
function generror(ec, str)
{
	print "Error: " str > "/dev/stderr"
	errcode = ec
	exit errcode
}

# Generate warning
# @str: warning message
function genwarning(str)
{
	print "Warning: " str > "/dev/stderr"
}

BEGIN {
	echo_exec = "/bin/echo"
}

# Search executables functions

# Search executable @exec in @path
# Returns: full pathname
function searchin(path, exec,    res)
{
	"[ -f '" path exec "' ] && [ -x '" path exec "' ] && " echo_exec " '" path exec "'" | getline res
	return res
}

# Search executable @exec in predefined paths
# Returns: full pathname
function searchexec(exec,    res)
{
	gsub(/'/, "", exec)
	gsub(/\s.*$/, "", exec)
	res = searchin("/usr/local/bin/", exec)
	if (res ~ /^\//) return res
	res = searchin("/usr/bin/", exec)
	if (res ~ /^\//) return res
	res = searchin("/bin/", exec)
	if (res ~ /^\//) return res
	res = searchin("/opt/bin/", exec)
	if (res ~ /^\//) return res
	return ""
}

BEGIN {
	# Excluded for security
	# coind_exec = (ENVIRON["COINDAEMON"] != "") ? ENVIRON["COINDAEMON"] : searchexec("bitcoind")

	# Used executables:
	coind_exec = searchexec("bitcoind")
	sed_exec =   searchexec("sed")
	bc_exec =    searchexec("bc")
	date_exec =  searchexec("date")
	if (coind_exec == "") generror(51, "bitcoind executable not found")
	if (sed_exec == "")   generror(52, "sed executable not found")
	if (bc_exec == "")    generror(53, "bc executable not found")
	if (date_exec == "")  generror(54, "date executable not found")

	# Error code
	errcode = 0
	# Address index, input index, output index (grows up), commission "output" index (grows down)
	aix = -1; iix = -1; oix = -1; ocommix = 0
	# Sequence number (for every output) as reverse byte ordered hex,
	# nlocktime as reverse byte ordered hex
	hexlock[0] = "ffffffff" ; hexlock[1] = "00000000"
	# Regular address regexp
	singleaddrheadregexp = "^1"
	# Multisignature address regexp
	multiaddrheadregexp = "^3"
}

# Log print functions

# Print debug message @str
# @sensitive is not empty for sensitive data (private keys)
function printdebug(str, sensitive, level)
{
	return
	if (sensitive != "") return
	print "DEBUG: " str > "/dev/stderr"
}

# Print final debug message @str
# @sensitive is not empty for sensitive data (private keys)
function printfinal(str, sensitive)
{
	return
	if (sensitive != "") return
	print "FINAL: " str > "/dev/stderr"
}

# Print external command to execute (@cmd)
# @category: caller function
function printcmd(category, cmd)
{
	return
	if (category == "signtransaction_nocheck")
		gsub(/'\[\".*\"\]'/, "'[\"<private keys>\"]'", cmd)
	print "CMD: " cmd > "/dev/stderr"
}

# General functions without side effects

# Calculate @expr via external command (bc)
# Used to avoid precision loss
function calculate_nocheck(expr,    cmd, res)
{
	gsub(/'/, "", expr)
	cmd = echo_exec " 'scale=8;" expr "' | " bc_exec
	printcmd("calculate_nocheck", cmd)
	cmd | getline res
	close(cmd)
	return gensub(/^\./, "0.", "", res)
}

# Convert @dec to reverse byte ordered hexadecimal
function hexrevert32_nocheck(dec,    hex)
{
	hex = sprintf("%08x", dec)
	return gensub(/^([[:xdigit:]]{2})([[:xdigit:]]{2})([[:xdigit:]]{2})([[:xdigit:]]{2})$/, "\\4\\3\\2\\1", "", hex)
}

# bitcoind getrawtransaction call (without return value check)
# @id: transaction id
# Returns: raw transaction
function getrawtransaction_nocheck(id,    cmd, res)
{
	cmd = coind_exec " getrawtransaction " id
	printcmd("getrawtransaction_nocheck", cmd)
	cmd | getline res
	close(cmd)
	return res
}

# Parse functions

# Parse line @line of bitcoind decoderawtransaction JSON result
# Set appropriate variables:
#     tx_i_id[txid, input_number], tx_i_vout[...] -
#         {id, vout} of previous corresponding transaction output for each input
#     tx_o_val[txid, output_number], tx_o_n[...], tx_o_addr[...], tx_o_script[...] -
#         {value, n, destination address, scriptPubKey} for each output
# @res: res[0] is used to return txid of decoded transaction
# @st: parser state
function parsedecodedtxline(res, st, line)
{
	printdebug(st[0] "\t" st[1] "\t" st[2] "\t" line, "", 4)
	switch (st[0]) {
	case 0:
		if      (line ~ /^ *\"txid\" *: *\"[[:xdigit:]]+\"/)
			res[0] = gensub(/^ *\"txid\" *: *\"([^\"]+)\".*$/, "\\1", "", line)
		else if (line ~ /^ *\"vin\" *: *\[ *$/)  {++st[0]; st[1] = 1; st[2] = -1}
		else if (line ~ /^ *\"vout\" *: *\[ *$/) {++st[0]; st[1] = 2; st[2] = -1}
		return
	case 1:
		switch (st[1]) {
		case 1: case 2:
			if      (line ~ /^ *\{ *$/)       {++st[0]; ++st[2]  }
			else if (line ~ /^ *\] *(, *)?$/) {--st[0]; st[1] = 0}
			return
		default:
			generror(41, "Invalid parser state (" st[0] "," st[1] "," st[2] ")")
		}
		return
	default:
		switch (st[1]) {
		case 1:
			if      (line ~ /^ *\"txid\" *: *\"[[:xdigit:]]+\"/)
				tx_i_id[res[0], st[2]] = gensub(/^ *\"txid\" *: *\"([^\"]*)\".*$/, "\\1", "", line)
			else if (line ~ /^ *\"vout\" *: *[0-9]+ *(,.*)?$/)
				tx_i_vout[res[0], st[2]] = gensub(/^ *\"vout\" *: *([0-9]+) *(,.*)?$/, "\\1", "", line)
			break
		case 2:
			if      (line ~ /^ *\"value\" *: *[0-9]+(\.[0-9]+)? *(,.*)?$/)
				tx_o_val[res[0], st[2]] = gensub(/^ *\"value\" *: *([0-9\.]+) *(,.*)?$/, "\\1", "", line)
			else if (line ~ /^ *\"n\" *: *[0-9]+ *(,.*)?$/)
				tx_o_n[res[0], st[2]] = gensub(/^ *\"n\" *: *([0-9]+) *(,.*)?$/, "\\1", "", line)
			else if (line ~ /^ *\"scriptPubKey\" *: *\{ *$/)
				st[1] = 4
			break
		case 4:
			if      (line ~ /^ *\"hex\" *: *\"[[:xdigit:]]+\"/)
				tx_o_script[res[0], st[2]] = gensub(/^ *\"hex\" *: *\"([^\"]+)\".*$/, "\\1", "", line)
			else if (line ~ /^ *\"addresses\" *: *\[ *$/)
				st[1] = 6
			else if (line ~ /^ *\} *(, *)?$/)
				st[1] = 2
			break
		case 6:
			if      (line ~ /^ *\"[[:alnum:]]+\"/)
				tx_o_addr[res[0], st[2]] = gensub(/^ *\"([[:alnum:]]+)\".*$/, "\\1", "", line)
			else if (line ~ /^ *\] *(, *)?$/)
				st[1] = 4
			break
		default:
			generror(41, "Invalid parser state (" st[0] "," st[1] "," st[2] ")")
		}
		if (line ~ /[{\[] *$/)         {++st[0]; return}
		if (line ~ /^ *[]}] *(, *)?$/) {--st[0]; return}
	}
}

# Parse transaction @tx
# Set appropriate variables (see parsedecodedtxline description)
# @tx: raw transaction
# Returns: @tx id
function parsetransaction(tx,    cmd, line, state, res)
{
	printdebug("parsetransaction")
	res[0] = rawtx_id[tx]
	if (res[0] != "") return res[0]
	cmd = coind_exec " decoderawtransaction " tx
	printcmd("parsetransaction", cmd)
	state[0] = 0
	while ((cmd | getline line) > 0)
		parsedecodedtxline(res, state, line)
	# Don't close cmd - results are buffered
	rawtx_id[tx] = res[0]
	return res[0]
}

# Parse seqnumber/nlocktime string @str
# @hexres: hexres[0] - sequence number as reverse byte ordered hex,
#          hexres[1] - nlocktime as reverse byte ordered hex
function parselock(hexres, str,    ltstr, cmd, declt, lt, nseq, n)
{
	printdebug("parselock")
	ltstr = gensub(/^l\s+[[:digit:]]+\s+/, "", "", str)
	gsub(/'/, "", ltstr)
	cmd = date_exec " --date='" ltstr "' '+%s'"
	printcmd("parselock", cmd)
	cmd | getline declt
	close(cmd)
	if (declt !~ /^[[:digit:]]+$/)
		generror(22, "Unable to convert locktime '" ltstr "'")
	lt = hexrevert32_nocheck(declt)
	if (lt !~ /^[[:xdigit:]]{8}$/)
		generror(22, "Unable to convert locktime '" ltstr "'")
	nseq = gensub(/^l\s+([[:digit:]]+)\s.*$/, "\\1", "", str)
	n = hexrevert32_nocheck(nseq)
	if (n !~ /^[[:xdigit:]]{8}$/)
		generror(23, "Unable to convert sequence number '" nseq "'")
	hexres[0] = n
	hexres[1] = lt
}

# Parse address string
# No complex actions, just concatenation
# Returns: combined address string (components separated by SUBSEP; used by makeaddress)
function parseaddress(num, a1, a2, a3)
{
	printdebug("parseaddress " num " " a1 " " a2 " " a3)
	if (num == "") return num
	if (a1 == "") return num
	num = num SUBSEP a1
	if (a2 == "") return num
	num = num SUBSEP a2
	if (a3 == "") return num
	num = num SUBSEP a3
	return num
}

# Functions that need real address

# Set bidirectional mapping between address @addr and public key @pub
# For multisignature @addr @pub is treated as redeemScript
function setpubkey(addr, pub)
{
	if ((addr == "") || (pub == "")) return
	if (addr ~ multiaddrheadregexp)
		redeem[addr] = pub
	else if (addr ~ singleaddrheadregexp) {
		addr_pub[addr] = pub
		pub_addr[pub] = addr
	}
}

# Validate address @addr (bitcoind validateaddress call)
# Set appropriate variables: addr_isvalid[@addr], addr_ismine[@addr], addr_isscript[@addr]
# Calls setpubkey
function validateaddress(addr,    cmd, line)
{
	printdebug("validateaddress " addr)
	cmd = coind_exec " validateaddress " addr
	printcmd("validateaddress", cmd)
	while ((cmd | getline line) > 0) {
		if      (line ~ /^ *\"isvalid\" *:/)
			addr_isvalid[addr] = (line ~ /^ *\"isvalid\" *: *true/) ? "1" : ""
		else if (line ~ /^ *\"ismine\" *:/)
			addr_ismine[addr] = (line ~ /^ *\"ismine\" *: *true/) ? "1" : ""
		else if (line ~ /^ *\"isscript\" *:/)
			addr_isscript[addr] = (line ~ /^ *\"isscript\" *: *true/) ? "1" : ""
		else if (line ~ /^ *\"pubkey\" *: *\"[[:xdigit:]]+\"/)
			setpubkey(addr, gensub(/^ *\"pubkey\" *: *\"([^\"]*)\".*$/, "\\1", "", line))
	}
	# Don't close cmd - results are buffered
}

# bitcoind dumpprivkey call for address @addr
# Set addr_priv[@addr]
function dumpprivkey(addr,    cmd, line)
{
	printdebug("dumpprivkey " addr)
	if (addr_priv[addr] != "") return
	cmd = coind_exec " dumpprivkey " addr
	printcmd("dumpprivkey", cmd)
	while ((cmd | getline line) > 0)
		if (line ~ /^[[:alnum:]]+$/) {
			addr_priv[addr] = line
			return
		}
	# Don't close cmd - results are buffered
}

# Retrieve private key for address @addr
# Returns: 1 on successful extraction, 0 otherwise (including previous extraction success for same @addr)
function retrieveprivkey(addr)
{
	printdebug("retrieveprivkey " addr)
	if (addr_priv[addr] != "") return 0
	validateaddress(addr)
	if ((addr_ismine[addr] == "") || (addr_isscript[addr] != "")) return 0
	dumpprivkey(addr)
	if (addr_priv[addr] == "")
		generror(3, "Cannot retrieve private key for address " addr " (is wallet locked?)")
	return (addr_priv[addr] != "") ? 1 : 0
}

# Retrieve private keys for multisignature address (@addr) participants
# Returns: number of newly retrieved private keys
function retrievemultisigprivkey(addr,    i, all)
{
	printdebug("retrievemultisigprivkey " addr)
	all = 0
	for (i = 0; multisig[addr, i] != ""; ++i)
		all += retrieveprivkey(multisig[addr, i])
	return all
}

# Retrieve scriptPubKey for address @addr
# Set script[@addr]
function retrieveaddressscript(addr,    cmdcreate, faketx, cmddecode, res)
{
	printdebug("retrieveaddressscript " addr)
	if ((addr == "") || (script[addr] != "")) return
	cmdcreate = coind_exec " createrawtransaction '[{\
		\"txid\":\"0000000000000000000000000000000000000000000000000000000000000000\",\
		\"vout\":0\
	}]' '{\"" addr "\":1.0}'"
	printcmd("retrieveaddressscript", cmdcreate)
	cmdcreate | getline faketx
	# Don't close cmd - results are buffered
	if (faketx !~ /^[[:xdigit:]]+$/)
		generror(7, "Cannot retrieve address script for address '" addr "' (is it valid?)")
	cmddecode = coind_exec " decoderawtransaction " faketx " | " sed_exec " -n '\
	/^ *\"vout\" *: *\\[/,$ {\
		/^ *\"hex\" *:/ {\
			s/^ *\"hex\" *: *\"\\([^\"]*\\)\".*$/\\1/;\
			p\
		}\
	}'"
	printcmd("retrieveaddressscript", cmddecode)
	cmddecode | getline res
	if (res !~ /^[[:xdigit:]]+$/)
		generror(6, "Cannot retrieve address script for address '" addr "'")
	script[addr] = res
	# Don't close cmd - results are buffered
}

# Read previous corresponding transaction for input @ix
# Set appropriate variables:
#     amount[@ix], src[@ix], script[src[@ix]] -
#         amount, source address, scriptPubKey of source address for input @ix
function readtransaction(ix,    rawtx, rix, val, asrc)
{
	printdebug("readtransaction " ix)
	rawtx = getrawtransaction_nocheck(txid[ix])
	if (rawtx !~ /^[[:xdigit:]]+$/)
		generror(5, "Unable to get raw transaction " txid[ix])
	rix = parsetransaction(rawtx)
	if (rix != txid[ix])
		generror(101, "Internal error - transaction id mismatch (" rix " != " txid[ix] ")")
	val = tx_o_val[txid[ix], vout[ix]]
	if ((amount[ix] != "") && (calculate_nocheck(amount[ix] "-" val) != 0))
		generror(11, "txin " ix ": amount '" amount[ix] "' is not valid (retrieved amount is '" val "')")
	amount[ix] = val
	asrc = tx_o_addr[txid[ix], vout[ix]]
	if ((src[ix] != "") && (src[ix] != asrc))
		generror(12, "txin " ix ": source address '" src[ix] "' is not valid (retrieved address is '" asrc "')")
	src[ix] = asrc
	if (script[src[ix]] == "")
		script[src[ix]] = tx_o_script[txid[ix], vout[ix]]
}

# Line pattern actions block

{
	parsed = 0
}

# Address description
/^a\s+(-\s+[[:alnum:]]+(\s+[[:alnum:]]+)?|[123](\s+[[:alnum:]]+){1,3})\s*$/ {
	printdebug("----addr----")
	parsed = 1
	addrtxt[++aix] = parseaddress($2, $3, $4, $5)
}

# Sequence number/nlocktime
/^l\s+[[:digit:]]+\s+/ {
	printdebug("----lock----")
	parsed = 1
	parselock(hexlock, $0)
}

# Input description
/^i\s+[[:xdigit:]]{64}\s+[[:digit:]]+(\s+-(\s+(-|[[:digit:]]+(\.[[:digit:]]{1,8})?)(\s+(-\s+[[:alnum:]]+(\s+[[:alnum:]]+)?|[123](\s+[[:alnum:]]+){1,3}))?)?)?\s*$/ {
	printdebug("----txin----")
	parsed = 1
	++iix

	txid[iix] = $2
	vout[iix] = $3
	# $4 is reserved for SIGHASH
	if (($5 != "-") && ($5 != "")) amount[iix] = $5
	srctxt[iix] = parseaddress($6, $7, $8, $9)
}

# Output description
/^o\s+(-|[[:digit:]]+(\.[[:digit:]]{1,8})?)(\s+(-\s+[[:alnum:]]+(\s+[[:alnum:]]+)?|[123](\s+[[:alnum:]]+){1,3}))?\s*$/ {
	printdebug("----txout----")
	parsed = 1

	dsttxtaddr = parseaddress($3, $4, $5, $6)
	dstvalue = ($2 != "-") ? calculate_nocheck("0+" $2) : $2
	if ($2 != 0) {
		coix = (dsttxtaddr != "") ? ++oix : --ocommix
		outval[coix] = dstvalue
		dsttxt[coix] = dsttxtaddr
	}
	else
		genwarning("Empty outputs are ignored, skipped '" $0 "'")
}

# Transaction (partial signed or full (for transaction check))
/^t\s+[[:xdigit:]]+\s*$/ {
	printdebug("----partial----")
	parsed = 1

	if (partialtx)
		generror(18, "Multiple partial transactions are not acceptable")
	partialtx = $2
}

# Action (no signing, check only)
/^checkonly\s*$/ {
	printdebug("----checkonly----")
	parsed = 1
	checkonly = 1
}

# Commentary
/^\s*([#;-].*)?$/ {
	parsed = 1
}

{
	if (parsed == 0)
		generror(21, "Unrecognized string '" $0 "'")
}

# Final parameters list creating functions

# Form transaction inputs list
# Returns: JSON array of transaction inputs
function formtxinlist(    res, i)
{
	res = "'["
	for (i = 0; txid[i] != ""; ++i) {
		if (res != "'[") res = res ","
		res = res "{\"txid\":\"" txid[i] "\",\"vout\":" vout[i] ",\"scriptPubKey\":\"" script[src[i]] "\""
		if (redeem[src[i]] != "") res = res ",\"redeemScript\":\"" redeem[src[i]] "\""
		res = res "}"
	}
	res = res "]'"
	return res
}

# Form transaction outputs list
# Returns: JSON list of transaction outputs
function formtxoutlist(    res, o)
{
	res = "'{"
	for (o = 0; outval[o] != ""; ++o) {
		if (dst[o] == "") continue
		if (res != "'{") res = res ","
		res = res "\"" dst[o] "\":" outval[o]
	}
	res = res "}'"
	return res
}

# Form private keys list
# Returns: JSON array of private keys
function formprivkeylist(    res, a)
{
	res = "'["
	for (a in addr_priv) {
		if (addr_priv[a] == "") continue
		if (res != "'[") res = res ","
		res = res "\"" addr_priv[a] "\""
	}
	res = res "]'"
	return res
}

# General final functions without side effects

# Modify sequence number and nlocktime for newly created transaction @createdtx
# @createdtx: newly created raw transaction
# @txincount: number of @createdtx inputs
# @hexnseq: sequence number to replace to (as reverse byte ordered hex)
# @hexlocktime: nlocktime to replace to (as reverse byte ordered hex)
# Returns: raw modified transaction
function modifylockfortransaction(createdtx, txincount, hexnseq, hexlocktime,    res, parts, n, i)
{
# Should parse raw transaction here instead of regexp replacing
	n = split(createdtx, parts, "00ffffffff")
	if (n > txincount + 1)
		generror(32, "Sequence number replacing failed (some false positives are possible): " createdtx)
	if (n < txincount + 1)
		generror(33, "Sequence number replacing failed (already replaced?): " createdtx)
	res = parts[1]
	for (i = 2; i <= n; ++i)
		res = res "00" hexnseq parts[i]
	gsub(/00000000$/, hexlocktime, res)
	return res
}

# Final action functions

# Check partial transaction (where id == @id) conformity with accumulated inputs/outputs
# (txid[], vout[], outval[], dst[])
function checkpartialtransaction(id,    ires, i, imax, ores, o, ox, oxmax)
{
	printdebug("checkpartialtransaction")
	ires = 0
	for (i = 0; tx_i_id[id, i] != ""; ++i) {
		if (tx_i_id[id, i] != txid[i]) {
			printdebug("(txid) " i " " tx_i_id[id, i] " != " txid[i], "", 3)
			ires = 1
		}
		if (tx_i_vout[id, i] != vout[i]) {
			printdebug("(vout) " i " " tx_i_vout[id, i] " != " vout[i], "", 3)
			ires = 1
		}
	}
	imax = i - 1

	ores = 0
	oxmax = -1
	for (o = 0; tx_o_n[id, o] != ""; ++o) {
		ox = tx_o_n[id, o]
		if (oxmax < ox) oxmax = ox
		# tx_o_val[id, o] is compared with outval[ox] (there is no mistyping in index)
		if (calculate_nocheck(tx_o_val[id, o] "-" outval[ox]) != 0) {
			printdebug("(value) " ox " " tx_o_val[id, o] " != " outval[ox], "", 3)
			ores = 1
		}
		if (tx_o_addr[id, o] != dst[ox]) {
			printdebug("(dst) " ox " " tx_o_addr[id, o] " != " dst[ox], "", 3)
			ores = 1
		}
	}

	if (ires != 0)
		generror(36, "Partial transaction doesn't match provided inputs")
	if (imax != iix)
		generror(37, "Partial transaction doesn't match provided inputs (additional inputs detected)")
	if (ores != 0)
		generror(38, "Partial transaction doesn't match provided outputs")
	if (oxmax != oix)
		generror(39, "Partial transaction doesn't match provided outputs (additional outputs detected)")
}

# Create multisignature address @num-of-{@a1, @a2, @a3}
# (or @num-of-{@a1, @a2} if @a3 is not set, or @num-of-{@a1} if @a2 and @a3 are not set)
# Attention: address orded is significant (e.g., 2-of-{a, b} != 2-of-{b, a})
# Returns: multisignature address
function createmultisigaddress(num, a1, a2, a3,    addr, aarray, parray, publist, cmd, line, aredeem, i)
{
	printdebug("createmultisigaddress " num " " a1 " " a2 " " a3)
	if ((a1 == "") && (a2 == "") && (a3 == "")) return ""
	i = -1
	if (a1 != "") aarray[++i] = a1
	if (a2 != "") aarray[++i] = a2
	if (a3 != "") aarray[++i] = a3
	for (i = 0; aarray[i] != ""; ++i) {
		parray[i] = (addr_pub[aarray[i]] != "") ? addr_pub[aarray[i]] : aarray[i]
		aarray[i] = (pub_addr[parray[i]] != "") ? pub_addr[parray[i]] : parray[i]
	}
	addr = multi_addr[num, aarray[0], aarray[1], aarray[2]]
	if (addr != "") return addr
	publist = "'["
	for (i = 0; aarray[i] != ""; ++i) {
		if (publist != "'[") publist = publist ","
		publist = publist "\"" parray[i] "\""
	}
	publist = publist "]'"
	cmd = coind_exec " createmultisig " num " " publist
	printcmd("createmultisigaddress", cmd)
	while ((cmd | getline line) > 0) {
		if      (line ~ /^ *\"address\" *: *\"[[:alnum:]]+\"/)
			addr = gensub(/^ *\"address\" *: *\"([^\"]*)\".*$/, "\\1", "", line)
		else if (line ~ /^ *\"redeemScript\" *: *\"[[:xdigit:]]+\"/)
			aredeem = gensub(/^ *\"redeemScript\" *: *\"([^\"]*)\".*$/, "\\1", "", line)
	}
	# Don't close cmd - results are buffered
	if ((addr !~ multiaddrheadregexp) || (aredeem !~ /^[[:xdigit:]]+$/))
		generror(2, "Invalid source multisig address " num "-of-" publist)
	printdebug("= createmultisigaddress " addr " " aredeem)
	multi_addr[num, aarray[0], aarray[1], aarray[2]] = addr
	redeem[addr] = aredeem
	for (i in aarray) multisig[addr, i] = aarray[i]
	return addr
}

# Convert text representation @atxt of address to real address (see parseaddress)
# @acceptmulti: permit createmultisigaddress call (for multisig addresses) if nonzero
# Returns: real address or empty string
function makeaddress(atxt, acceptmulti,    parts, n)
{
	printdebug("makeaddress " atxt)
	if (atxt == "") return ""
	n = split(atxt, parts, SUBSEP)
	if (n < 2)
		generror(1, "Invalid address '" atxt "' (you should use '- <address>' format)")
	if (parts[1] != "-") {
		if ((! acceptmulti) || (acceptmulti == 0)) return ""
		return createmultisigaddress(parts[1], parts[2], parts[3], parts[4])
	}
	validateaddress(parts[2])
	if (addr_isvalid[parts[2]] == "")
		generror(1, "Invalid address '" parts[2] "'")
	if (parts[3] != "") {
		if ((addr_pub[parts[2]] != "") && (addr_pub[parts[2]] != parts[3]))
			generror(4, "Invalid pubkey for address " parts[2])
		setpubkey(parts[2], parts[3])
	}
	return parts[2]
}

# Convert accumulated text representations (addrtxt[], srctxt[], dsttxt[]) of addresses to real addresses
# (see parseaddress)
# Set appropriate variables (src[i], dst[o])
function makeaddresses(    stage, a, i, o)
{
	for (stage = 0; stage <= 1; ++stage) {
		for (a in addrtxt)
			if (addrtxt[a] != "")
				makeaddress(addrtxt[a], stage)
		for (i in srctxt)
			if ((src[i] == "") && (srctxt[i] != ""))
				src[i] = makeaddress(srctxt[i], stage)
		for (o in dsttxt)
			if ((dst[o] == "") && (dsttxt[o] != ""))
				dst[o] = makeaddress(dsttxt[o], stage)
	}
}

# Process delayed actions (convert addresses,
# read previous corresponding transactions for inputs without full information,
# retrieve scriptPubKey of source address for each input,
# retrieve private keys for each input)
function processdelayedactions(    i)
{
	makeaddresses()
	for (i in txid) {
		if ((amount[i] == "") || (src[i] == ""))
			readtransaction(i)
		retrieveaddressscript(src[i])
		if (checkonly) continue
		if (src[i] ~ singleaddrheadregexp)
			retrieveprivkey(src[i])
		else if (src[i] ~ multiaddrheadregexp) {
			if ((multisig[src[i], 0] != "") && (redeem[src[i]] != ""))
				retrievemultisigprivkey(src[i])
			else
				genwarning("Input " i " signing is skipped, you should provide '" src[i] "' participants")
		}
	}
}

# Write change to output(s) where outval[o] == "-"
# Divide change equally if there are several such outputs
# Set outval[o]
function writechange(    volume, i, partvol, ochange, o, ochcount)
{
	volume = "0"
	for (i = 0; amount[i] != ""; ++i)
		volume = calculate_nocheck(volume "+" amount[i])

	ochcount = 0
	for (o = -1; outval[o] != ""; --o);
	for (++o; outval[o] != ""; ++o) {
		if (outval[o] == "-")
			ochange[ochcount++] = o
		else {
			volume = calculate_nocheck(volume "-" outval[o])
			if (volume < 0)
				generror(19, "Volume of outputs exseeds volume of inputs")
				#! May be correct (SIGHASH_ANYONECANPAY)
		}
	}
	if ((ochcount == 0) && (volume > 0))
		generror(20, "Volume of outputs isn't equal to volume of inputs (difference == " volume "). You should explicitly set change address and commission")
	if ((ochcount == 0) || (volume <= 0)) return

	partvol = calculate_nocheck(volume "/" ochcount)
	volume = calculate_nocheck(volume "-((" ochcount "-1)*" partvol ")")
	for (o = 0; ochange[o] != ""; ++o)
		outval[ochange[o]] = partvol
	outval[ochange[o - 1]] = volume
}

# bitcoind signrawtransaction call (without return value check)
# @tx: raw transaction to sign
# @txinlist: JSON array of transaction inputs
# @privkeylist: JSON array of private keys to sign with
# Returns: (fully/partially) signed raw transaction concatenated with result (true/false) via space
#
# Attention: there is a possibility of private key stealing via commandline (e.g., by "ps aux" or such command).
# Workaround: use distinct virtual guest system only for wallet and this script
function signtransaction_nocheck(tx, txinlist, privkeylist,    cmd, res)
{
	cmd = coind_exec " signrawtransaction " tx " " txinlist " " privkeylist " | " sed_exec " -n '\
	/^ *\"hex\" *:/ {\
		s/^ *\"hex\" *: *\"\\([^\"]*\\)\".*$/\\1/;\
		h\
	};\
	/^ *\"complete\" *:/ {\
		s/^ *\"complete\" *: *\\([^ ]*\\).*$/\\1/;\
		H\
	};\
	$ {\
		x;\
		s/\\n/ /g;\
		p\
	}\
	'"
	printcmd("signtransaction_nocheck", cmd)
	cmd | getline res
	close(cmd)
	return res
}

# Create raw transaction and call modifylockfortransaction
# @txinlist: JSON array of transaction inputs
# @txoutlist: JSON list of transaction outputs
# @txincount: number of transaction inputs
# @hexnseq, @hexlocktime: see modifylockfortransaction
# Returns: modified raw transaction
function maketransaction(txinlist, txoutlist, txincount, hexnseq, hexlocktime,    cmd, createdtx, modifiedtx)
{
	cmd = coind_exec " createrawtransaction " txinlist " " txoutlist
	printcmd("maketransaction", cmd)
	cmd | getline createdtx
	close(cmd)
	if (createdtx !~ /^[[:xdigit:]]+$/)
		generror(13, "Unable to create new transaction " txinlist " " txoutlist)
	modifiedtx = modifylockfortransaction(createdtx, txincount, hexnseq, hexlocktime)
	if (modifiedtx !~ /^[[:xdigit:]]+$/)
		generror(14, "Unable to modify new transaction " createdtx)
	return modifiedtx
}

# Main action block

END {
	printdebug("----final----")
	if (errcode != 0) exit errcode
	if (iix < 0)
		generror(16, "Transactions without inputs are unacceptable")

	processdelayedactions()
	writechange()

	if (partialtx != "")
		checkpartialtransaction(parsetransaction(partialtx))

	txinlist = formtxinlist()
	printfinal(txinlist)
	txoutlist = formtxoutlist()
	printfinal(txoutlist)
	privkeylist = checkonly ? "'[]'" : formprivkeylist()
	printfinal(privkeylist, "true")
	printfinal(hexlock[0] ":" hexlock[1])

	if (partialtx == "")
		partialtx = maketransaction(txinlist, txoutlist, iix + 1, hexlock[0], hexlock[1])
	signedtx = signtransaction_nocheck(partialtx, txinlist, privkeylist)
	if (signedtx !~ /^[[:xdigit:]]+ (true|false)$/)
		generror(9, "Unable to sign new transaction " partialtx)
	split(signedtx, signedtxparts)
	print (signedtxparts[2] == "true") ? parsetransaction(signedtxparts[1]) : signedtxparts[2]
	print signedtxparts[1]
}
