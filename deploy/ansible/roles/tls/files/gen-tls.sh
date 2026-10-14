#!/usr/bin/env bash
# gen-tls.sh DIR ADDRESS
#
# Keeps a private CA and a certificate for the controller at ADDRESS (an IP
# or a DNS name, put in the subjectAltName) in DIR, for the controller's
# HTTPS API. Gateways and clients trust the CA; nothing else does.
#
# Running it again changes nothing, unless ADDRESS changed or a
# certificate expires within 30 days: then it issues what is needed. It
# prints "changed" when it wrote a file, "unchanged" otherwise.
set -euo pipefail

[[ $# -eq 2 ]] || { echo "usage: $0 DIR ADDRESS" >&2; exit 2; }
dir=$1 addr=$2
renew=$((30 * 86400))
umask 077
mkdir -p "$dir"
chmod 700 "$dir"
cd "$dir"

if [[ $addr =~ ^[0-9.]+$ || $addr == *:* ]]; then san="IP:$addr"; else san="DNS:$addr"; fi
changed=0

valid() { [[ -s $1 ]] && openssl x509 -in "$1" -noout -checkend "$renew" >/dev/null 2>&1; }

if [[ ! -s ca.key ]] || ! valid ca.crt; then
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-keyout ca.key -out ca.crt -days 3650 -subj "/CN=egressa testbed CA" \
		-addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
	rm -f controller.crt
	changed=1
fi

if [[ ! -s controller.key ]] || ! valid controller.crt || [[ $(cat controller.addr 2>/dev/null) != "$addr" ]] ||
	! openssl verify -CAfile ca.crt controller.crt >/dev/null 2>&1; then
	openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
		-keyout controller.key -out controller.csr -subj "/CN=$addr" 2>/dev/null
	printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' \
		"$san" >controller.ext
	openssl x509 -req -in controller.csr -CA ca.crt -CAkey ca.key -set_serial "0x$(openssl rand -hex 16)" \
		-days 825 -extfile controller.ext -out controller.crt 2>/dev/null
	rm -f controller.csr controller.ext
	echo "$addr" >controller.addr
	changed=1
fi

chmod 600 ./*
if [[ $changed == 1 ]]; then echo changed; else echo unchanged; fi
