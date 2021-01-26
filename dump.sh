#!/bin/sh
domain=domain
user=username
pass=password
mkdir -p dump
docker run -it --rm -v "$PWD/dump":/tmp nla sh -c "
	/build/winpr/tools/hash-cli/winpr-hash -d $domain -u $user -p $pass -f sam > /build/sam
	echo SERVER
	xvfb-run -a /build/server/shadow/freerdp-shadow-cli /sec:nla /sam-file:/build/sam &
	sleep 1
	echo CLIENT
	xvfb-run -a /build/client/X11/xfreerdp /d:$domain /u:$user /p:$pass /v:127.0.0.1 /cert:ignore &
	sleep 1
	rm -rf /tmp/.X* /tmp/xvfb-run.*
	exit
"
