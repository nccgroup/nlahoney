#!/usr/bin/env python3

#
# This parses a session from a server perspective
#

# Imports
import argparse
import binascii
import glob
import hashlib
import hmac
import os
import sys
import unittest

bDebug = True
bStreamDebug = False

def streamGetRemainingBytes(barray, streamindex):
	return (len(barray) - streamindex)

def streamReadBytes(barray, streamindex, number):
	if bStreamDebug is True: print("[d] streamindex " + str(streamindex))
	raw = barray[streamindex:streamindex+number]
	if bStreamDebug is True: print("[d] raw " + str(raw))
	streamindex=streamindex+number
	return raw, streamindex

def streamReadUint32(barray, streamindex):
	if bStreamDebug is True: print("[d] streamindex " + str(streamindex))
	raw = barray[streamindex:streamindex+4]
	if bStreamDebug is True: print("[d] raw " + str(raw))
	ret = int.from_bytes(raw,byteorder='little', signed=False)
	streamindex=streamindex+4
	return ret, streamindex

def streamReadUint16(barray, streamindex):
	if bStreamDebug is True: print("[d] streamindex " + str(streamindex))
	raw = barray[streamindex:streamindex+2]
	if bStreamDebug is True: print("[d] raw " + str(raw))
	ret = int.from_bytes(raw,byteorder='little', signed=False)
	streamindex=streamindex+2
	return ret, streamindex

def streamReadUint8(barray, streamindex):
	if bStreamDebug is True: print("[d] streamindex " + str(streamindex))
	raw = barray[streamindex:streamindex+1]
	if bStreamDebug is True: print("[d] raw " + str(raw))
	ret = int.from_bytes(raw,byteorder='little', signed=False)
	streamindex=streamindex+1
	return ret, streamindex

def checkHeaderandGetType(barray, streamindex):

	if str(barray[0:7].decode()) == "NTLMSSP":
		streamindex = streamindex + 8
		type,streamindex=streamReadUint32(barray, streamindex)
		return type,streamindex
	else:
		if bDebug is True: print("[d] " + barray[0:7].decode())
		return False,0


def streamReadNTLMMessageField(barray, streamindex):
	if streamGetRemainingBytes(barray,streamindex) < 8:
		return False

	len, streamindex = streamReadUint16(barray, streamindex)
	maxlen, streamindex = streamReadUint16(barray, streamindex)
	bufferoffset, streamindex = streamReadUint32(barray, streamindex)

	return True, streamindex, len, maxlen, bufferoffset

# AV Pair
# struct _NTLM_AV_PAIR
#{
#	UINT16 AvId;
#	UINT16 AvLen;
#};

def ntlmAVPairGet(avpairlist, avpairlistlen, whichavid):
	avpairlistindex= 0
	data = None

	while(avpairlistindex < avpairlistlen):
		avid,avpairlistindex =  streamReadUint16(avpairlist, avpairlistindex)
		avlen,avpairlistindex =  streamReadUint16(avpairlist, avpairlistindex)

		if avid == 0:
			print("[i] Parsing.. AV ID type is MsvAvEOL")
		elif avid == 1:
			print("[i] Parsing.. AV ID type is NB Computer Name")
		elif avid == 2:
			print("[i] Parsing.. AV ID type is NB Domain Name")
		elif avid == 3:
			print("[i] Parsing.. AV ID type is DNS Computer Name")
		elif avid == 4:
			print("[i] Parsing.. AV ID type is DNS Domain Name")
		elif avid == 5:
			print("[i] Parsing.. AV ID type is DNS Tree Name")
		elif avid == 6:
			print("[i] Parsing.. AV ID type is Flags")
		elif avid == 7:
			print("[i] Parsing.. AV ID type is Time Stamp")
		elif avid == 8:
			print("[i] Parsing.. AV ID type is Single Host")
		elif avid == 9:
			print("[i] Parsing.. AV ID type is Target Name")
		elif avid == 10:
			print("[i] Parsing.. AV ID type is Channel Bindings")

		if avid == whichavid:
			print("[i] Matched AV ID type - it is " + str(avlen) + " bytes long")

			if avid == 6: # MsvAvFlags
				data,avpairlistindex =  streamReadUint32(avpairlist, avpairlistindex)

			break
		elif avid == 0: # MsvAvEOL
			break
		else: # get next
			avpairlistindex = avpairlistindex + avlen

	return avid,data

#
def parseNegotiate(session, dir):
	print("[i] ** Parsing Negotiate for session " + str(session))

	streamindex = 0

	strFile = dir +"/" + str(session) + ".NegotiateIn.bin"
	hFile = open(strFile, 'rb')
	ba = bytearray(hFile.read())

	ret,streamindex = checkHeaderandGetType(ba,streamindex)
	if ret is False:
		print("[!] Packet magic is not present ")
		return False
	elif ret != 1: # MESSAGE_TYPE_NEGOTIATE
		print("[!] Incorrect message type " + str(ret))
		return False
	else:
		remaining = streamGetRemainingBytes(ba,streamindex);
		if remaining < 4:
			print("[!] Not enough bytes remaining " + str(remaining.stream))
			return False

		else:

			# Negotiate Flags
			NegotiateFlags,streamindex  = streamReadUint32(ba,streamindex)
			if not NegotiateFlags & 0x00000004 : 	# NTLMSSP_REQUEST_TARGET
				print("[!] Incorrect Negotiate flags")
				return False

			if not NegotiateFlags & 0x00000200 : 	# NTLMSSP_NEGOTIATE_NTLM
				print("[!] Incorrect Negotiate flags")
				return False

			if not NegotiateFlags & 0x00000001 : 	# NTLMSSP_NEGOTIATE_UNICODE
				print("[!] Incorrect Negotiate flags")
				return False

			print("[i] Got Negotiate flags")

			# Domain
			bSuccess, streamindex, len, maxlen, bufferoffset = streamReadNTLMMessageField(ba, streamindex)
			print("[i] Domain Length: " + str(len) + " at " +str(bufferoffset))

			# Workstation
			bSuccess, streamindex, len, maxlen, bufferoffset = streamReadNTLMMessageField(ba, streamindex)
			print("[i] Workstation Length: " + str(len) + " at " +str(bufferoffset))

			# NegotiateFlags & 0x02000000 which is NTLMSSP_NEGOTIATE_VERSION
			if NegotiateFlags & 0x02000000: # NTLMSSP_NEGOTIATE_VERSION
				# Product Version
				negotiateProductMajorVersion,streamindex = streamReadUint8(ba,streamindex)
				negotiateProductMinorVersion,streamindex = streamReadUint8(ba,streamindex)
				negotiateProductProductBuild,streamindex = streamReadUint16(ba,streamindex)
				streamindex = streamindex + 1 # Skips over a reserved
				negotiateNTLMRevisionCurrent,streamindex  = streamReadUint8(ba,streamindex)
				print("[i] from Version: " + str(negotiateProductMajorVersion) + "." + str(negotiateProductMinorVersion) + " build (" + str(negotiateProductProductBuild) +") NTLM Revision " + str(negotiateNTLMRevisionCurrent))

			return True


#
def parseChallenge(session, dir):
	print("[i] ** Parsing Challenge for session " + str(session))

	streamindex = 0

	strFile = dir + "/" + str(session) + ".ChallengeOut.bin"
	hFile = open(strFile, 'rb')
	ba = bytearray(hFile.read())

	ret,streamindex = checkHeaderandGetType(ba,streamindex)
	if ret is False:
		print("[!] Packet magic is not present ")
		return False
	elif ret != 2: # MESSAGE_TYPE_CHALLENGE
		print("[!] Incorrect message type " + str(ret))
		return False
	else:
		remaining = streamGetRemainingBytes(ba,streamindex);
		if remaining < 4:
			print("[!] Not enough bytes remaining " + str(remaining.stream))
			return False

		else:

			# Target Name
			bSuccess, streamindex, tnlen, tnmaxlen, tnbufferoffset = streamReadNTLMMessageField(ba, streamindex)
			print("[i] Target Name Length: " + str(tnlen) + " at " +str(tnbufferoffset))

			# Negotiate Flags
			NegotiateFlags,streamindex  = streamReadUint32(ba,streamindex)
			print("[i] Got Negotiate flags")

			challenge,streamindex = streamReadBytes(ba,streamindex,8)
			print("[i] Got Servers challenge " + str(binascii.hexlify(challenge)))

			reserved,streamindex = streamReadBytes(ba,streamindex,8)
			print("[i] Skipped reserved ")

			# Target Info
			bSuccess, streamindex, tilen, timaxlen, tibufferoffset = streamReadNTLMMessageField(ba, streamindex)
			print("[i] Target Info Length: " + str(tilen) + " at " +str(tibufferoffset))

			# NegotiateFlags & 0x02000000 which is NTLMSSP_NEGOTIATE_VERSION
			if NegotiateFlags & 0x02000000: # NTLMSSP_NEGOTIATE_VERSION
				# Product Version
				negotiateProductMajorVersion,streamindex = streamReadUint8(ba,streamindex)
				negotiateProductMinorVersion,streamindex = streamReadUint8(ba,streamindex)
				negotiateProductProductBuild,streamindex = streamReadUint16(ba,streamindex)
				streamindex = streamindex + 1 # Skips over a reserved
				negotiateNTLMRevisionCurrent,streamindex  = streamReadUint8(ba,streamindex)
				print("[i] from Version: " + str(negotiateProductMajorVersion) + "." + str(negotiateProductMinorVersion) + " build (" + str(negotiateProductProductBuild) +") NTLM Revision " + str(negotiateNTLMRevisionCurrent))

			# Target Name
			if NegotiateFlags & 0x00000004 : 	# NTLMSSP_REQUEST_TARGET
				targetname,throwaway = streamReadBytes(ba,tnbufferoffset,tnlen)
				print("[i] Got Target Name " + str(targetname.decode('utf8', errors='ignore')))

			# Target Info - maybe parse this?
			if NegotiateFlags & 0x00800000 :	# NTLMSSP_NEGOTIATE_TARGET_INFO
				targetinfo,throwaway= streamReadBytes(ba,tibufferoffset,tilen)
				print("[i] Got Target Info " + str(binascii.hexlify(targetinfo)))

			return True, challenge, targetname, targetinfo

#
def parseAuthenticate(session, dir ):
	print("[i] ** Parsing Authenticate for session " + str(session))

	streamindex = 0

	strFile = dir +"/" + str(session) + ".AuthenticateIn.bin"
	hFile = open(strFile, 'rb')
	ba = bytearray(hFile.read())

	ret,streamindex = checkHeaderandGetType(ba,streamindex)
	if ret is False:
		print("[!] Packet magic is not present ")
		return False
	elif ret != 3: # MESSAGE_TYPE_AUTHENTICATE
		print("[!] Incorrect message type " + str(ret))
		return False
	else:
		remaining = streamGetRemainingBytes(ba,streamindex);
		if remaining < 4:
			print("[!] Not enough bytes remaining " + str(remaining.stream))
			return False

		else:
			# LmChallengeResponse
			bSuccess, streamindex, lmcrlen, lmcrmaxlen, lmcrbufferoffset = streamReadNTLMMessageField(ba, streamindex)
			print("[i] LM Challenge Response Length: " + str(lmcrlen) + " at " +str(lmcrbufferoffset))

			# NtChallengeResponse
			#  Note: client challenge is in here and the message integrity code
			bSuccess, streamindex, ntcrlen, ntcrmaxlen, ntcrbufferoffset = streamReadNTLMMessageField(ba, streamindex)
			print("[i] NT Challenge Response Length: " + str(ntcrlen) + " at " +str(ntcrbufferoffset))

			# Domain Name
			bSuccess, streamindex, domlen, dommaxlen, dombufferoffset = streamReadNTLMMessageField(ba, streamindex)
			print("[i] Domain Name Length: " + str(domlen) + " at " +str(dombufferoffset))
			domain,throwaway = streamReadBytes(ba,dombufferoffset,domlen)
			print("[i] Got Domain " + str(domain.decode('utf8', errors='ignore')))

			# User Name
			bSuccess, streamindex, usrlen, usrmaxlen, usrbufferoffset = streamReadNTLMMessageField(ba, streamindex)
			print("[i] User Name Length: " + str(usrlen) + " at " +str(usrbufferoffset))
			username,throwaway = streamReadBytes(ba,usrbufferoffset,usrlen)
			print("[i] Got User Name " + str(username.decode('utf8', errors='ignore')))

			# Workstation
			bSuccess, streamindex, wslen, wsmaxlen, wsbufferoffset = streamReadNTLMMessageField(ba, streamindex)
			print("[i] Workstation Length: " + str(wslen) + " at " +str(wsbufferoffset))
			workstation,throwaway = streamReadBytes(ba,wsbufferoffset,wslen)
			print("[i] Got Workstation " + str(workstation.decode('utf8', errors='ignore')))

			# Encryted Random Session Key
			bSuccess, streamindex, ersklen, erskmaxlen, erskbufferoffset = streamReadNTLMMessageField(ba, streamindex)
			print("[i] Encrypted Random Session Key Length: " + str(ersklen) + " at " +str(erskbufferoffset))
			encryptedrandomsessionkey,throwaway = streamReadBytes(ba,erskbufferoffset,ersklen)
			print("[i] Got Encrypted Random Session Key")

			# Negotiate Flags
			NegotiateFlags,streamindex  = streamReadUint32(ba,streamindex)
			print("[i] Got Negotiate flags")


			# NegotiateFlags & 0x02000000 which is NTLMSSP_NEGOTIATE_VERSION
			if NegotiateFlags & 0x02000000: # NTLMSSP_NEGOTIATE_VERSION
				# Product Version
				negotiateProductMajorVersion,streamindex = streamReadUint8(ba,streamindex)
				negotiateProductMinorVersion,streamindex = streamReadUint8(ba,streamindex)
				negotiateProductProductBuild,streamindex = streamReadUint16(ba,streamindex)
				streamindex = streamindex + 1 # Skips over a reserved
				negotiateNTLMRevisionCurrent,streamindex  = streamReadUint8(ba,streamindex)
				print("[i] from Version: " + str(negotiateProductMajorVersion) + "." + str(negotiateProductMinorVersion) + " build (" + str(negotiateProductProductBuild) +") NTLM Revision " + str(negotiateNTLMRevisionCurrent))

			# Save this for later
			PayloadBufferOffset = streamindex

			# Parse the NtChallengeResponse we read above
			if ntcrlen > 0:
				ntcrstreamindex = 0
				print("[i] Remaining " + str(ntcrlen - ntcrstreamindex))

				ntcrba, throwaway = streamReadBytes(ba, ntcrbufferoffset, ntcrlen)
				ntcrresponse, ntcrstreamindex = streamReadBytes(ntcrba, ntcrstreamindex, 16)

				if ntcrlen - ntcrstreamindex < 28:
					print("[!] Not enough data in the NT Challenge Response byte array")

				else: # this is ntlm_read_ntlm_v2_client_challenge in ntlm_compute.c in FreeRDP
					ntcrresptype,ntcrstreamindex =  streamReadUint8(ntcrba, ntcrstreamindex)
					ntcrhiresptype,ntcrstreamindex =  streamReadUint8(ntcrba, ntcrstreamindex)

					ntcrreserved1,ntcrstreamindex =  streamReadUint16(ntcrba, ntcrstreamindex)
					ntcrreserved2,ntcrstreamindex =  streamReadUint32(ntcrba, ntcrstreamindex)

					ntcrtimestamp,ntcrstreamindex =  streamReadBytes(ntcrba, ntcrstreamindex, 8)
					print("[i] Got Clients timestamp " + str(binascii.hexlify(ntcrtimestamp)))

					ntcrclientchallenge,ntcrstreamindex =  streamReadBytes(ntcrba, ntcrstreamindex, 8)
					print("[i] Got Clients challenge " + str(binascii.hexlify(ntcrclientchallenge)))

					ntcrreserved3,ntcrstreamindex =  streamReadUint32(ntcrba, ntcrstreamindex)

					#print("[d] Remaining " + str(ntcrlen - ntcrstreamindex))

					# AV Pairs

					ntcravpairslen = ntcrlen - ntcrstreamindex
					ntcravpairsba,ntcrstreamindex =  streamReadBytes(ntcrba, ntcrstreamindex, ntcravpairslen )

					avid, aviddata = ntlmAVPairGet(ntcravpairsba, ntcravpairslen, 6) # MsvAvFlags == 6

					flags = aviddata

			if(flags & 0x00000002):
				# I know know yet why we are off by two here
				print("[i] Message Integrity Check/Code (MIC) Present at " + str(PayloadBufferOffset+2))

				# I've verified the MIC returned here is correct
				# from the patched ntlm_message.c on a known session
				mic,throwaway =  streamReadBytes(ba, PayloadBufferOffset+2, 16)
				print("[i] Got MIC " + str(binascii.hexlify(mic)))

				# Now return a whole host of stuff
				return True, str(username.decode('utf8', errors='ignore')), str(domain.decode('utf8', errors='ignore')), flags, ba, ntcrclientchallenge, ntcrtimestamp, mic, str(workstation.decode('utf8', errors='ignore')), ntcrresponse
				
			else:
				return False
			
			
def recalcandCompareMIC(username, domain, password, avflags, binaryarray, serverchallenge, clientchallenge, mic, ntcrresponse):

	#
	# there are two ways to verify if the password supplied is correct
	# NtProofString - we don't support (see ntlm_message.c) - this is Windows NT, Windows 2000, Windows XP and
	#				 Windows Server 2003
	# Message Integrity Check - we do support
	#

	ourmic = None

	print("[i] Cracking..")

	#
	# TODO - Yawn....
	#

	# compute AuthNtlmHash - see ntlm_SetContextAttributesW 
	# NOT sure we need to do this 

	# compute LM v2 response - see ntlm_compute_lm_v2_response
	# this involves ntlm_compute_ntlm_v2_hash to get the hash from our SAM
	#    this has a subset of running NTOWFv2FromHashW on it
	# THEN concatenating  the server challenge and client challenge
	# THEN doing an HMAC-MD5 of the concatenated buffer with the NTLMv2 hash as the key
	# THEN concatenating the HMAC-MD5 with the Client Challenge giving us the LMv2 response

	# Unsure if it needs to be like this or a string
	testsamhash = bytes.fromhex("88 46 f7 ea ee 8f b1 17 ad 06 bd d8 30 b7 58 6c") # we would need to do the pre-calc for passwords
	testntlmv1 = bytes.fromhex('88 46 f7 ea ee 8f b1 17 ad 06 bd d8 30 b7 58 6c')
	testusername = bytes.fromhex('75 73 65 72 6e 61 6d 65').decode().encode('utf-16le')	# 'username'
	testdomain = bytes.fromhex('64 6f 6d 61 69 6e').decode().encode('utf-16le')	# 'domain'
	testbuffer = bytes.fromhex('55 00 53 00 45 00 52 00 4e 00 41 00 4d 00 45 00 64 00 6f 00 6d 00 61 00 69 00 6e 00')	# 'USERNAMEdomain'
	testntlmv2 = bytes.fromhex('a3 06 37 10 10 c4 39 fe c3 97 ec 2b 83 66 17 17')

	# NTOWFv2FromHashW
	# this concatenates the UPPERCASE username and domain
	# then does HMAC-MD5 using the NTLMv1 from the SAM file as the key results is NTLMv2
	upperuserandomain = testusername.upper() + testdomain

	ntlmv2hash = hmac.new(testsamhash, upperuserandomain, hashlib.md5).digest()

	if ntlmv2hash != testntlmv2:
		print("[!] ntlmv2hash miscalculation")

	serverandclientbuffer = serverchallenge + clientchallenge
	if len(serverandclientbuffer) != 16:
		return False

	lmv2response = hmac.new(ntlmv2hash, bytes(serverandclientbuffer), hashlib.md5).digest()

	#
	# UP TO HERE ON IMPLEMENTATION - NOT TESTED
	#

	# compute NTLM v2 response - see ntlm_compute_ntlm_v2_response
	# this involves ntlm_compute_ntlm_v2_hash using the output of AuthNtlmHash
	# THEN concatenating the two fixed bytes, client timestamp, client challenge, reserved 4 bytes into temp
	# THEN concatenating temp with the server challenge
	# THEN doing an HMAC-MD5 of the concatenated buffer with the NTLMv2 hash as the key
	# THEN taking the output and then
	#  - raw it becomes NtProofString
	#  - from byte 16 onwards into a temp buffer (doesnt appear to be used)
	#  - computing the SessionBaseKey which is HMAC-MD5 hash of NtProofString using the NTLMv2 hash as the key
	ntlmv2response = None
	ntproofstring = None

	# HYPOTHESIS:
	#   - above we will just computed NtProofString
	#   - we can use this with NTLMv2Response ( see ntlm_read_AuthenticateMessage and ntlm_server_AuthenticateComplete)
	#	  to see if the entered password is correct
	# this would reduce the computational overhead per password significantly as we wouldn't need to do the below
	# i.e. it would be two round of HMAC-MD5
	#
	# if this is correct the below logic will work
	if ntcrresponse == ntlmv2response:
		return True

	# generate key exchange - see ntlm_generate_key_exchange_key
	# this is simply the SessionBaseKey we calculated just before

	# decrypt random session key - see ntlm_decrypt_random_session_key
	# ... TODO here little bit blegh ...

	# generate exported session key - see ntlm_generate_exported_session_key
	# this is the RandomSessionKey we calculated just before

	# compute our Message Integrity Check - ntlm_compute_message_integrity_check
	# we zero the MIC in the authenticate message (as are about to calculate it)
	# the HMAC-MD5 hash of ConcatenationOf(NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE, AUTHENTICATE_MESSAGE)
	# all using the ExportedSessionKey

	# compare Message Integrity Check
	if ourmic == mic:
		return True
	else:
		return False



	return False

# Parse the files
def parsefiles(session, dir):

	# We parse the files
	if parseNegotiate(session,dir) is True:

		success, serverchallenge, targetname, targetinfo = parseChallenge(session,dir)

		if success is True:

			success, username, domain, avflags, binaryarray, clientchallenge, clienttimestamp, mic, workstation, ntcrresponse = parseAuthenticate(session,dir)

			if success is True:

				# We do some calculations
				success = recalcandCompareMIC(username, domain, "test", avflags, binaryarray, serverchallenge, clientchallenge, mic, ntcrresponse)

				if success is True:
					print("[*] Attacker from " + workstation.decode() + " using " + domain.decode() + "\\" + username.decode() + " with " + password)
				else:
					print("[!] Attacker from " + workstation + " using " + domain + "\\" + username + " but we failed to crack the password")
				

# Check the files we need exist
def checkfiles(session, dir):
	strFile = dir + "/" + str(session) + ".NegotiateIn.bin"

	if os.path.exists(strFile) is not True:
		print("[!] Could not file inbound Negotiate packet file " + strFile)
		return False
	else:
		print("[i] Found Negotiate packet file")

	strFile = dir + "/" + str(session) + ".ChallengeOut.bin"

	if os.path.exists(strFile) is not True:
		print("[!] Could not file outbound Challenge packet file " + strFile )
		return False
	else:
		print("[i] Found Challenge packet file")

	strFile = dir + "/" + str(session) + ".AuthenticateIn.bin"

	if os.path.exists(strFile) is not True:
		print("[!] Could not file inbound Authenticate file" + strFile)
		return False
	else:
		print("[i] Found Authenticate packet file")

	return True

# Process
def process(session, dir):
	print("[i] Processing session " + str(session))

	if checkfiles(session,dir) is not True:
		print("[!] Could not find required session files")
		return
	else:
		parsefiles(session,dir)
		
# Entry point to script
if sys.version_info[0] < 3:
	print("[!] Must be Python 3")
	sys.exit(1)
	
parser = argparse.ArgumentParser()
parser.add_argument("-d","--dir", help="directory containing dumps", default="/tmp")
parser.add_argument("session", help="parse this session", type=int)
args = parser.parse_args()
process(args.session,args.dir)


