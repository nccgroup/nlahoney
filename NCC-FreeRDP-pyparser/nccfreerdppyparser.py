#!/bin/python

#
# This parses a session from a server perspective
#

# Imports
import glob
import argparse
import os

bDebug = True
bStreamDebug = False

def checkHeaderandGetType(barray, streamindex):
	
	if str(barray[0:7].decode()) == "NTLMSSP":
		type = barray[8:9]
		streamindex=streamindex+8
		return int.from_bytes(type,byteorder='big', signed=False),streamindex
	else:
		if bDebug is True: print("[d] " + barray[0:7].decode())
		return False,0

def streamGetRemainingBytes(barray, streamindex):
	return (len(barray) - streamindex)

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


#
def parseNegotiate(session):
	print("[i] Parsing Negotiate for " + str(session))
	
	streamindex = 0
	
	strFile = "/tmp/" + str(session) + ".NegotiateIn.bin"
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
			if NegotiateFlags & 0x00000004 is False: 	# NTLMSSP_REQUEST_TARGET
				print("[!] Incorrect Negotiate flags")
				return False
				
			if NegotiateFlags & 0x00000200 is False: 	# NTLMSSP_NEGOTIATE_NTLM
				print("[!] Incorrect Negotiate flags")
				return False
		
			if NegotiateFlags & 0x00000001   is False: 	# NTLMSSP_NEGOTIATE_UNICODE
				print("[!] Incorrect Negotiate flags")
				return False
			
			# Product Version
			ProductMajorVersion,streamindex = streamReadUint8(ba,streamindex)
			ProductMinorVersion,streamindex = streamReadUint8(ba,streamindex)
			ProductProductBuild,streamindex = streamReadUint16(ba,streamindex)
			streamindex = streamindex + 1 # Skips over a reserved
			NTLMRevisionCurrent,streamindex  = streamReadUint8(ba,streamindex)
			print("[i] from Version: " + str(ProductMajorVersion) + "." + str(ProductMinorVersion) + " build (" + str(ProductProductBuild) +") NTLM Revision " + str(NTLMRevisionCurrent))
			
			# TODO: Read the domain if present
			
			# TODO: Read the workstation if present
			
			# TODO: Check NegotiateFlags & 0x02000000 which is NTLMSSP_NEGOTIATE_VERSION 
			#       if present read the version out
			

#
def parseChallenge(session):
	print("[i] Parsing Challenge for " + str(session))

#
def parseAuthenticate(session):
	print("[i] Parsing Authenticate for " + str(session))
	
# Parse the files
def parsefiles(session):

	# We parse the files
	if parseNegotiate(session) is True:
		if parseChallenge(session) is True:
			if parseAuthenticate(session) is True:
				print("[i] Cracking..")
				# We do some calculations

# Check the files we need exist
def checkfiles(session):
	strFile = "/tmp/" + str(session) + ".NegotiateIn.bin"
	
	if os.path.exists(strFile) is not True:
		print("[!] Could not file inbound Negotiate packet file " + strFile)
		return False
	else:
		print("[i] Found Negotiate packet file")
	
	strFile = "/tmp/" + str(session) + ".ChallengeOut.bin"
		
	if os.path.exists(strFile) is not True:
		print("[!] Could not file outbound Challenge packet file " + strFile )
		return False
	else:
		print("[i] Found Challenge packet file")
		
	strFile = "/tmp/" + str(session) + ".AuthenticateIn.bin"
		
	if os.path.exists(strFile) is not True:
		print("[!] Could not file inbound Authenticate file" + strFile)
		return False
	else:
		print("[i] Found Authenticate packet file")
		
	return True
	
# Process 
def process(session):
	print("[i] Processing session " + str(session))

	if checkfiles(session) is not True:
		print("[!] Could not find required session files")
		return
	else:
		parsefiles(session)
		
# Entry point to script
parser = argparse.ArgumentParser()
parser.add_argument("session", help="parse this session", type=int)
args = parser.parse_args()
process(args.session)
