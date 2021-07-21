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
import io
import os
import pprint
import struct
import sys
import unittest

from md4 import MD4


MESSAGE_TYPE_NEGOTIATE = 1
MESSAGE_TYPE_CHALLENGE = 2
MESSAGE_TYPE_AUTHENTICATE = 3
MSV_AV_FLAGS_MESSAGE_INTEGRITY_CHECK = 0x00000002
NTLMSSP_NEGOTIATE_UNICODE = 0x00000001
NTLMSSP_NEGOTIATE_NTLM = 0x00000200
NTLMSSP_NEGOTIATE_VERSION = 0x02000000
NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000
NTLMSSP_REQUEST_TARGET = 0x00000004
SSPI_CREDENTIALS_HASH_LENGTH_OFFSET = 512
UINT32_MAX = 0xffffffff

# AV Pair
# struct _NTLM_AV_PAIR
#{
#	UINT16 AvId;
#	UINT16 AvLen;
#};

# enum _NTLM_AV_ID
MsvAvEOL = 0
MsvAvNbComputerName = 1
MsvAvNbDomainName = 2
MsvAvDnsComputerName = 3
MsvAvDnsDomainName = 4
MsvAvDnsTreeName = 5
MsvAvFlags = 6
MsvAvTimestamp = 7
MsvAvSingleHost = 8
MsvAvTargetName = 9
MsvChannelBindings = 10

# enum _NTLM_STATE
NTLM_STATE_INITIAL = 0
NTLM_STATE_NEGOTIATE = 1
NTLM_STATE_CHALLENGE = 2
NTLM_STATE_AUTHENTICATE = 3
NTLM_STATE_COMPLETION = 4
NTLM_STATE_FINAL = 5


def Stream_Read(s, n):
	raw = s.read(n)
	assert len(raw) == n
	return raw


def Stream_Read_UINT8(s):
	raw = Stream_Read(s, 1)
	return int.from_bytes(raw, byteorder="little", signed=False)


def Stream_Read_UINT16(s):
	raw = Stream_Read(s, 2)
	return int.from_bytes(raw, byteorder="little", signed=False)


def Stream_Read_UINT32(s):
	raw = Stream_Read(s, 4)
	return int.from_bytes(raw, byteorder="little", signed=False)


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm_message.c:/^static int ntlm_read_message_header\(
def ntlm_read_message_header(s):
	header = {}
	header["Signature"] = Stream_Read(s, 8)
	header["MessageType"] = Stream_Read_UINT32(s)
	return header


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm_message.c:/^static int ntlm_read_message_fields\(
def ntlm_read_message_fields(s):
	fields = {}
	fields["Len"] = Stream_Read_UINT16(s)	# Len (2 bytes)
	fields["MaxLen"] = Stream_Read_UINT16(s)	# MaxLen (2 bytes)
	fields["BufferOffset"] = Stream_Read_UINT32(s)	# BufferOffset (4 bytes)
	return fields


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm_message.c:/^static int ntlm_read_message_fields_buffer\(
def ntlm_read_message_fields_buffer(s, fields):
	offset = fields["BufferOffset"] + fields["Len"]
	s.seek(fields["BufferOffset"])
	fields["Buffer"] = Stream_Read(s, fields["Len"])


def checkHeaderandGetType(s):
	header = Stream_Read(s, 8)
	assert header[0:7] == b"NTLMSSP"
	type = Stream_Read_UINT32(s)
	return type


def streamReadNTLMMessageField(s):
	len = Stream_Read_UINT16(s)
	maxlen = Stream_Read_UINT16(s)
	bufferoffset = Stream_Read_UINT32(s)
	return len, maxlen, bufferoffset


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm_av_pairs.c:/^NTLM_AV_PAIR\* ntlm_av_pair_get\(
def ntlm_av_pair_get(pAvPairList, AvId):
	with io.BytesIO(pAvPairList) as avpairlist:
		while True:
			avid =  Stream_Read_UINT16(avpairlist)
			avlen =  Stream_Read_UINT16(avpairlist)

			print("[i] Parsing.. AV ID type is {avid=}")

			if avid == AvId:
				print(f"[i] Matched AV ID type - it is {avlen} bytes long")

				if avid == MsvAvFlags:
					return Stream_Read_UINT32(avpairlist)
				elif avid == MsvAvTimestamp:
					return Stream_Read(avpairlist, avlen)
				else:
					raise ValueError(f"ntlm_av_pair_get: unhandled {avid=}")

				break
			elif avid == MsvAvEOL:
					raise ValueError(f"ntlm_av_pair_get: MsvAvEOL")
			else: # get next
				avpairlist.seek(avlen, io.SEEK_CUR)


#
def parseNegotiate(session, dir):
	strFile = dir +"/" + str(session) + ".NegotiateIn.bin"
	print(f"[i] ** Parsing {strFile}")

	hFile = open(strFile, 'rb')

	ret = checkHeaderandGetType(hFile)
	assert ret == MESSAGE_TYPE_NEGOTIATE

	# Negotiate Flags
	NegotiateFlags = Stream_Read_UINT32(hFile)
	assert NegotiateFlags & NTLMSSP_REQUEST_TARGET
	assert NegotiateFlags & NTLMSSP_NEGOTIATE_NTLM
	assert NegotiateFlags & NTLMSSP_NEGOTIATE_UNICODE
	print("[i] Got Negotiate flags")

	# Domain
	len, maxlen, bufferoffset = streamReadNTLMMessageField(hFile)
	print(f"[i] Domain Length: {len} at {bufferoffset}")

	# Workstation
	len, maxlen, bufferoffset = streamReadNTLMMessageField(hFile)
	print(f"[i] Workstation Length: {len} at {bufferoffset}")

	assert NegotiateFlags & NTLMSSP_NEGOTIATE_VERSION

	# Product Version
	negotiateProductMajorVersion = Stream_Read_UINT8(hFile)
	negotiateProductMinorVersion = Stream_Read_UINT8(hFile)
	negotiateProductProductBuild = Stream_Read_UINT16(hFile)
	__ = Stream_Read_UINT8(hFile) # Skip reserved byte
	negotiateNTLMRevisionCurrent  = Stream_Read_UINT8(hFile)
	print("[i] from Version: " + str(negotiateProductMajorVersion) + "." + str(negotiateProductMinorVersion) + " build (" + str(negotiateProductProductBuild) +") NTLM Revision " + str(negotiateNTLMRevisionCurrent))


#
def parseChallenge(session, dir):
	strFile = dir + "/" + str(session) + ".ChallengeOut.bin"
	print(f"[i] ** Parsing {strFile}")

	streamindex = 0

	s = open(strFile, 'rb')

	ret = checkHeaderandGetType(s)
	assert ret == MESSAGE_TYPE_CHALLENGE

	# Target Name
	tnlen, tnmaxlen, tnbufferoffset = streamReadNTLMMessageField(s)
	print(f"[i] Target Name Length: {tnlen} at {tnbufferoffset}")

	# Negotiate Flags
	NegotiateFlags = Stream_Read_UINT32(s)
	print("[i] Got Negotiate flags")

	challenge = Stream_Read(s, 8)
	print("[i] Got Servers challenge {binascii.hexlify(challenge))}")

	__ = Stream_Read(s, 8)
	print("[i] Skipped reserved")

	# Target Info
	tilen, timaxlen, tibufferoffset = streamReadNTLMMessageField(s)
	print(f"[i] Target Info Length: {tilen} at {tibufferoffset}")

	if NegotiateFlags & NTLMSSP_NEGOTIATE_VERSION:
		# Product Version
		negotiateProductMajorVersion = Stream_Read_UINT8(s)
		negotiateProductMinorVersion = Stream_Read_UINT8(s)
		negotiateProductProductBuild = Stream_Read_UINT16(s)
		__ = Stream_Read_UINT8(s) # Skip reserved byte
		negotiateNTLMRevisionCurrent = Stream_Read_UINT8(s)
		print("[i] from Version: " + str(negotiateProductMajorVersion) + "." + str(negotiateProductMinorVersion) + " build (" + str(negotiateProductProductBuild) +") NTLM Revision " + str(negotiateNTLMRevisionCurrent))

	# Target Name
	if NegotiateFlags & 0x00000004 : 	# NTLMSSP_REQUEST_TARGET
		s.seek(tnbufferoffset)
		targetname = Stream_Read(s, tnlen)
		print(f"[i] Got Target Name {targetname}")

	# Target Info - maybe parse this?
	if NegotiateFlags & 0x00800000 :	# NTLMSSP_NEGOTIATE_TARGET_INFO
		s.seek(tibufferoffset)
		targetinfo = Stream_Read(s, tilen)
		print("[i] Got Target Info {binascii.hexlify(targetinfo)}")

	return challenge, targetname, targetinfo


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm_message.c:/^SECURITY_STATUS ntlm_read_ChallengeMessage\(
def ntlm_read_ChallengeMessage(context, s):
	StartOffset = s.tell()
	message = ntlm_read_message_header(s)
	assert message["MessageType"] == MESSAGE_TYPE_CHALLENGE
	message["TargetName"] = ntlm_read_message_fields(s)	# TargetNameFields (8 bytes)
	message["NegotiateFlags"] = Stream_Read_UINT32(s)	# NegotiateFlags (4 bytes)
	context["NegotiateFlags"] = message["NegotiateFlags"]
	message["ServerChallenge"] = Stream_Read(s, 8)	# ServerChallenge (8 bytes)
	__ = Stream_Read(s, 8)	# Reserved (8 bytes), should be ignored
	message["TargetInfo"] = ntlm_read_message_fields(s)
	if context["NegotiateFlags"] & NTLMSSP_NEGOTIATE_VERSION:
		message["Version"] = ntlm_read_version_info(s)

	PayloadOffset = s.tell()

	if message["TargetName"]["Len"]:
		ntlm_read_message_fields_buffer(s, message["TargetInfo"])
		context["ChallengeTargetInfo"] = {}
		context["ChallengeTargetInfo"]["pvBuffer"] = message["TargetInfo"]["Buffer"]
		context["ChallengeTargetInfo"]["cbBuffer"] = message["TargetInfo"]["Len"]
		context["ChallengeTimestamp"] = ntlm_av_pair_get(message["TargetInfo"]["Buffer"], MsvAvTimestamp)

		if context["ChallengeTimestamp"]:
			if context["NTLMv2"]:
				context["UseMIC"] = True

	length = (PayloadOffset - StartOffset) + len(message["TargetName"]) + len(message["TargetInfo"])
	s.seek(StartOffset)
	context["ChallengeMessage"] = Stream_Read(s, length)

	#TODO? if WITH_DEBUG_NTLM:

	# AV_PAIRs
	if context["NTLMv2"]:
		# TODO?
		# ntlm_construct_authenticate_target_info(context)
		# context["ChallengeTargetInfo"] = context["AuthenticateTargetInfo"]
		context["ChallengeTargetInfo"] = {}

	#ntlm_generate_timestamp(context)	# Timestamp
	context["Timestamp"] = context["ChallengeTimestamp"]

	# Implemented, but something's wrong?
	#ntlm_compute_lm_v2_response(context)	# LmChallengeResponse
	#ntlm_compute_ntlm_v2_response(context)	# NtChallengeResponse

	# TODO?
#	ntlm_generate_key_exchange_key(context)	# KeyExchangeKey
#	ntlm_generate_random_session_key(context)	# RandomSessionKey
#	ntlm_generate_exported_session_key(context)	# ExportedSessionKey
#	ntlm_encrypt_random_session_key(context)	# EncryptedRandomSessionKey
#	# Generate signing keys
#	ntlm_generate_client_signing_key(context)
#	ntlm_generate_server_signing_key(context)
#	# Generate sealing keys
#	ntlm_generate_client_sealing_key(context)
#	ntlm_generate_server_sealing_key(context)
#	# Initialize RC4 seal state using client sealing key
#	ntlm_init_rc4_seal_states(context)

	# TODO? if WITH_DEBUG_NTLM:

	context["state"] = NTLM_STATE_AUTHENTICATE


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm_message.c:/^SECURITY_STATUS ntlm_read_AuthenticateMessage\(
def ntlm_read_AuthenticateMessage(context, s):
	context["AUTHENTICATE_MESSAGE"] = {}
	message = context["AUTHENTICATE_MESSAGE"]

	ret = checkHeaderandGetType(s)
	assert ret == MESSAGE_TYPE_AUTHENTICATE

	# LmChallengeResponse
	lmcrlen, lmcrmaxlen, lmcrbufferoffset = streamReadNTLMMessageField(s)

	# NtChallengeResponse
	#  Note: client challenge is in here and the message integrity code
	ntcrlen, ntcrmaxlen, ntcrbufferoffset = streamReadNTLMMessageField(s)

	# Domain Name
	domlen, dommaxlen, dombufferoffset = streamReadNTLMMessageField(s)
	print(f"[i] Domain Name Length: {domlen} at {dombufferoffset}")

	# User Name
	usrlen, usrmaxlen, usrbufferoffset = streamReadNTLMMessageField(s)
	print(f"[i] User Name Length: {usrlen} at {usrbufferoffset}")

	# Workstation
	wslen, wsmaxlen, wsbufferoffset = streamReadNTLMMessageField(s)
	print(f"[i] Workstation Length: {wslen} at {wsbufferoffset}")

	# Encrypted Random Session Key
	ersklen, erskmaxlen, erskbufferoffset = streamReadNTLMMessageField(s)
	print(f"[i] Encrypted Random Session Key Length: {ersklen} at {erskbufferoffset}")
	pos = s.tell()
	s.seek(erskbufferoffset)
	message["EncryptedRandomSessionKey"] = Stream_Read(s, ersklen)
	s.seek(pos)
	print("[i] Got Encrypted Random Session Key")

	# Negotiate Flags
	message["NegotiateFlags"] = Stream_Read_UINT32(s)
	context["NegotiateKeyExchange"] = (message["NegotiateFlags"] & NTLMSSP_NEGOTIATE_KEY_EXCH) != 0
	print("[i] Got Negotiate flags")

	if message["NegotiateFlags"] & NTLMSSP_NEGOTIATE_VERSION:
		message["Version"] = ntlm_read_version_info(s)

	# Save this for later
	PayloadBufferOffset = s.tell()

	s.seek(dombufferoffset)
	message["DomainName"] = Stream_Read(s, domlen)
	print(f"[i] Got Domain {message['DomainName']}")
	s.seek(usrbufferoffset)
	message["UserName"] = Stream_Read(s, usrlen)
	print(f"[i] Got User Name {message['UserName']}")
	s.seek(wsbufferoffset)
	message["Workstation"] = Stream_Read(s, wslen)
	print(f"[i] Got Workstation {message['Workstation']}")
	s.seek(lmcrbufferoffset)
	message["LmChallengeResponse"] = Stream_Read(s, lmcrlen)
	print(f"[i] LM Challenge Response Length: {lmcrlen} at {lmcrbufferoffset}")
	s.seek(ntcrbufferoffset)
	message["NtChallengeResponse"] = Stream_Read(s, ntcrlen)
	print(f"[i] NT Challenge Response Length: {ntcrlen} at {ntcrbufferoffset}")

	# Parse the NtChallengeResponse we read above
	if ntcrlen > 0:
		with io.BytesIO(message["NtChallengeResponse"]) as snt:
			context["NTLMv2Response"] = ntlm_read_ntlm_v2_response(snt)
		context["NtChallengeResponse"] = message["NtChallengeResponse"]
		context["ChallengeTargetInfo"] = context["NTLMv2Response"]["Challenge"]["AvPairs"]
		context["ClientChallenge"] = context["NTLMv2Response"]["Challenge"]["ClientChallenge"][:8]
		AvFlags = ntlm_av_pair_get(context["NTLMv2Response"]["Challenge"]["AvPairs"], MsvAvFlags)

		if AvFlags:
			flags = AvFlags

	assert flags & MSV_AV_FLAGS_MESSAGE_INTEGRITY_CHECK
	print(f"[i] Message Integrity Check/Code (MIC) Present at {PayloadBufferOffset}")

	# I've verified the MIC returned here is correct
	# from the patched ntlm_message.c on a known session
	s.seek(PayloadBufferOffset)
	message["MessageIntegrityCheck"] = Stream_Read(s, 16)
	print(f"[i] Got MIC {binascii.hexlify(message['MessageIntegrityCheck'])}")


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm_compute.c:/^int ntlm_read_ntlm_v2_response\(
def ntlm_read_ntlm_v2_response(s):
	response = {}
	response["Response"] = Stream_Read(s, 16)
	response["Challenge"] = ntlm_read_ntlm_v2_client_challenge(s)
	return response


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm_compute.c:/^static int ntlm_read_ntlm_v2_client_challenge\(
def ntlm_read_ntlm_v2_client_challenge(s):
	challenge = {}
	challenge["RespType"] = Stream_Read_UINT8(s)
	challenge["HiRespType"] = Stream_Read_UINT8(s)
	challenge["Reserved1"] = Stream_Read_UINT16(s)
	challenge["Reserved2"] = Stream_Read_UINT32(s)
	challenge["Timestamp"] = Stream_Read(s, 8)
	challenge["ClientChallenge"] = Stream_Read(s, 8)
	challenge["Reserved3"] = Stream_Read_UINT32(s)
	challenge["AvPairs"] = s.read()
	challenge["cbAvPairs"] = len(challenge["AvPairs"])
	assert challenge["cbAvPairs"] <= UINT32_MAX
	return challenge


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm_compute.c:/^int ntlm_read_version_info\(
def ntlm_read_version_info(s):
	""" Read VERSION structure. """
	versionInfo = {}
	versionInfo["ProductMajorVersion"] = Stream_Read_UINT8(s)	# ProductMajorVersion (1 byte)
	versionInfo["ProductMinorVersion"] = Stream_Read_UINT8(s)	# ProductMinorVersion (1 byte)
	versionInfo["ProductProductBuild"] = Stream_Read_UINT16(s)	# ProductBuild (2 bytes)
	versionInfo["Reserved"] = Stream_Read(s, 3) # Reserved (3 bytes)
	versionInfo["NTLMRevisionCurrent"]  = Stream_Read_UINT8(s)	# NTLMRevisionCurrent (1 byte)
	return versionInfo


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm_message.c:/^SECURITY_STATUS ntlm_server_AuthenticateComplete\(
def ntlm_server_AuthenticateComplete(context):
	if ntlm_compute_lm_v2_response(context) == False:
		print("ntlm_server_AuthenticateComplete: ntlm_compute_lm_v2_response failed")
		return False
	if ntlm_compute_ntlm_v2_response(context) == False:
		print("ntlm_server_AuthenticateComplete: ntlm_compute_ntlm_v2_response failed")
		return False
	ourmic = ntlm_compute_message_integrity_check(context)
	if ourmic == False:
		print("ntlm_server_AuthenticateComplete: ntlm_compute_message_integrity_check failed")
		return False
	mic = context['AuthenticateMessage']['MessageIntegrityCheck']
	return ourmic == mic


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm_compute.c:/^int ntlm_compute_lm_v2_response\(
def ntlm_compute_lm_v2_response(context):
	NtlmV2Hash = ntlm_compute_ntlm_v2_hash(context)
	if NtlmV2Hash == False:
		print("ntlm_compute_lm_v2_response: ntlm_compute_ntlm_v2_hash failed")
		return False
	context["NtlmV2Hash"] = NtlmV2Hash
	value = context["ServerChallenge"] + context["ClientChallenge"]
	# Compute the HMAC-MD5 hash of the resulting value using the NTLMv2 hash as the key
	response = winpr_HMAC(hashlib.md5, context["NtlmV2Hash"], value)
	# Concatenate the resulting HMAC-MD5 hash and the client challenge, giving us the LMv2 response
	response += context["ClientChallenge"]
	context["LmChallengeResponse"] = response
	return True


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm_compute.c:/^static int ntlm_compute_ntlm_v2_hash\(
def ntlm_compute_ntlm_v2_hash(context):
	credentials = context.get("credentials")

	if credentials == None:
		print("ntlm_compute_ntlm_v2_hash: no credentials")
		pprint.pprint(context)
		return False
	elif context.get("NtlmHash"):
		# NULL
		return False
	elif credentials.get("identity") and credentials["identity"].get("Password") and len(credentials["identity"]["Password"]) > SSPI_CREDENTIALS_HASH_LENGTH_OFFSET:
		# Long hash
		# Special case for WinPR: password hash
		NtlmHash = ntlm_convert_password_hash(context)
		if NtlmHash == False:
			return False
		context["NtlmHash"] = NtlmHash
		hash = NTOWFv2FromHashW(context["NtlmHash"], credentials["identity"]["User"], credentials["identity"]["Domain"])
		return hash
	elif credentials.get("identity") and credentials["identity"].get("Password"):
		# Password
		hash = NTOWFv2W(credentials["identity"]["Password"], credentials["identity"]["User"], credentials["identity"]["Domain"])
		return hash
	elif credentials.get("HashCallback"):
		# Hash call back
		proofValue = ntlm_computeProofValue(context)
		if proofValue == False:
			return False
		micValue = ntlm_computeMicValue(context)
		if micValue == False:
			return False
		ret = context["HashCallback"](context["HashCallbackArg"], credentials["identity"], proofValue,
			context["EncryptedRandomSessionKey"],
			context["AUTHENTICATE_MESSAGE"]["MessageIntegrityCheck"],
			micValue,
			hash)
		return ret
	elif context.get("UseSamFileDatabase"):
		# Using SAM
		ret = ntlm_fetch_ntlm_v2_hash(context)
		return ret

	return True


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm_compute.c:/^static int ntlm_fetch_ntlm_v2_hash\(
def ntlm_fetch_ntlm_v2_hash(context):
	credentials = context["credentials"]
	sam = "sam file"
	entry = SamLookupUserW(sam, credentials["identity"]["User"], credentials["identity"]["Domain"])
	return NTOWFv2FromHashW(entry["NtHash"], credentials["identity"]["User"], credentials["identity"]["Domain"])


# ../FreeRDP-ResearchServer/winpr/libwinpr/utils/ntlm.c:/^BOOL NTOWFv2FromHashW\(
def NTOWFv2FromHashW(NtHashV1, User, Domain):
	"""Return V2 hash from V1 hash, user, and domain.

	>>> NTOWFv2FromHashW(
	...	 b'\x88\x46\xf7\xea\xee\x8f\xb1\x17\xad\x06\xbd\xd8\x30\xb7\x58\x6c',
	...	 'username'.encode('utf-16le'),
	...	 'domain'.encode('utf-16le')
	...	 ) == b'\xa3\x06\x37\x10\x10\xc4\x39\xfe\xc3\x97\xec\x2b\x83\x66\x17\x17'
	True
	"""

	# Concatenate(UpperCase(User), Domain)
	buffer = User.upper() + Domain

	# Compute the HMAC-MD5 hash of the above value using the NTLMv1 hash as the key, the result is
	# the NTLMv2 hash
	NtHash = winpr_HMAC(hashlib.md5, NtHashV1, buffer)
	return NtHash


# ../FreeRDP-ResearchServer/winpr/libwinpr/utils/ntlm.c:/^BOOL NTOWFv2W\(
def NTOWFv2W(Password, User, Domain):
	NtHashV1 = NTOWFv1W(Password)
	return NTOWFv2FromHashW(NtHashV1, User, Domain)


# ../FreeRDP-ResearchServer/winpr/libwinpr/utils/ntlm.c:/^BOOL NTOWFv1W\(
def NTOWFv1W(Password):
	return MD4(Password).bytes()


# ../FreeRDP-ResearchServer/winpr/libwinpr/crypto/hash.c:/^BOOL winpr_HMAC\(
def winpr_HMAC(digest, key, msg):
	return hmac.digest(key, msg, digest)


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm_compute.c:/^int ntlm_compute_ntlm_v2_response\(
def ntlm_compute_ntlm_v2_response(context):
	TargetInfo = context["ChallengeTargetInfo"]
	# Compute the NTLMv2 hash
	NtlmV2Hash = ntlm_compute_ntlm_v2_hash(context)
	if NtlmV2Hash == False:
		print("ntlm_compute_ntlm_v2_response: ntlm_compute_ntlm_v2_hash failed")
		return False

	# Construct temp
	blob = b"\x01"	# RespType (1 byte)
	blob += b"\x01"	# HighRespType (1 byte)
	blob += b"\x00\x00"	# Reserved1 (2 bytes)
	blob += b"\x00\x00\x00\x00"	# Reserved2 (4 bytes)
	blob += context["Timestamp"]	# Timestamp (8 bytes)
	blob += context["ClientChallenge"]	# ClientChallenge (8 bytes)
	blob += b"\x00\x00\x00\x00"	# Reserved3 (4 bytes)
	blob += TargetInfo
	ntlm_v2_temp = blob

	# Concatenate server challenge with temp
	blob = context["ServerChallenge"]
	blob += ntlm_v2_temp
	ntlm_v2_temp_chal = blob
	context["NtProofString"] = winpr_HMAC(hashlib.md5, context["NtlmV2Hash"], ntlm_v2_temp_chal)

	# NtChallengeResponse, Concatenate NTProofStr with temp
	# result of above HMAC
	blob = context["NtProofString"]
	blob += ntlm_v2_temp
	context["NtChallengeResponse"] = blob

	# Compute SessionBaseKey, the HMAC-MD5 hash of NTProofStr using the NTLMv2 hash as the key
	context["SessionBaseKey"] = winpr_HMAC(hashlib.md5, context["NtlmV2Hash"], context["NtProofString"])

	return True


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm_compute.c:/^void ntlm_compute_message_integrity_check\(
def ntlm_compute_message_integrity_check(context):
	msg = context["NegotiateMessage"]	# this is from the client
	msg += context["ChallengeMessage"]	# this is from us
	msg += context["AuthenticateMessage"]
	# mic is the output
	mic = winpr_HMAC(hashlib.md5, context["ExportedSessionKey"])
	return mic


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
	context = {
		"ClientChallenge": clientchallenge,
		"credentials": {
			"identity": {
				"Domain": domain,
				"Password": password,
				"User": username,
			},
		},
		"ServerChallenge": serverchallenge,
	}
	return ntlm_server_AuthenticateComplete(context)


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm.c:/^static NTLM_CONTEXT\* ntlm_ContextNew\(
def ntlm_ContextNew():
	context = {}
	context["randID"] = 0
	context["NTLMv2"] = True
	context["UseMIC"] = False
	context["SendVersionInfo"] = True
	context["SendSingleHostData"] = False
	context["SendWorkstationName"] = True
	context["NegotiateKeyExchange"] = True
	context["UseSamFileDatabase"] = True
	context["SuppressExtendedProtection"] = False
	context["NegotiateFlags"] = 0
	context["LmCompatibilityLevel"] = 3
	context["state"] = NTLM_STATE_INITIAL
	context["MachineID"] = b"0xAA" * 32
	if context["NTLMv2"]:
		context["UseMIC"] = True
	return context


# Parse the files
def parsefiles(session, dir):
	context = ntlm_ContextNew()

	# Add static credentials for use with calculating hash
	# TODO: use dictionary
	context["credentials"] = {}
	context["credentials"]["identity"] = {
		"Domain": "domain".encode('utf-16le'),
		"Password": "password".encode('utf-16le'),
		"User": "username".encode('utf-16le'),
	}

	# We parse the files
	parseNegotiate(session,dir)

	context["ServerChallenge"], targetname, targetinfo = parseChallenge(session,dir)

	print(f"[i] ** Parsing Client Challenge for session {session}")
	with open(f"{dir}/{session}.ChallengeIn.bin", 'rb') as file:
		ntlm_read_ChallengeMessage(context, file)

	print(f"[i] ** Parsing Authenticate for session {session}")
	with open(f"{dir}/{session}.AuthenticateIn.bin", 'rb') as file:
		ntlm_read_AuthenticateMessage(context, file)

	# We do some calculations
	success = ntlm_server_AuthenticateComplete(context)
	if success:
		print(f"[*] Attacker from {context['AUTHENTICATE_MESSAGE']['Workstation']} using {context['AUTHENTICATE_MESSAGE']['DomainName']}\\{context['AUTHENTICATE_MESSAGE']['UserName']} with {'FUTURE password'}")
	else:
		print("[!] Attacker from {context['AUTHENTICATE_MESSAGE']['Workstation']} using {context['AUTHENTICATE_MESSAGE']['DomainName']}\\{context['AUTHENTICATE_MESSAGE']['UserName']} but we failed to crack the password")


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-d","--dir", help="directory containing dumps", default="dump")
	parser.add_argument("session", help="parse this session", type=int)
	args = parser.parse_args()
	parsefiles(args.session, args.dir)
