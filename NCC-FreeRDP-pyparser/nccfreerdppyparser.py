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
import secrets
import struct
import sys
import unittest

from md4 import MD4


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm.h
MESSAGE_TYPE_NEGOTIATE = 1
MESSAGE_TYPE_CHALLENGE = 2
MESSAGE_TYPE_AUTHENTICATE = 3
NTLMSSP_NEGOTIATE_56 = 0x80000000	# W   (0)
NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000	# V   (1)
NTLMSSP_NEGOTIATE_128 = 0x20000000	# U   (2)
NTLMSSP_RESERVED1 = 0x10000000	# r1  (3)
NTLMSSP_RESERVED2 = 0x08000000	# r2  (4)
NTLMSSP_RESERVED3 = 0x04000000	# r3  (5)
NTLMSSP_NEGOTIATE_VERSION = 0x02000000	# T   (6)
NTLMSSP_RESERVED4 = 0x01000000	# r4  (7)
NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000	# S   (8)
NTLMSSP_REQUEST_NON_NT_SESSION_KEY = 0x00400000	# R   (9)
NTLMSSP_RESERVED5 = 0x00200000	# r5  (10)
NTLMSSP_NEGOTIATE_IDENTIFY = 0x00100000	# Q   (11)
NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY = 0x00080000	# P   (12)
NTLMSSP_RESERVED6 = 0x00040000	# r6  (13)
NTLMSSP_TARGET_TYPE_SERVER = 0x00020000	# O   (14)
NTLMSSP_TARGET_TYPE_DOMAIN = 0x00010000	# N   (15)
NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000	# M   (16)
NTLMSSP_RESERVED7 = 0x00004000	# r7  (17)
NTLMSSP_NEGOTIATE_WORKSTATION_SUPPLIED = 0x00002000	# L   (18)
NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED = 0x00001000	# K   (19)
NTLMSSP_NEGOTIATE_ANONYMOUS = 0x00000800	# J   (20)
NTLMSSP_RESERVED8 = 0x00000400	# r8  (21)
NTLMSSP_NEGOTIATE_NTLM = 0x00000200	# H   (22)
NTLMSSP_RESERVED9 = 0x00000100	# r9  (23)
NTLMSSP_NEGOTIATE_LM_KEY = 0x00000080	# G   (24)
NTLMSSP_NEGOTIATE_DATAGRAM = 0x00000040	# F   (25)
NTLMSSP_NEGOTIATE_SEAL = 0x00000020	# E   (26)
NTLMSSP_NEGOTIATE_SIGN = 0x00000010	# D   (27)
NTLMSSP_RESERVED10 = 0x00000008	# r10 (28)
NTLMSSP_REQUEST_TARGET = 0x00000004	# C   (29)
NTLMSSP_NEGOTIATE_OEM = 0x00000002	# B   (30)
NTLMSSP_NEGOTIATE_UNICODE = 0x00000001	# A   (31)
MSV_AV_FLAGS_AUTHENTICATION_CONSTRAINED = 0x00000001
MSV_AV_FLAGS_MESSAGE_INTEGRITY_CHECK = 0x00000002
MSV_AV_FLAGS_TARGET_SPN_UNTRUSTED_SOURCE = 0x00000004

MSV_AV_FLAGS_MESSAGE_INTEGRITY_CHECK = 0x00000002
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
	s.seek(fields["BufferOffset"])
	fields["Buffer"] = Stream_Read(s, fields["Len"])


def checkHeaderandGetType(s):
	header = Stream_Read(s, 8)
	assert header == b"NTLMSSP\x00"
	type = Stream_Read_UINT32(s)
	return type


def streamReadNTLMMessageField(s):
	fields = ntlm_read_message_fields(s)
	return fields["Len"], fields["MaxLen"], fields["BufferOffset"]


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


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm_message.c:/^SECURITY_STATUS ntlm_read_NegotiateMessage\(
def ntlm_read_NegotiateMessage(context, s):
	message = {}

	ret = checkHeaderandGetType(s)
	assert ret == MESSAGE_TYPE_NEGOTIATE

	# Negotiate Flags
	message["NegotiateFlags"] = Stream_Read_UINT32(s) # NegotiateFlags (4 bytes)
	assert message["NegotiateFlags"] & NTLMSSP_REQUEST_TARGET
	assert message["NegotiateFlags"] & NTLMSSP_NEGOTIATE_NTLM
	assert message["NegotiateFlags"] & NTLMSSP_NEGOTIATE_UNICODE
	print("[i] Got Negotiate flags")

	# DomainNameFields (8 bytes)
	message["Domain"] = ntlm_read_message_fields(s)
	print(f"[i] Domain Length: {message['Domain']['Len']} at {message['Domain']['BufferOffset']}")

	# WorkstationFields (8 bytes)
	message["Workstation"] = ntlm_read_message_fields(s)
	print(f"[i] Workstation Length: {message['Workstation']['Len']} at {message['Workstation']['BufferOffset']}")

	# Version (8 bytes)
	if message["NegotiateFlags"] & NTLMSSP_NEGOTIATE_VERSION:
		message["Version"] = ntlm_read_version_info(s)

	context["NegotiateMessage"] = s.read()
	return message


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
	ntlm_generate_random_session_key(context)	# RandomSessionKey
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


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm_message.c:/^SECURITY_STATUS ntlm_write_ChallengeMessage\(
def ntlm_unwrite_ChallengeMessage(context, s):
	"""
	This function "unwrites" (reads) `s` back into `context`.
	`ntlm_write_ChallengeMessage` first reads from `context`, then writes into `s`.
	This function first reads from `s`, then writes into `context`.
	"""
	message = {}

	# First read ChallengeMessage from `s`

	# Message Header (12 bytes)
	ret = checkHeaderandGetType(s)
	assert ret == MESSAGE_TYPE_CHALLENGE

	# TargetNameFields (8 bytes)
	message["TargetName"] = ntlm_read_message_fields(s)
	print(f"[i] Target Name Length: {message['TargetName']['Len']} at {message['TargetName']['BufferOffset']}")

	# NegotiateFlags (4 bytes)
	message["NegotiateFlags"] = Stream_Read_UINT32(s)
	print("[i] Got Negotiate flags")

	# ServerChallenge (8 bytes)
	message["ServerChallenge"] = Stream_Read(s, 8)
	print("[i] Got Servers challenge {binascii.hexlify(challenge))}")

	# Reserved (8 bytes), should be ignored
	message["Reserved"] = Stream_Read(s, 8)
	print("[i] Skipped reserved")

	# TargetInfoFields (8 bytes)
	message["TargetInfo"] = ntlm_read_message_fields(s)
	print(f"[i] Target Info Length: {message['TargetInfo']['Len']} at {message['TargetInfo']['BufferOffset']}")

	if message["NegotiateFlags"] & NTLMSSP_NEGOTIATE_VERSION:
		# Version (8 bytes)
		message["Version"] = ntlm_read_version_info(s)

	# Payload (variable)

	if message["NegotiateFlags"] & NTLMSSP_REQUEST_TARGET:
		ntlm_read_message_fields_buffer(s, message["TargetName"])

		# Product Version
		negotiateProductMajorVersion = Stream_Read_UINT8(s)
		negotiateProductMinorVersion = Stream_Read_UINT8(s)
		negotiateProductProductBuild = Stream_Read_UINT16(s)
		__ = Stream_Read_UINT8(s) # Skip reserved byte
		negotiateNTLMRevisionCurrent = Stream_Read_UINT8(s)
		print("[i] from Version: " + str(negotiateProductMajorVersion) + "." + str(negotiateProductMinorVersion) + " build (" + str(negotiateProductProductBuild) +") NTLM Revision " + str(negotiateNTLMRevisionCurrent))

	# Target Name
	if message["NegotiateFlags"] & 0x00000004 : 	# NTLMSSP_REQUEST_TARGET
		s.seek(message["TargetName"]["BufferOffset"])
		targetname = Stream_Read(s, message["TargetName"]["Len"])
		print(f"[i] Got Target Name {targetname}")

	# Target Info - maybe parse this?
	if message["NegotiateFlags"] & 0x00800000 :	# NTLMSSP_NEGOTIATE_TARGET_INFO
		s.seek(message["TargetInfo"]["BufferOffset"])
		targetinfo = Stream_Read(s, message["TargetInfo"]["Len"])
		print("[i] Got Target Info {binascii.hexlify(targetinfo)}")

	# Finished reading from `s`. Time to write back to `context`.

	context["NegotiateFlags"] = message["NegotiateFlags"]
	context["ServerChallenge"] = message["ServerChallenge"]
	context["CHALLENGE_MESSAGE"] = message

	return message


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm_compute.c:/^void ntlm_generate_random_session_key\(
def ntlm_generate_random_session_key(context):
	"""Generate RandomSessionKey (16-byte nonce)."""
	context["RandomSessionKey"] = secrets.token_bytes(16)


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm_message.c:/^SECURITY_STATUS ntlm_read_AuthenticateMessage\(
def ntlm_read_AuthenticateMessage(context, s):
	credentials = context["credentials"]

	context["AUTHENTICATE_MESSAGE"] = {}
	message = context["AUTHENTICATE_MESSAGE"]

	ret = checkHeaderandGetType(s)
	assert ret == MESSAGE_TYPE_AUTHENTICATE

	# LmChallengeResponseFields (8 bytes)
	message["LmChallengeResponse"] = ntlm_read_message_fields(s)

	# NtChallengeResponseFields (8 bytes)
	# Note: client challenge is in here and the message integrity code
	message["NtChallengeResponse"] = ntlm_read_message_fields(s)

	# DomainNameFields (8 bytes)
	message["DomainName"] = ntlm_read_message_fields(s)
	print(f"[i] Domain Name Length: {message['DomainName']['Len']} at {message['DomainName']['BufferOffset']}")

	# UserNameFields (8 bytes)
	message["UserName"] = ntlm_read_message_fields(s)
	print(f"[i] User Name Length: {message['UserName']['Len']} at {message['UserName']['BufferOffset']}")

	# WorkstationFields (8 bytes)
	message["Workstation"] = ntlm_read_message_fields(s)
	print(f"[i] Workstation Length: {message['Workstation']['Len']} at {message['Workstation']['BufferOffset']}")

	# EncryptedRandomSessionKeyFields (8 bytes)
	message["EncryptedRandomSessionKey"] = ntlm_read_message_fields(s)
	print(f"[i] Encrypted Random Session Key Length: {message['EncryptedRandomSessionKey']['Len']} at {message['EncryptedRandomSessionKey']['BufferOffset']}")

	# NegotiateFlags (4 bytes)
	message["NegotiateFlags"] = Stream_Read_UINT32(s)
	context["NegotiateKeyExchange"] = (message["NegotiateFlags"] & NTLMSSP_NEGOTIATE_KEY_EXCH) != 0
	print("[i] Got Negotiate flags")

	if message["NegotiateFlags"] & NTLMSSP_NEGOTIATE_VERSION:
		# Version (8 bytes)
		message["Version"] = ntlm_read_version_info(s)

	# Save this for later
	PayloadBufferOffset = s.tell()

	ntlm_read_message_fields_buffer(s, message["DomainName"])
	print(f"[i] Got DomainName {message['DomainName']['Buffer']}")
	ntlm_read_message_fields_buffer(s, message["UserName"])
	print(f"[i] Got UserName {message['UserName']['Buffer']}")
	ntlm_read_message_fields_buffer(s, message["Workstation"])
	print(f"[i] Got Workstation {message['Workstation']['Buffer']}")
	ntlm_read_message_fields_buffer(s, message["LmChallengeResponse"])
	print(f"[i] LmChallengeResponse Length: {message['LmChallengeResponse']['Len']} at {message['LmChallengeResponse']['BufferOffset']}")
	ntlm_read_message_fields_buffer(s, message["NtChallengeResponse"])
	print(f"[i] NtChallengeResponse Length: {message['NtChallengeResponse']['Len']} at {message['NtChallengeResponse']['BufferOffset']}")

	# Parse the NtChallengeResponse we read above
	if message['NtChallengeResponse']['Len'] > 0:
		with io.BytesIO(message["NtChallengeResponse"]["Buffer"]) as snt:
			context["NTLMv2Response"] = ntlm_read_ntlm_v2_response(snt)
		context["NtChallengeResponse"] = message["NtChallengeResponse"]
		context["ChallengeTargetInfo"] = context["NTLMv2Response"]["Challenge"]["AvPairs"]
		context["ClientChallenge"] = context["NTLMv2Response"]["Challenge"]["ClientChallenge"][:8]
		AvFlags = ntlm_av_pair_get(context["NTLMv2Response"]["Challenge"]["AvPairs"], MsvAvFlags)

		if AvFlags:
			flags = AvFlags

	# EncryptedRandomSessionKey
	ntlm_read_message_fields_buffer(s, message["EncryptedRandomSessionKey"])
	if message["EncryptedRandomSessionKey"]["Len"]:
		assert message["EncryptedRandomSessionKey"]["Len"] == 16
		context["EncryptedRandomSessionKey"] = message["EncryptedRandomSessionKey"]["Buffer"]
	print("[i] Got Encrypted Random Session Key")

	context["AuthenticateMessage"] = s.read()

	# I've verified the MIC returned here is correct
	# from the patched ntlm_message.c on a known session
	s.seek(PayloadBufferOffset)

	assert flags & MSV_AV_FLAGS_MESSAGE_INTEGRITY_CHECK
	print(f"[i] Message Integrity Check/Code (MIC) Present at {PayloadBufferOffset}")
	context["MessageIntegrityCheckOffset"] = s.tell()
	message["MessageIntegrityCheck"] = Stream_Read(s, 16)
	print(f"[i] Got MIC {binascii.hexlify(message['MessageIntegrityCheck'])}")

	if message["UserName"]["Len"]:
		credentials["identity"]["User"] = message["UserName"]["Buffer"]
		credentials["identity"]["UserLength"] = message["UserName"]["Len"] // 2
	if message["DomainName"]["Len"]:
		credentials["identity"]["Domain"] = message["DomainName"]["Buffer"]
		credentials["identity"]["DomainLength"] = message["DomainName"]["Len"] // 2


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
	assert context
	# assert context["state"] == NTLM_STATE_COMPLETION

	message = context["AUTHENTICATE_MESSAGE"]
	AvFlags = ntlm_av_pair_get(context["NTLMv2Response"]["Challenge"]["AvPairs"], MsvAvFlags)

	if AvFlags:
		flags = AvFlags

	# LmChallengeResponse
	assert ntlm_compute_lm_v2_response(context)
	# NtChallengeResponse
	assert ntlm_compute_ntlm_v2_response(context)

	# KeyExchangeKey
	ntlm_generate_key_exchange_key(context)
	# EncryptedRandomSessionKey
	ntlm_decrypt_random_session_key(context)
	# ExportedSessionKey
	ntlm_generate_exported_session_key(context)

	if flags & MSV_AV_FLAGS_MESSAGE_INTEGRITY_CHECK:
		ourmic = ntlm_compute_message_integrity_check(context)
		if ourmic == False:
			print("ntlm_server_AuthenticateComplete: ntlm_compute_message_integrity_check failed")
			return False
		mic = context['AuthenticateMessage']['MessageIntegrityCheck']
		return ourmic == mic
	else:
		"""
		no mic message was present

		https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/f9e6fbc4-a953-4f24-b229-ccdcc213b9ec
		the mic is optional, as not supported in Windows NT, Windows 2000, Windows XP, and
		Windows Server 2003 and, as it seems, in the NTLMv2 implementation of Qt5.

		now check the NtProofString, to detect if the entered client password matches the
		expected password.
		"""


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm_compute.c:/^void ntlm_generate_key_exchange_key\(
def ntlm_generate_key_exchange_key(context):
	# In NTLMv2, KeyExchangeKey is the 128-bit SessionBaseKey
	context["KeyExchangeKey"] = context["SessionBaseKey"][:16]


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm_compute.c:/^void ntlm_decrypt_random_session_key\(
def ntlm_decrypt_random_session_key(context):
	"""Decrypt RandomSessionKey (RC4-encrypted RandomSessionKey, using KeyExchangeKey as the key)."""
	# In NTLMv2, EncryptedRandomSessionKey is the ExportedSessionKey RC4-encrypted with the
	# KeyExchangeKey

	#	if (NegotiateFlags & NTLMSSP_NEGOTIATE_KEY_EXCH)
	#		Set RandomSessionKey to RC4K(KeyExchangeKey,
	# AUTHENTICATE_MESSAGE.EncryptedRandomSessionKey) else Set RandomSessionKey to KeyExchangeKey
	if context["NegotiateKeyExchange"]:
		context["RandomSessionKey"] = ntlm_rc4k(context["KeyExchangeKey"], context["EncryptedRandomSessionKey"])
	else:
		context["RandomSessionKey"] = context["KeyExchangeKey"][:16]


# ../FreeRDP-ResearchServer/winpr/libwinpr/sspi/NTLM/ntlm_compute.c:/^void ntlm_rc4k\(
def ntlm_rc4k(key, plaintext):
	"""Encrypt the given plain text using RC4 and the given key."""
	assert len(key) == 16

	# https://github.com/g2jun/RC4-Python/blob/51ad9391cb0101e1b7b9ebc02f30359e892fc068/RC4.py#L88-L112
	cipherList = []

	keyLen = len(key)
	plainLen = len(plaintext)
	S = list(range(256))

	j = 0
	for i in range(256):
		j = (j + S[i] + key[i % keyLen]) % 256
		S[i], S[j] = S[j], S[i]

	i = 0
	j = 0
	for m in range(plainLen):
		i = (i + 1) % 256
		j = (j + S[i]) % 256
		S[i], S[j] = S[j], S[i]
		k = S[(S[i] + S[j]) % 256]
		cipherList.append(k ^ plaintext[m])

	return cipherList


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
	print(f"[i] ** Parsing Client Negotiate for session {session}")
	with open(f"{dir}/{session}.NegotiateIn.bin", "rb") as s:
		ntlm_read_NegotiateMessage(context, s)

	print(f"[i] ** Parsing Server Challenge for session {session}")
	with open(f"{dir}/{session}.ChallengeOut.bin", 'rb') as s:
		ntlm_unwrite_ChallengeMessage(context, s)

	print(f"[i] ** Parsing Client Challenge for session {session}")
	with open(f"{dir}/{session}.ChallengeIn.bin", 'rb') as s:
		ntlm_read_ChallengeMessage(context, s)

	print(f"[i] ** Parsing Authenticate for session {session}")
	with open(f"{dir}/{session}.AuthenticateIn.bin", 'rb') as s:
		ntlm_read_AuthenticateMessage(context, s)

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
