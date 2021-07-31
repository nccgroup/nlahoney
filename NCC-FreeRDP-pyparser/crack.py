#!/usr/bin/env python3

# Imports
import argparse
import base64
import binascii
import hashlib
import hmac
import struct
import sys


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

	return bytes(cipherList)


# Copyright © 2019 James Seo <james@equiv.tech> (github.com/kangtastic).
#
# This file is released under the WTFPL, version 2 (wtfpl.net).
class MD4:
	"""An implementation of the MD4 hash algorithm."""

	width = 32
	mask = 0xFFFFFFFF

	# Unlike, say, SHA-1, MD4 uses little-endian. Fascinating!
	h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

	def __init__(self, msg=None):
		""":param ByteString msg: The message to be hashed."""
		if msg is None:
			msg = b""

		self.msg = msg

		# Pre-processing: Total length is a multiple of 512 bits.
		ml = len(msg) * 8
		msg += b"\x80"
		msg += b"\x00" * (-(len(msg) + 8) % 64)
		msg += struct.pack("<Q", ml)

		# Process the message in successive 512-bit chunks.
		self._process([msg[i : i + 64] for i in range(0, len(msg), 64)])

	def __repr__(self):
		if self.msg:
			return f"{self.__class__.__name__}({self.msg:s})"
		return f"{self.__class__.__name__}()"

	def __str__(self):
		return self.hexdigest()

	def __eq__(self, other):
		return self.h == other.h

	def bytes(self):
		""":return: The final hash value as a `bytes` object."""
		return struct.pack("<4L", *self.h)

	def hexbytes(self):
		""":return: The final hash value as hexbytes."""
		return self.hexdigest().encode

	def hexdigest(self):
		""":return: The final hash value as a hexstring."""
		return "".join(f"{value:02x}" for value in self.bytes())

	def _process(self, chunks):
		for chunk in chunks:
			X, h = list(struct.unpack("<16I", chunk)), self.h.copy()

			# Round 1.
			Xi = [3, 7, 11, 19]
			for n in range(16):
				i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
				K, S = n, Xi[n % 4]
				hn = h[i] + MD4.F(h[j], h[k], h[l]) + X[K]
				h[i] = MD4.lrot(hn & MD4.mask, S)

			# Round 2.
			Xi = [3, 5, 9, 13]
			for n in range(16):
				i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
				K, S = n % 4 * 4 + n // 4, Xi[n % 4]
				hn = h[i] + MD4.G(h[j], h[k], h[l]) + X[K] + 0x5A827999
				h[i] = MD4.lrot(hn & MD4.mask, S)

			# Round 3.
			Xi = [3, 9, 11, 15]
			Ki = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
			for n in range(16):
				i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
				K, S = Ki[n], Xi[n % 4]
				hn = h[i] + MD4.H(h[j], h[k], h[l]) + X[K] + 0x6ED9EBA1
				h[i] = MD4.lrot(hn & MD4.mask, S)

			self.h = [((v + n) & MD4.mask) for v, n in zip(self.h, h)]

	@staticmethod
	def F(x, y, z):
		return (x & y) | (~x & z)

	@staticmethod
	def G(x, y, z):
		return (x & y) | (x & z) | (y & z)

	@staticmethod
	def H(x, y, z):
		return x ^ y ^ z

	@staticmethod
	def lrot(value, n):
		lbits, rbits = (value << n) & MD4.mask, value >> (MD4.width - n)
		return lbits | rbits


# ../FreeRDP-ResearchServer/winpr/libwinpr/crypto/hash.c:/^BOOL winpr_HMAC\(
def winpr_HMAC(digest, key, msg):
	return hmac.digest(key, msg, digest)


def test_winpr_HMAC():
	digest = hashlib.md5
	key = b"\xa3\x06\x37\x10\x10\xc4\x39\xfe\xc3\x97\xec\x2b\x83\x66\x17\x17"
	msg = b"\x4d\xfc\x83\xb0\x86\x54\xe0\xa1\x00\x71\x60\x67\xce\x62\xa8\x19"
	expected = b"\xdb\x08\x36\xab\xdb\x3f\xab\x8a\x03\x7c\x48\x4e\x89\xeb\xbe\x7f"
	actual = winpr_HMAC(digest, key, msg)
	assert expected == actual


def hash_decode(hash):
	"""Decode user:workstation:domain:$NLA$UserDomain$ntlm_v2_temp_chal$msg$EncryptedRandomSessionKey$MessageIntegrityCheck"""
	user, workstation, domain, hashes = hash.split(":")
	assert hashes[:5] == "$NLA$"
	UserDomain, ntlm_v2_temp_chal, msg, EncryptedRandomSessionKey, MessageIntegrityCheck = [base64.b64decode(b) for b in hashes.split("$")[2:]]
	return {
		"user": user,
		"workstation": workstation,
		"domain": domain,
		"UserDomain": UserDomain,
		"ntlm_v2_temp_chal": ntlm_v2_temp_chal,
		"msg": msg,
		"EncryptedRandomSessionKey": EncryptedRandomSessionKey,
		"MessageIntegrityCheck": MessageIntegrityCheck,
	}


def calculate_MIC(Password, UserDomain, ntlm_v2_temp_chal, msg, EncryptedRandomSessionKey):
	NtHashV1 = MD4(Password).bytes()
	NtlmV2Hash = winpr_HMAC(hashlib.md5, NtHashV1, UserDomain)
	NtProofString = winpr_HMAC(hashlib.md5, NtlmV2Hash, ntlm_v2_temp_chal)
	KeyExchangeKey = winpr_HMAC(hashlib.md5, NtlmV2Hash, NtProofString)
	if EncryptedRandomSessionKey:
		ExportedSessionKey = ntlm_rc4k(KeyExchangeKey, EncryptedRandomSessionKey)
	else:
		ExportedSessionKey = KeyExchangeKey
	return winpr_HMAC(hashlib.md5, ExportedSessionKey, msg)


def test_calculate_MIC():
	UserDomain = "USERNAMEdomain".encode("utf-16le")
	Password = "password".encode("utf-16le")
	ChallengeTargetInfo = b"\x02\x00\x18\x00\x44\x00\x39\x00\x39\x00\x42\x00\x42\x00\x45\x00\x37\x00\x36\x00\x34\x00\x36\x00\x45\x00\x33\x00\x01\x00\x18\x00\x44\x00\x39\x00\x39\x00\x42\x00\x42\x00\x45\x00\x37\x00\x36\x00\x34\x00\x36\x00\x45\x00\x33\x00\x04\x00\x18\x00\x64\x00\x39\x00\x39\x00\x62\x00\x62\x00\x65\x00\x37\x00\x36\x00\x34\x00\x36\x00\x65\x00\x33\x00\x03\x00\x18\x00\x64\x00\x39\x00\x39\x00\x62\x00\x62\x00\x65\x00\x37\x00\x36\x00\x34\x00\x36\x00\x65\x00\x33\x00\x07\x00\x08\x00\x00\xd2\xdb\xf7\x4b\x80\xd7\x01\x06\x00\x04\x00\x02\x00\x00\x00\x0a\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x22\x00\x54\x00\x45\x00\x52\x00\x4d\x00\x53\x00\x52\x00\x56\x00\x2f\x00\x31\x00\x32\x00\x37\x00\x2e\x00\x30\x00\x2e\x00\x30\x00\x2e\x00\x31\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	ClientChallenge = b"\x8a\x58\x46\x32\xb1\xd6\xf5\xd3"
	EncryptedRandomSessionKey = b"\x09\xe8\x44\x93\x42\x2b\xf3\x65\x95\x0f\xc7\xc8\x06\x1a\xbd\x4d"
	ServerChallenge = b"\x7b\xee\x47\x27\xbb\x32\x98\x33"
	Timestamp = b"\x00\xd2\xdb\xf7\x4b\x80\xd7\x01"

	ntlm_v2_temp = b"\x01"	# RespType (1 byte)
	ntlm_v2_temp += b"\x01"	# HighRespType (1 byte)
	ntlm_v2_temp += b"\x00\x00"	# Reserved1 (2 bytes)
	ntlm_v2_temp += b"\x00\x00\x00\x00"	# Reserved2 (4 bytes)
	ntlm_v2_temp += Timestamp	# Timestamp (8 bytes)
	ntlm_v2_temp += ClientChallenge	# ClientChallenge (8 bytes)
	ntlm_v2_temp += b"\x00\x00\x00\x00"	# Reserved3 (4 bytes)
	ntlm_v2_temp += ChallengeTargetInfo
	ntlm_v2_temp_chal = ServerChallenge + ntlm_v2_temp

	msg = b"\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\xb7\x82\x08\xe2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x01\xb1\x1d\x00\x00\x00\x0f\x4e\x54\x4c\x4d\x53\x53\x50\x00\x02\x00\x00\x00\x18\x00\x18\x00\x38\x00\x00\x00\xb7\x82\x88\xe2\x7b\xee\x47\x27\xbb\x32\x98\x33\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x80\x00\x50\x00\x00\x00\x06\x01\xb1\x1d\x00\x00\x00\x0f\x44\x00\x39\x00\x39\x00\x42\x00\x42\x00\x45\x00\x37\x00\x36\x00\x34\x00\x36\x00\x45\x00\x33\x00\x02\x00\x18\x00\x44\x00\x39\x00\x39\x00\x42\x00\x42\x00\x45\x00\x37\x00\x36\x00\x34\x00\x36\x00\x45\x00\x33\x00\x01\x00\x18\x00\x44\x00\x39\x00\x39\x00\x42\x00\x42\x00\x45\x00\x37\x00\x36\x00\x34\x00\x36\x00\x45\x00\x33\x00\x04\x00\x18\x00\x64\x00\x39\x00\x39\x00\x62\x00\x62\x00\x65\x00\x37\x00\x36\x00\x34\x00\x36\x00\x65\x00\x33\x00\x03\x00\x18\x00\x64\x00\x39\x00\x39\x00\x62\x00\x62\x00\x65\x00\x37\x00\x36\x00\x34\x00\x36\x00\x65\x00\x33\x00\x07\x00\x08\x00\x00\xd2\xdb\xf7\x4b\x80\xd7\x01\x00\x00\x00\x00\x4e\x54\x4c\x4d\x53\x53\x50\x00\x03\x00\x00\x00\x18\x00\x18\x00\x8c\x00\x00\x00\xfa\x00\xfa\x00\xa4\x00\x00\x00\x0c\x00\x0c\x00\x58\x00\x00\x00\x10\x00\x10\x00\x64\x00\x00\x00\x18\x00\x18\x00\x74\x00\x00\x00\x10\x00\x10\x00\x9e\x01\x00\x00\x35\xb2\x88\xe2\x06\x01\xb1\x1d\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x64\x00\x6f\x00\x6d\x00\x61\x00\x69\x00\x6e\x00\x75\x00\x73\x00\x65\x00\x72\x00\x6e\x00\x61\x00\x6d\x00\x65\x00\x64\x00\x39\x00\x39\x00\x62\x00\x62\x00\x65\x00\x37\x00\x36\x00\x34\x00\x36\x00\x65\x00\x33\x00\x71\xdd\x91\xd0\xc6\xef\x9c\x8f\x91\xf0\xef\x1b\xf5\x80\xb0\xe4\x8a\x58\x46\x32\xb1\xd6\xf5\xd3\xe9\xe0\xeb\x3d\x1b\x04\x1d\x4b\x0a\x55\xab\x6b\x14\x90\xeb\x21\x01\x01\x00\x00\x00\x00\x00\x00\x00\xd2\xdb\xf7\x4b\x80\xd7\x01\x8a\x58\x46\x32\xb1\xd6\xf5\xd3\x00\x00\x00\x00\x02\x00\x18\x00\x44\x00\x39\x00\x39\x00\x42\x00\x42\x00\x45\x00\x37\x00\x36\x00\x34\x00\x36\x00\x45\x00\x33\x00\x01\x00\x18\x00\x44\x00\x39\x00\x39\x00\x42\x00\x42\x00\x45\x00\x37\x00\x36\x00\x34\x00\x36\x00\x45\x00\x33\x00\x04\x00\x18\x00\x64\x00\x39\x00\x39\x00\x62\x00\x62\x00\x65\x00\x37\x00\x36\x00\x34\x00\x36\x00\x65\x00\x33\x00\x03\x00\x18\x00\x64\x00\x39\x00\x39\x00\x62\x00\x62\x00\x65\x00\x37\x00\x36\x00\x34\x00\x36\x00\x65\x00\x33\x00\x07\x00\x08\x00\x00\xd2\xdb\xf7\x4b\x80\xd7\x01\x06\x00\x04\x00\x02\x00\x00\x00\x0a\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x00\x22\x00\x54\x00\x45\x00\x52\x00\x4d\x00\x53\x00\x52\x00\x56\x00\x2f\x00\x31\x00\x32\x00\x37\x00\x2e\x00\x30\x00\x2e\x00\x30\x00\x2e\x00\x31\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\xe8\x44\x93\x42\x2b\xf3\x65\x95\x0f\xc7\xc8\x06\x1a\xbd\x4d"
	expected = b"\x7a\xc2\x2a\x98\xff\x8e\x0b\xa4\x8c\xd6\xa6\x75\xc5\x15\xc0\x31"
	actual = calculate_MIC(Password, UserDomain, ntlm_v2_temp_chal, msg, EncryptedRandomSessionKey)
	assert actual == expected


def crack(hash):
	components = hash_decode(hash)

	passwordList = [
		"qwerty",
		"password",
		"secret",
		"yoink",
	]
	mic = binascii.hexlify(components["MessageIntegrityCheck"]).decode()
	for password in passwordList:
		if components["MessageIntegrityCheck"] == calculate_MIC(
			password.encode("utf-16le"),
			components["UserDomain"],
			components["ntlm_v2_temp_chal"],
			components["msg"],
			components["EncryptedRandomSessionKey"],
		):
			print(f'Success: {mic}:{components["domain"]}\\{components["user"]}@{components["workstation"]}:{password}')
			break
	else:
		print(f'Fail: {mic}:{components["domain"]}\\{components["user"]}@{components["workstation"]}')


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("file", help="files containing NLA hashes", nargs="+")
	args = parser.parse_args()

	for file in args.file:
		with open(file, "r") as f:
			for hash in f:
				crack(hash)
