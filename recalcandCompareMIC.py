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
