# nlahoney
NLA Honeypot Associated Research

MIC calculation dependency tree:
- ntlm_compute_message_integrity_check()
	- msg
		- context["NegotiateMessage"] = {session}.NegotiateIn.bin
		- context["ChallengeMessage"] = {session}.ChallengeIn.bin
		- context["AuthenticateMessage"] = {session}.AuthenticateOut.bin
	- context["ExportedSessionKey"]
		- ntlm_server_AuthenticateComplete()
			- context["RandomSessionKey"][:16]
				- ntlm_rc4k(context["KeyExchangeKey"], context["EncryptedRandomSessionKey"])
					- context["KeyExchangeKey"]
						- (See below)
					- context["EncryptedRandomSessionKey"]
						- ntlm_read_AuthenticateMessage() <- {session}.AuthenticateIn.bin
				- context["KeyExchangeKey"][:16]
					- context["SessionBaseKey"][:16]
						- ntlm_compute_ntlm_v2_response()
							- winpr_HMAC(hashlib.md5, context["NtlmV2Hash"], context["NtProofString"])
								- context["NtlmV2Hash"]
									- ntlm_compute_ntlm_v2_hash()
										- NTOWFv2W(context["credentials"]["identity"]["Password"], context["credentials"]["identity"]["User"], context["credentials"]["identity"]["Domain"])
											- context["credentials"]["identity"]["Password"]
											- context["credentials"]["identity"]["User"] <- {session}.AuthenticateIn.bin
											- context["credentials"]["identity"]["Domain"] <- {session}.AuthenticateIn.bin
											- NTOWFv2FromHashW(MD4(Password), User, Domain)
												- winpr_HMAC(hashlib.md5, MD4(Password), User.upper() + Domain)
								- context["NtProofString"]
									- winpr_HMAC(hashlib.md5, context["NtlmV2Hash"], ntlm_v2_temp_chal)
										- context["NtlmV2Hash"]
											- (See above)
										- ntlm_v2_temp_chal
											- context["ServerChallenge"]
												- ntlm_unwrite_ChallengeMessage() <- {session}.ChallengeOut.bin
											- ntlm_v2_temp
												- context["Timestamp"]
													- ntlm_read_ChallengeMessage() <- {session}.ChallengeIn.bin
												- context["ClientChallenge"]
													- ntlm_read_AuthenticateMessage() <- {session}.AuthenticateIn.bin
												- context["ChallengeTargetInfo"]
													- ntlm_read_ChallengeMessage() <- {session}.ChallengeIn.bin
- MIC
	- ntlm_read_AuthenticateMessage()
		- message["MessageIntegrityCheck"]
			- context["MessageIntegrityCheckOffset"]


Big picture:
* once we get a way to extract a crackable hash from the NLA protocol (we are close now)
	- How do we get a crackable hash? At what point in the code is there a hash that is crackable?
	- What steps do we need to do in code in order to "generate" a crackable hash? Or what interactions do we need with the client in order for them to send us a crackable hash?
* we are going to build a hashcrack CUDA implementation to make it highly performant
* we will then use that implementation to recover the credentials (i.e. the passwords) being sprayed at RDP honeypots we deploy
* the goal here us to understand what passwords are being used and are they organisation specific etc.

- Ultimate vision is recover credentials to NLA enabled honeypots
	- number of steps
	1. 2 rounds of MD5 hmac, with cleartext password to replicate process, convert to NTLM hmac, hash from NLA handshake
		- negotiate
		- auth
		- get packet packets that attackers send us
		- extract username and domain (got)
			- working on extracting elements of NLA protocol (to elements we need to replicate handshake)
		- attacker's traffic (username we know, password we don't)

		- trying to generate NT Proof String
			- password converted to LanHash, combined with various challenge responses to generate NT proof
			- server can read from SAM
				- dictionary of SAM
			- they're trying these usernames and these passwords
				- recover these passwords
				- once we get them: we can check if it's your legit password, if it's leaked

- Do we want to submit this work to any conferences?
	- BlackHat talk
		- NTLM Hash
		- RDP always allows
		- This protocol isn't
