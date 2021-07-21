# nlahoney
NLA Honeypot Associated Research

Todo:
[X] Dump backtrace of functions called that lead up to authentication.
[ ] Dump data received and data returned
[ ] Implement each function

Big picture:
* once we get a way to extract a crackable hash from the NLA protocol (we are close now)
	- How do we get a crackable hash? At what point in the code is there a hash that is crackable?
	- What steps do we need to do in code in order to "generate" a crackable hash? Or what interactions do we need with the client in order for them to send us a crackable hash?
* we are going to build a hashcrack CUDA implementation to make it highly performant
* we will then use that implementation to recover the credentials (i.e. the passwords) being sprayed at RDP honeypots we deploy
* the goal here us to understand what passwords are being used and are they organisation specific etc.

- Do we want to submit this work to any conferences?

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

- BlackHat talk
	- NTLM Hash
	- RDP always allows
	- This protocol isn't

- Randomness of

- Complex honeypot infrastructure

Jan 10
RDP Christmas
