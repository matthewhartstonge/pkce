package pkce

const (
	// ParamCodeChallenge (required) provides the url query param key required
	// to send a PKCE code challenge as part of the Authorization Request.
	ParamCodeChallenge = "code_challenge"

	// ParamCodeChallengeMethod (optional) provides the url query param key
	// required to send the PKCE code challenge method as part of the
	// Authorization Request. Defaults to "plain" if not present in the request.
	ParamCodeChallengeMethod = "code_challenge_method"

	// ParamCodeVerifier provides the url query param key required to send a
	// PKCE code verifier as part of the token request.
	ParamCodeVerifier = "code_verifier"
)
